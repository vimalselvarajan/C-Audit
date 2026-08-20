"""Part 07 runner tests: T-07-15, T-07-16 (AC-07-7), plus AC-07-11.

The subject here is failure. An analyzer that crashes, hangs, or is not
installed must leave a limitation naming itself and the translation unit, and
must not stop the other units — because a run that quietly produced nothing
for nine files reads exactly like a run that found nothing wrong with them.

These use a stub interpreter rather than a real Clang, so they run in the
default suite on a machine with no LLVM. T-07-21 covers the real thing under
``needs_clang``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from caudit.analyzers.csa import CsaAnalyzer
from caudit.analyzers.diagnostics import DiagnosticsAnalyzer
from caudit.analyzers.normalize import Normalizer
from caudit.analyzers.profile import load_profile
from caudit.analyzers.runner import (
    AnalyzerRun,
    RunStatus,
    analysis_flags,
    run_units,
    source_argument,
)
from caudit.analyzers.service import generate_candidates
from caudit.analyzers.tidy import TidyAnalyzer
from caudit.config.loader import Config
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.intake.plan import Coverage, ScanPlan, TranslationUnit
from caudit.model.finding import LimitationKind
from tests.conftest import make_translation_unit, stub_subprocess

#: A "compiler" that is guaranteed to exist wherever the tests run.
PYTHON = sys.executable


def _plan(root: Path, units: list[TranslationUnit]) -> ScanPlan:
    return ScanPlan(
        repo_root=root,
        revision="test-revision",
        compile_commands_path=root / "compile_commands.json",
        units=units,
        coverage=Coverage(
            tus_in_database=len(units),
            tus_selected=len(units),
            source_files_in_tree=len(units),
            source_files_covered=len(units),
            coverage_ratio=1.0,
        ),
    )


def _normalizer(root: Path) -> Normalizer:
    return Normalizer(
        store=SourceStore(root, revision="test-revision"), profile=load_profile(), index=None
    )


def _stub_analyzer(root: Path, script: str) -> DiagnosticsAnalyzer:
    """A diagnostics analyzer whose "compiler" is a one-line Python program."""
    analyzer = DiagnosticsAnalyzer(
        profile=load_profile(), normalizer=_normalizer(root), clang=PYTHON, tool_version="stub"
    )
    analyzer.command = lambda unit: [PYTHON, "-c", script]  # type: ignore[method-assign]  # noqa: ARG005
    return analyzer


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, list[TranslationUnit]]:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    for name in ("a", "b", "c"):
        (root / "src" / f"{name}.c").write_text(
            f"void {name}(void)\n{{\n    return;\n}}\n", encoding="utf-8"
        )
    units = [make_translation_unit(root, f"src/{name}.c") for name in ("a", "b", "c")]
    return root, units


# ------------------------------------------------------------- T-07-15/16


def test_an_analyzer_that_hangs_is_stopped_and_recorded(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    """T-07-15: the timeout is a limitation, and the other units still finish."""
    root, units = tree
    slow = _stub_analyzer(root, "import time; time.sleep(30)")

    runs = run_units([slow], units, out_dir=tmp_path / "out", timeout_s=0.5, jobs=3)

    assert len(runs) == 3
    assert {run.status for run in runs} == {RunStatus.TIMED_OUT}
    for run in runs:
        limitation = run.limitation()
        assert limitation is not None
        assert limitation.kind is LimitationKind.ANALYZER_FAILED
        assert str(run.unit) in limitation.detail
        assert "clang" in limitation.detail


def test_an_analyzer_that_aborts_is_not_a_clean_translation_unit(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    """T-07-16: exit 134, no output — a recorded blind spot, not silence."""
    root, units = tree
    crasher = _stub_analyzer(root, "raise SystemExit(134)")

    runs = run_units([crasher], units[:1], out_dir=tmp_path / "out", timeout_s=10.0)

    assert runs[0].status is RunStatus.CRASHED
    assert runs[0].exit_code == 134
    limitation = runs[0].limitation()
    assert limitation is not None
    assert limitation.kind is LimitationKind.ANALYZER_FAILED
    assert "128 + signal 6" in limitation.detail
    assert runs[0].read_raw_output() == ""


def test_one_failing_unit_does_not_stop_the_others(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    root, units = tree
    healthy = _stub_analyzer(root, "print('ok')")
    broken = _stub_analyzer(root, "raise SystemExit(139)")

    runs = run_units([healthy, broken], units, out_dir=tmp_path / "out", timeout_s=10.0, jobs=2)

    assert len(runs) == 6
    assert sum(1 for run in runs if run.ok) == 3
    assert sum(1 for run in runs if run.status is RunStatus.CRASHED) == 3


def test_a_non_zero_exit_still_has_its_output_parsed(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    """clang-tidy exits non-zero on a compile error and still reports."""
    root, units = tree
    analyzer = _stub_analyzer(
        root,
        "import sys; sys.stderr.write('src/a.c:3:5: warning: x [-Wshadow]\\n'); sys.exit(1)",
    )

    run = run_units([analyzer], units[:1], out_dir=tmp_path / "out", timeout_s=10.0)[0]

    assert run.status is RunStatus.NONZERO_EXIT
    assert run.limitation() is not None
    assert run.status.produced_output
    assert "-Wshadow" in run.read_raw_output()


def test_a_missing_binary_is_a_toolchain_limitation_not_a_crash(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    root, units = tree
    analyzer = DiagnosticsAnalyzer(
        profile=load_profile(),
        normalizer=_normalizer(root),
        clang="caudit-definitely-not-installed",
        tool_version="unknown",
    )

    run = run_units([analyzer], units[:1], out_dir=tmp_path / "out", timeout_s=10.0)[0]

    assert run.status is RunStatus.TOOL_MISSING
    limitation = run.limitation()
    assert limitation is not None
    assert limitation.kind is LimitationKind.TOOLCHAIN_UNAVAILABLE
    assert "is not on PATH" in limitation.detail
    assert "my_docs/guides/setup.md" in limitation.detail


# ---------------------------------------------------------------- ordering


def test_results_come_back_in_unit_order_whatever_finishes_first(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    """AC-07-11: the schedule must not decide what a report says.

    ``src/a.c`` sleeps longest and ``src/c.c`` returns instantly, so with three
    workers the completion order is the reverse of the request order.
    """
    root, units = tree
    analyzer = _stub_analyzer(root, "pass")
    delays = {"src/a.c": 0.6, "src/b.c": 0.3, "src/c.c": 0.0}
    analyzer.command = lambda unit: [  # type: ignore[method-assign]
        PYTHON,
        "-c",
        f"import time; time.sleep({delays[str(unit.file)]})",
    ]

    runs = run_units([analyzer], units, out_dir=tmp_path / "out", timeout_s=20.0, jobs=3)

    assert [str(run.unit) for run in runs] == ["src/a.c", "src/b.c", "src/c.c"]


# --------------------------------------------------------------- arguments


def test_analysis_flags_drop_argv_zero_and_the_input_file() -> None:
    unit = TranslationUnit(
        file="src/a.c",
        directory=Path("/build"),
        arguments=["clang", "-std=c11", "-Iinc", "-c", "src/a.c", "-o", "a.o"],
        language="c",
    )

    assert source_argument(unit) == "src/a.c"
    assert analysis_flags(unit) == ["-std=c11", "-Iinc"]


def test_analysis_flags_keep_every_flag_the_build_stated() -> None:
    """Never add, never guess — and never quietly drop an include path."""
    unit = TranslationUnit(
        file="src/a.c",
        directory=Path("/build"),
        arguments=["cc", "-DFOO=1", "-I", "inc", "-isystem", "/opt/x", "-c", "/abs/src/a.c"],
        language="c",
    )
    assert analysis_flags(unit) == ["-DFOO=1", "-I", "inc", "-isystem", "/opt/x"]


def test_a_database_that_never_names_its_input_falls_back_to_the_plan() -> None:
    unit = TranslationUnit(
        file="src/a.c", directory=Path("/build"), arguments=["clang", "-c"], language="c"
    )
    assert source_argument(unit) == "src/a.c"


def test_the_recorded_command_shows_what_came_from_the_build(tmp_path: Path) -> None:
    """A report has to be able to name the command that produced it."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text("int a(void){return 0;}\n", encoding="utf-8")
    unit = make_translation_unit(
        root, "src/a.c", arguments=["clang", "-std=c11", "-Iinc", "src/a.c"]
    )
    profile = load_profile()

    tidy = TidyAnalyzer(profile=profile, normalizer=_normalizer(root))
    command = tidy.command(unit, tmp_path / "fixes.yaml")
    assert "--fix" not in command
    assert command[command.index("--") + 1 :][:2] == ["-std=c11", "-Iinc"]

    csa = CsaAnalyzer(
        profile=profile, normalizer=_normalizer(root), checkers=["core.NullDereference"]
    )
    assert "-analyzer-checker=core.NullDereference" in csa.command(unit, tmp_path / "o.sarif")
    assert "-analyzer-output=sarif" in csa.command(unit, tmp_path / "o.sarif")


# ------------------------------------------------------ generate_candidates


def test_generate_candidates_records_that_no_analyzer_ran(
    tree: tuple[Path, list[TranslationUnit]],
) -> None:
    """The loudest limitation in the package: nothing looked."""
    root, units = tree
    config = Config.model_validate(
        {"analyzers": {"clang": "caudit-no-clang", "clang_tidy": "caudit-no-tidy"}}
    )
    index = Index(revision="test-revision", repo_root=root, libclang="stub")

    result = generate_candidates(_plan(root, units), index, config)

    assert result.candidates == []
    assert result.runs == []
    kinds = {limitation.kind for limitation in result.limitations}
    assert kinds == {LimitationKind.TOOLCHAIN_UNAVAILABLE}
    assert any("did not look" in item.detail for item in result.limitations)


def test_generate_candidates_runs_every_analyzer_over_every_unit(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    """Three analyzers, three units, and a stub that never starts a process."""
    root, units = tree
    diagnostics = "src/a.c:3:5: warning: unused thing [-Wshadow]\n"
    runner = stub_subprocess(
        output=diagnostics,
        writes={"--export-fixes": "Diagnostics: []\n", "--analyze": '{"runs": []}'},
    )
    config = Config()
    index = Index(revision="test-revision", repo_root=root, libclang="stub")

    result = generate_candidates(
        _plan(root, units),
        index,
        config,
        out_dir=tmp_path / "raw",
        subprocess_runner=runner,
    )

    assert len(result.runs) == 9
    assert result.analyzers_that_ran == {"clang", "clang-static-analyzer", "clang-tidy"}
    assert result.tool_versions == {
        "clang": "18.1.8",
        "clang-static-analyzer": "18.1.8",
        "clang-tidy": "18.1.8",
    }
    assert result.profile_version == "1"
    # The -Wshadow warning names src/a.c, so it lands once per unit that saw it
    # and merges into a single candidate for that file.
    assert [str(c.region.path) for c in result.candidates] == ["src/a.c"]


def test_generate_candidates_is_independent_of_completion_order(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    """AC-07-11 end to end: same inputs, same candidate list, twice."""
    root, units = tree
    runner = stub_subprocess(
        output="src/a.c:3:5: warning: unused thing [-Wshadow]\n",
        writes={"--export-fixes": "Diagnostics: []\n", "--analyze": '{"runs": []}'},
    )
    index = Index(revision="test-revision", repo_root=root, libclang="stub")
    plan = _plan(root, units)

    first = generate_candidates(
        plan, index, Config(), out_dir=tmp_path / "one", subprocess_runner=runner
    )
    shuffled = _plan(root, [units[2], units[0], units[1]])
    second = generate_candidates(
        shuffled, index, Config(), out_dir=tmp_path / "two", subprocess_runner=runner
    )

    assert [c.model_dump(mode="json") for c in first.candidates] == [
        c.model_dump(mode="json") for c in second.candidates
    ]


def test_raw_output_is_retained_for_provenance(
    tree: tuple[Path, list[TranslationUnit]], tmp_path: Path
) -> None:
    root, units = tree
    runner = stub_subprocess(
        output="", writes={"--export-fixes": "Diagnostics: []\n", "--analyze": '{"runs": []}'}
    )
    index = Index(revision="test-revision", repo_root=root, libclang="stub")

    result = generate_candidates(
        _plan(root, units[:1]),
        index,
        Config(),
        out_dir=tmp_path / "raw",
        subprocess_runner=runner,
    )

    retained = sorted(path.name for path in (tmp_path / "raw").iterdir())
    assert "src__a.c.tidy.yaml" in retained
    assert "src__a.c.csa.sarif" in retained
    for run in result.runs:
        assert isinstance(run, AnalyzerRun)
        assert run.command

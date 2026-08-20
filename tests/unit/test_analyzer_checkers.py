"""Part 07: the static-analyzer capability probe, and what a scan prints.

An unknown checker id makes Clang refuse the whole translation unit, so a
profile pinned to one LLVM release would otherwise fail every unit on another.
The probe is what keeps a checker-set difference a recorded limitation rather
than a run-wide failure — and the difference between "no checkers" and "would
not say" is the same one this project draws everywhere else.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from rich.console import Console

from caudit.analyzers.csa import available_checkers
from caudit.analyzers.normalize import Normalizer
from caudit.analyzers.profile import load_profile
from caudit.analyzers.runner import CommandResult, RunStatus, checkers_unavailable
from caudit.analyzers.service import AnalyzerResult, build_analyzers, generate_candidates
from caudit.config.loader import Config
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.intake.plan import Coverage, ScanPlan
from caudit.model.finding import LimitationKind
from caudit.report.console import render_candidates, summarize_candidates
from tests.conftest import make_translation_unit, stub_subprocess

CHECKER_HELP = """\
USAGE: -analyzer-checker <CHECKER or PACKAGE,...>

CHECKERS:
  core.CallAndMessage          Check for logical errors
  core.NullDereference         Check for dereferences of null pointers
  unix.Malloc                  Check for memory leaks and double frees
  alpha.core.Conversion        Check for loss of information
"""


def _normalizer(root: Path) -> Normalizer:
    return Normalizer(store=SourceStore(root, revision="test"), profile=load_profile(), index=None)


def _help_runner(output: str, status: RunStatus = RunStatus.OK, exit_code: int = 0):  # type: ignore[no-untyped-def]
    def run(command: Sequence[str], _cwd: Path | None, _timeout: float) -> CommandResult:
        if "--version" in command:
            return CommandResult(RunStatus.OK, 0, "clang version 18.1.8", 0.0)
        return CommandResult(status, exit_code, output, 0.0)

    return run


# ------------------------------------------------------------------- probe


def test_the_probe_reads_the_checker_names_clang_lists() -> None:
    found = available_checkers("clang", subprocess_runner=_help_runner(CHECKER_HELP))

    assert found is not None
    assert "core.NullDereference" in found
    assert "alpha.core.Conversion" in found
    # The usage banner is not a checker.
    assert not any(name.startswith("USAGE") for name in found)


def test_a_probe_that_says_nothing_is_not_evidence_of_no_checkers() -> None:
    """``None`` means "we could not look", and the profile is used unfiltered."""
    silent = _help_runner("", status=RunStatus.CRASHED, exit_code=1)
    assert available_checkers("clang", subprocess_runner=silent) is None

    missing = _help_runner("", status=RunStatus.TOOL_MISSING, exit_code=-1)
    assert available_checkers("clang", subprocess_runner=missing) is None


def test_checkers_the_toolchain_lacks_become_a_named_limitation(tmp_path: Path) -> None:
    """A checker-set difference between LLVM releases is a blind spot, not a crash."""
    analyzers, limitations = build_analyzers(
        profile=load_profile(),
        normalizer=_normalizer(tmp_path),
        config=Config(),
        subprocess_runner=_help_runner(CHECKER_HELP),
    )

    csa = next(a for a in analyzers if a.tool_name == "clang-static-analyzer")
    assert set(csa.checkers) == {  # type: ignore[attr-defined]
        "core.CallAndMessage",
        "core.NullDereference",
        "unix.Malloc",
        "alpha.core.Conversion",
    }
    unavailable = [
        item for item in limitations if item.kind is LimitationKind.TOOLCHAIN_UNAVAILABLE
    ]
    assert unavailable
    assert "alpha.security.ArrayBound" in unavailable[0].detail
    assert "did not run" in unavailable[0].detail


def test_an_unanswering_probe_leaves_the_profile_unfiltered(tmp_path: Path) -> None:
    analyzers, limitations = build_analyzers(
        profile=load_profile(),
        normalizer=_normalizer(tmp_path),
        config=Config(),
        subprocess_runner=_help_runner("", status=RunStatus.CRASHED, exit_code=1),
    )

    csa = next(a for a in analyzers if a.tool_name == "clang-static-analyzer")
    assert len(csa.checkers) == len(load_profile().csa_checkers())  # type: ignore[attr-defined]
    assert not [i for i in limitations if i.kind is LimitationKind.TOOLCHAIN_UNAVAILABLE]


def test_the_limitation_wording_never_claims_the_checks_found_nothing() -> None:
    limitation = checkers_unavailable("clang", ["alpha.unix.Stream"])
    assert "did not run" in limitation.detail
    assert "nothing they would have found is in this report" in limitation.detail


def test_disabling_a_producer_in_config_drops_only_that_one(tmp_path: Path) -> None:
    config = Config.model_validate({"analyzers": {"enable_csa": False}})
    analyzers, _ = build_analyzers(
        profile=load_profile(),
        normalizer=_normalizer(tmp_path),
        config=config,
        subprocess_runner=_help_runner(CHECKER_HELP),
    )
    assert {a.tool_name for a in analyzers} == {"clang", "clang-tidy"}


# ------------------------------------------------------------- what prints


@pytest.fixture
def result(tmp_path: Path) -> AnalyzerResult:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text("void a(void)\n{\n    return;\n}\n", encoding="utf-8")
    unit = make_translation_unit(root, "src/a.c")
    plan = ScanPlan(
        repo_root=root,
        revision="test",
        compile_commands_path=root / "compile_commands.json",
        units=[unit],
        coverage=Coverage(
            tus_in_database=1,
            tus_selected=1,
            source_files_in_tree=1,
            source_files_covered=1,
            coverage_ratio=1.0,
        ),
    )
    runner = stub_subprocess(
        output="src/a.c:3:5: warning: unreachable code [-Wunreachable-code]\n",
        writes={"--export-fixes": "Diagnostics: []\n", "--analyze": '{"runs": []}'},
    )
    return generate_candidates(
        plan,
        Index(revision="test", repo_root=root, libclang="stub"),
        Config(),
        out_dir=tmp_path / "raw",
        subprocess_runner=runner,
    )


def test_the_summary_names_the_profile_and_every_analyzer_version(
    result: AnalyzerResult,
) -> None:
    """A report has to name the ruleset and the versions that produced it."""
    rows = dict(summarize_candidates(result))

    assert rows["check profile"] == "v1"
    assert rows["analyzer — clang"] == "18.1.8"
    assert rows["analyzer — clang-tidy"] == "18.1.8"
    assert rows["candidates"] == "1"


def test_the_summary_never_sums_two_producer_counts(result: AnalyzerResult) -> None:
    """ "Three analyzers agree" and "one check fired thrice" stay distinguishable."""
    labels = [label for label, _ in summarize_candidates(result)]
    assert not any("total" in label.lower() for label in labels)
    assert any(label.startswith("candidates naming ") for label in labels)


def test_an_unmapped_candidate_is_counted_as_review_bound(result: AnalyzerResult) -> None:
    rows = dict(summarize_candidates(result))
    assert rows["candidates with no CWE mapping (routed to review)"] == "1"


def test_rendering_a_run_with_no_analyzer_says_it_is_not_a_clean_result() -> None:
    console = Console(file=None, record=True, width=100, soft_wrap=True, markup=False)
    render_candidates(AnalyzerResult(profile_version="1"), console)
    text = console.export_text()

    assert "No analyzer ran" in text
    assert "not a clean result" in text
    assert "caudit doctor" in text

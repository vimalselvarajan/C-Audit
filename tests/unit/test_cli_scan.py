"""Part 05 CLI tests: the flags, the exit codes, and what reaches the terminal.

The plan summary is the only place a user learns that a scan covered 62% of
their tree. If it does not print, a short report and a thorough one look
identical.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.cli.main import main
from caudit.cli.scan_cmd import apply_scan_overrides
from caudit.config.loader import Config
from caudit.intake import load_scan_plan
from caudit.report.console import summarize_plan
from caudit.status import ExitCode
from tests.conftest import compdb_entry, intake_config, write_compdb, write_tree


def _project(tmp_path: Path, total: int = 3, covered: int | None = None) -> tuple[Path, Path]:
    covered = total if covered is None else covered
    root = write_tree(
        tmp_path, {f"src/f{index}.c": f"void f{index}(void){{}}\n" for index in range(total)}
    )
    database = write_compdb(
        root, [compdb_entry(root, str(root / f"src/f{index}.c")) for index in range(covered)]
    )
    return root, database


@pytest.mark.needs_libclang
def test_scan_prints_the_plan_the_index_and_the_candidates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, database = _project(tmp_path)
    code = main(["scan", str(root), "--compile-commands", str(database)])
    out = capsys.readouterr()

    # No Clang on this machine, so nothing looked; see the exit-code rule in
    # scan_cmd. On a machine with a toolchain this is 0 or 1 instead.
    assert code in {int(ExitCode.OK), int(ExitCode.FINDINGS), int(ExitCode.ENVIRONMENT)}
    assert "translation units selected" in out.out
    assert "source files covered" in out.out
    assert "cannot claim reproducibility" in out.out
    # Part 06's half: the plan is described, then indexed.
    assert "translation units indexed" in out.out
    assert "3/3" in out.out
    assert "symbols" in out.out
    # Part 07's half: the profile and the candidate count.
    assert "check profile" in out.out
    assert "candidates" in out.out
    # Part 08's half: the three artifacts, named where they were written.
    assert "report.md" in out.out
    assert "results.sarif" in out.out
    assert "run-manifest.json" in out.out


@pytest.mark.needs_libclang
def test_a_scan_with_no_analyzer_says_so_rather_than_reporting_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-07-7's posture at the CLI: "we did not look" must not read as "clean".

    The binaries are pointed at names that cannot exist, so this asserts the
    same thing on a machine with a full toolchain and on one with none.
    """
    root, database = _project(tmp_path)
    code = main(
        [
            "--set",
            "analyzers.clang=caudit-no-such-clang",
            "--set",
            "analyzers.clang_tidy=caudit-no-such-clang-tidy",
            "scan",
            str(root),
            "--compile-commands",
            str(database),
        ]
    )
    out = capsys.readouterr()

    # Exit 3, not 0: a run that could not look must not report the status a
    # clean run reports, however loud the report text is.
    assert code == int(ExitCode.ENVIRONMENT)
    assert "No analyzer ran" in out.out
    assert "not a clean result" in out.out
    assert "caudit-no-such-clang" in out.out


@pytest.mark.needs_libclang
def test_the_index_summary_names_a_unit_that_did_not_parse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dropped unit is the quietest way a scan misleads, so it is printed."""
    root, _database = _project(tmp_path, total=3)
    (root / "src" / "broken.c").write_text("int broken(void) { return\n", encoding="utf-8")
    database = write_compdb(
        root,
        [compdb_entry(root, str(root / f"src/{name}.c")) for name in ("f0", "f1", "f2", "broken")],
    )
    code = main(["scan", str(root), "--compile-commands", str(database)])
    out = capsys.readouterr()

    assert code == int(ExitCode.ENVIRONMENT)
    assert "3/4" in out.out
    assert "src/broken.c" in out.out
    assert "What the index could not see" in out.out
    assert "parse_failed" in out.out


def test_scan_below_the_coverage_floor_exits_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, database = _project(tmp_path, total=10, covered=3)
    code = main(["scan", str(root), "--compile-commands", str(database)])
    assert code == int(ExitCode.ENVIRONMENT)
    assert "0.30" in capsys.readouterr().err


@pytest.mark.needs_libclang
def test_allow_partial_coverage_flag_lets_the_scan_proceed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_analyzers: None
) -> None:
    root, database = _project(tmp_path, total=10, covered=3)
    code = main(
        [
            "scan",
            str(root),
            "--compile-commands",
            str(database),
            "--allow-partial-coverage",
        ]
    )
    out = capsys.readouterr()
    assert code == int(ExitCode.ENVIRONMENT)
    assert "intake.allow_partial_coverage" in out.out
    assert "Known blind spots" in out.out


@pytest.mark.needs_libclang
def test_target_flag_narrows_the_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_analyzers: None
) -> None:
    root, database = _project(tmp_path, total=3)
    code = main(["scan", str(root), "--compile-commands", str(database), "--target", "src/f1.c"])
    out = capsys.readouterr()
    assert code == int(ExitCode.ENVIRONMENT)
    assert "excluded — not_selected" in out.out
    assert "confirmed findings" in out.out


def test_scan_on_a_path_that_is_not_a_directory_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _root, database = _project(tmp_path)
    code = main(["scan", str(database), "--compile-commands", str(database)])
    assert code == int(ExitCode.USAGE)
    assert "not a directory" in capsys.readouterr().err


def test_a_flag_the_user_did_not_pass_cannot_undo_their_config_file() -> None:
    """`--allow-partial-coverage` can only turn the setting on, never off."""
    configured = intake_config(allow_partial_coverage=True, targets=["src/a.c"])
    unchanged = apply_scan_overrides(configured, targets=[], allow_partial_coverage=False)
    assert unchanged.intake.allow_partial_coverage is True
    assert unchanged.intake.targets == ["src/a.c"]

    narrowed = apply_scan_overrides(Config(), targets=["src/b.c"], allow_partial_coverage=True)
    assert narrowed.intake.targets == ["src/b.c"]
    assert narrowed.intake.allow_partial_coverage is True


def test_the_summary_never_sums_two_counts(tmp_path: Path) -> None:
    """Confirmed-vs-review-required is not the only pair that must stay apart."""
    root, database = _project(tmp_path, total=4, covered=3)
    plan = load_scan_plan(
        root,
        database,
        intake_config(),
        git_runner=lambda _args, _cwd: None,
    )
    rows = dict(summarize_plan(plan))
    assert rows["entries in database"] == "3"
    assert rows["translation units selected"] == "3"
    assert rows["source files covered"] == "3/4 (0.75)"
    assert not any("total" in label.lower() for label in rows)


def test_intake_configuration_is_visible_in_print_config(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A floor that decides whether a run stops has to be inspectable."""
    assert main(["--print-config"]) == int(ExitCode.OK)
    out = capsys.readouterr().out
    assert "intake.coverage_floor" in out
    assert "0.6" in out

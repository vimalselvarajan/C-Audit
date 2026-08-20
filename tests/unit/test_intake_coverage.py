"""Part 05 coverage tests: T-05-08, T-05-09, T-05-10, T-05-17.

"Materially incomplete" has to be a number or every run argues with itself
about whether to proceed. These tests pin the number, the boundary, and the
escape hatch — and check that the escape hatch leaves a mark.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from caudit.errors import IntakeError
from caudit.intake import load_scan_plan
from caudit.intake.coverage import build_coverage, check_completeness
from caudit.intake.plan import Coverage, ExclusionReason
from caudit.status import ExitCode
from tests.conftest import compdb_entry, intake_config, write_compdb, write_tree


def _repo_with(tmp_path: Path, total: int, covered: int) -> tuple[Path, Path]:
    """A tree of ``total`` source files of which ``covered`` are in the database."""
    root = write_tree(
        tmp_path,
        {f"src/f{index}.c": f"void f{index}(void) {{}}\n" for index in range(total)},
    )
    database = write_compdb(
        root, [compdb_entry(root, str(root / f"src/f{index}.c")) for index in range(covered)]
    )
    return root, database


def test_coverage_below_the_floor_stops_and_names_both_numbers(tmp_path: Path) -> None:
    """T-05-08: 3 of 10 covered — the stop prints 0.30 and the 0.60 floor."""
    root, database = _repo_with(tmp_path, total=10, covered=3)
    with pytest.raises(IntakeError) as excinfo:
        load_scan_plan(root, database, intake_config())

    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT
    assert "0.30" in excinfo.value.message
    assert "0.60" in excinfo.value.message
    assert "3 of 10" in excinfo.value.message

    hint = excinfo.value.hint or ""
    assert "src/f9.c" in hint, "the stop must name the files that were missed"
    assert "--allow-partial-coverage" in hint
    assert "intake.coverage_floor" in hint
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in hint


def test_allow_partial_coverage_proceeds_and_records_the_gap(tmp_path: Path) -> None:
    """T-05-09: the escape hatch is a decision, and it leaves a mark."""
    root, database = _repo_with(tmp_path, total=10, covered=3)
    plan = load_scan_plan(root, database, intake_config(allow_partial_coverage=True))

    assert plan.coverage.coverage_ratio == pytest.approx(0.30)
    assert plan.coverage.source_files_covered == 3
    assert plan.coverage.source_files_in_tree == 10

    gaps = [item for item in plan.limitations if item.kind == "missing_build_target"]
    assert gaps, "proceeding below the floor must be recorded"
    assert "0.30" in gaps[0].detail
    assert "0.60" in gaps[0].detail
    assert "not evidence of their absence" in gaps[0].detail
    assert "intake.allow_partial_coverage" in plan.overrides


def test_coverage_exactly_at_the_floor_proceeds(tmp_path: Path) -> None:
    """T-05-10: the floor comparison is inclusive, and that is documented."""
    root, database = _repo_with(tmp_path, total=5, covered=3)
    plan = load_scan_plan(root, database, intake_config())
    assert plan.coverage.coverage_ratio == pytest.approx(0.60)
    assert plan.coverage.tus_selected == 3


def test_one_file_below_the_floor_stops(tmp_path: Path) -> None:
    """The other side of the boundary, so `>=` cannot silently become `>`."""
    root, database = _repo_with(tmp_path, total=5, covered=2)
    with pytest.raises(IntakeError):
        load_scan_plan(root, database, intake_config())


def test_the_floor_is_configurable(tmp_path: Path) -> None:
    root, database = _repo_with(tmp_path, total=10, covered=3)
    plan = load_scan_plan(root, database, intake_config(coverage_floor=0.25))
    assert plan.coverage.coverage_ratio == pytest.approx(0.30)


def test_partial_coverage_above_the_floor_is_still_recorded(tmp_path: Path) -> None:
    """Between the floor and 1.0 the run proceeds — and still says what it missed."""
    root, database = _repo_with(tmp_path, total=4, covered=3)
    plan = load_scan_plan(root, database, intake_config())
    gaps = [item for item in plan.limitations if item.kind == "missing_build_target"]
    assert gaps
    assert "1 of 4 source files are not described" in gaps[0].detail
    assert gaps[0].affects == "src/f3.c"


def test_complete_coverage_records_nothing(tmp_path: Path) -> None:
    root, database = _repo_with(tmp_path, total=3, covered=3)
    plan = load_scan_plan(root, database, intake_config())
    assert plan.coverage.is_complete
    assert plan.coverage.coverage_ratio == 1.0
    assert "missing_build_target" not in plan.limitation_kinds()


def test_a_source_file_missing_from_disk_is_excluded_and_the_run_continues(
    tmp_path: Path,
) -> None:
    """T-05-17: the build claims a file that is not there. Note it and go on."""
    root = write_tree(tmp_path, {"src/present.c": "void present(void){}\n"})
    database = write_compdb(
        root,
        [
            compdb_entry(root, str(root / "src/present.c")),
            compdb_entry(root, str(root / "src/vanished.c")),
        ],
    )
    plan = load_scan_plan(root, database, intake_config())

    assert [unit.file for unit in plan.units] == [PurePosixPath("src/present.c")]
    assert plan.excluded_by(ExclusionReason.MISSING_SOURCE) == [PurePosixPath("src/vanished.c")]
    missing = [
        item
        for item in plan.limitations
        if item.kind == "missing_build_target" and "missing_source" in item.detail
    ]
    assert missing
    assert missing[0].affects == "src/vanished.c"


def test_an_entry_outside_the_repository_is_counted_but_not_citable(tmp_path: Path) -> None:
    """It has no repository-relative path, so nothing in it could be cited."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "far.c").write_text("void far_away(void){}\n", encoding="utf-8")
    root = write_tree(tmp_path / "repo", {"src/a.c": "void a(void){}\n"})
    database = write_compdb(
        root,
        [
            compdb_entry(root, str(root / "src/a.c")),
            compdb_entry(root, str(outside / "far.c")),
        ],
    )
    plan = load_scan_plan(root, database, intake_config())

    assert [unit.file for unit in plan.units] == [PurePosixPath("src/a.c")]
    assert plan.coverage.tus_in_database == 2
    assert plan.coverage.tus_excluded[ExclusionReason.NOT_SELECTED] == 1
    assert plan.excluded == [], "an out-of-tree path cannot be listed repository-relative"
    assert any("outside the repository root" in item.detail for item in plan.limitations)


def test_headers_are_not_counted_in_the_denominator(tmp_path: Path) -> None:
    """Every honest C project would look half-uncovered otherwise."""
    root = write_tree(
        tmp_path,
        {
            "src/a.c": '#include "a.h"\nvoid a(void){}\n',
            "src/a.h": "void a(void);\n",
            "include/shared.h": "int shared;\n",
        },
    )
    database = write_compdb(root, [compdb_entry(root, str(root / "src/a.c"))])
    plan = load_scan_plan(root, database, intake_config())
    assert plan.coverage.source_files_in_tree == 1
    assert plan.coverage.coverage_ratio == 1.0


def test_a_header_with_its_own_entry_is_excluded(tmp_path: Path) -> None:
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n", "src/a.h": "void a(void);\n"})
    database = write_compdb(
        root,
        [compdb_entry(root, str(root / "src/a.c")), compdb_entry(root, str(root / "src/a.h"))],
    )
    plan = load_scan_plan(root, database, intake_config())
    assert plan.excluded_by(ExclusionReason.UNSUPPORTED_LANGUAGE) == [PurePosixPath("src/a.h")]


def test_an_empty_tree_counts_as_fully_covered() -> None:
    coverage = build_coverage(
        entries_in_database=0,
        selected=0,
        exclusions=[],
        files_present=[],
        files_in_database=[],
    )
    assert coverage.coverage_ratio == 1.0
    assert coverage.is_complete


def test_check_completeness_returns_none_when_nothing_is_missing() -> None:
    coverage = Coverage(
        tus_in_database=1,
        tus_selected=1,
        tus_excluded={},
        source_files_in_tree=1,
        source_files_covered=1,
        coverage_ratio=1.0,
    )
    assert check_completeness(coverage, intake_config().intake, compdb_path=Path("x")) is None


def test_coverage_rejects_impossible_arithmetic() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        Coverage(
            tus_in_database=2,
            tus_selected=2,
            tus_excluded={ExclusionReason.THIRD_PARTY: 1},
            source_files_in_tree=1,
            source_files_covered=1,
            coverage_ratio=1.0,
        )
    with pytest.raises(ValueError, match="covered exceeds"):
        Coverage(
            tus_in_database=1,
            tus_selected=1,
            tus_excluded={},
            source_files_in_tree=1,
            source_files_covered=2,
            coverage_ratio=1.0,
        )

"""Part 05 plan tests: T-05-15, T-05-20, and the ScanPlan invariants.

A plan that differs between two runs on unchanged inputs makes every
downstream comparison meaningless, so determinism is asserted on the
serialized bytes rather than on a field at a time.
"""

from __future__ import annotations

import json
import random
from pathlib import Path, PurePosixPath

import pytest

from caudit.errors import IntakeError
from caudit.intake import load_scan_plan
from caudit.intake.plan import (
    UNKNOWN_REVISION,
    Coverage,
    ExclusionReason,
    ScanPlan,
    TranslationUnit,
)
from caudit.model.finding import LimitationKind
from tests.conftest import compdb_entry, intake_config, write_compdb, write_tree


def _plan(root: Path, database: Path, **intake: object) -> ScanPlan:
    """Load with the revision probe stubbed out, so tmp_path is never a repo."""
    return load_scan_plan(
        root, database, intake_config(**intake), git_runner=lambda _args, _cwd: None
    )


def test_duplicate_entries_resolve_to_one_unit_and_record_the_collision(
    tmp_path: Path,
) -> None:
    """T-05-15: a multi-config build lists one file twice. Last entry wins."""
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    absolute = str(root / "src/a.c")
    database = write_compdb(
        root,
        [
            compdb_entry(root, absolute, arguments=["clang", "-DDEBUG=1", "-O0", "-c", absolute]),
            compdb_entry(root, absolute, arguments=["clang", "-DNDEBUG=1", "-O2", "-c", absolute]),
        ],
    )
    plan = _plan(root, database)

    assert len(plan.units) == 1
    assert "-DNDEBUG=1" in plan.units[0].arguments, "the last entry is the documented winner"
    assert plan.coverage.tus_in_database == 2
    assert plan.coverage.tus_selected == 1
    assert plan.coverage.duplicate_configurations == 1

    collisions = [
        item for item in plan.limitations if item.kind is LimitationKind.AMBIGUOUS_BUILD_CONFIG
    ]
    assert len(collisions) == 1
    assert "compiled 2 times" in collisions[0].detail
    assert collisions[0].affects == "src/a.c"


def test_three_configurations_of_one_file_record_two_discards(tmp_path: Path) -> None:
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    absolute = str(root / "src/a.c")
    database = write_compdb(
        root,
        [
            compdb_entry(root, absolute, arguments=["clang", f"-DCONFIG={n}", "-c", absolute])
            for n in range(3)
        ],
    )
    plan = _plan(root, database)
    assert len(plan.units) == 1
    assert "-DCONFIG=2" in plan.units[0].arguments
    collisions = [
        item for item in plan.limitations if item.kind is LimitationKind.AMBIGUOUS_BUILD_CONFIG
    ]
    assert "compiled 3 times" in collisions[0].detail
    assert "2 other configuration(s)" in collisions[0].detail


def test_the_plan_is_stable_when_unrelated_entries_are_shuffled(tmp_path: Path) -> None:
    """T-05-15, second half: ordering of distinct entries must not matter.

    Only the duplicate rule is positional. Everything else — unit order,
    exclusion order, limitation order — is sorted, so shuffling entries that
    do not collide leaves the serialized plan byte-identical.
    """
    root = write_tree(
        tmp_path, {f"src/f{index}.c": f"void f{index}(void){{}}\n" for index in range(6)}
    )
    entries = [compdb_entry(root, str(root / f"src/f{index}.c")) for index in range(6)]
    first = write_compdb(root, entries, name="ordered.json")

    shuffled = list(entries)
    random.Random(20260811).shuffle(shuffled)
    assert shuffled != entries
    second = write_compdb(root, shuffled, name="shuffled.json")

    left = _plan(root, first).model_dump(exclude={"compile_commands_path"})
    right = _plan(root, second).model_dump(exclude={"compile_commands_path"})
    assert left == right


def test_two_loads_of_the_same_inputs_serialize_identically(tmp_path: Path) -> None:
    """T-05-20: byte-for-byte, including unit order."""
    root = write_tree(
        tmp_path,
        {
            "src/b.c": "void b(void){}\n",
            "src/a.c": "void a(void){}\n",
            "third_party/dep.c": "void dep(void){}\n",
            "src/gen.pb.cc": "void gen(void){}\n",
        },
    )
    database = write_compdb(
        root,
        [
            compdb_entry(root, str(root / relative))
            for relative in ("src/b.c", "src/a.c", "third_party/dep.c", "src/gen.pb.cc")
        ],
    )

    first = _plan(root, database).model_dump_json()
    second = _plan(root, database).model_dump_json()
    assert first == second

    decoded = json.loads(first)
    assert [unit["file"] for unit in decoded["units"]] == ["src/a.c", "src/b.c"]
    assert decoded["revision"] == UNKNOWN_REVISION


def test_a_plan_round_trips_through_json(tmp_path: Path) -> None:
    """AC-05-11: serializable means deserializable, not merely printable."""
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    database = write_compdb(root, [compdb_entry(root, str(root / "src/a.c"))])
    plan = _plan(root, database)
    assert ScanPlan.model_validate_json(plan.model_dump_json()) == plan


def test_a_plan_cannot_disagree_with_its_own_coverage(tmp_path: Path) -> None:
    coverage = Coverage(
        tus_in_database=1,
        tus_selected=1,
        tus_excluded={},
        source_files_in_tree=1,
        source_files_covered=1,
        coverage_ratio=1.0,
    )
    with pytest.raises(ValueError, match="coverage reports 1"):
        ScanPlan(
            repo_root=Path("/repo"),
            revision=UNKNOWN_REVISION,
            compile_commands_path=Path("/repo/compile_commands.json"),
            units=[],
            coverage=coverage,
        )


def test_a_plan_cannot_hold_one_file_twice() -> None:
    unit = TranslationUnit(
        file=PurePosixPath("src/a.c"),
        directory=Path("/repo/build"),
        arguments=["clang", "-c", "src/a.c"],
        language="c",
    )
    coverage = Coverage(
        tus_in_database=2,
        tus_selected=2,
        tus_excluded={},
        source_files_in_tree=1,
        source_files_covered=1,
        coverage_ratio=1.0,
    )
    with pytest.raises(ValueError, match="more than one selected unit"):
        ScanPlan(
            repo_root=Path("/repo"),
            revision=UNKNOWN_REVISION,
            compile_commands_path=Path("/repo/compile_commands.json"),
            units=[unit, unit],
            coverage=coverage,
        )


@pytest.mark.parametrize(
    "bad_path", ["/absolute/a.c", "../escape.c", "src/../../escape.c", "c:\\windows\\a.c"]
)
def test_a_translation_unit_cannot_point_outside_the_repository(bad_path: str) -> None:
    with pytest.raises(ValueError, match="path must"):
        TranslationUnit.model_validate(
            {
                "file": bad_path,
                "directory": "/repo/build",
                "arguments": ["clang", "-c", bad_path],
                "language": "c",
            }
        )


def test_a_translation_unit_requires_an_absolute_working_directory() -> None:
    with pytest.raises(ValueError, match="directory must be absolute"):
        TranslationUnit.model_validate(
            {
                "file": "src/a.c",
                "directory": "build",
                "arguments": ["clang", "-c", "src/a.c"],
                "language": "c",
            }
        )


def test_translation_unit_derived_views() -> None:
    unit = TranslationUnit(
        file=PurePosixPath("src/a.c"),
        directory=Path("/repo/build"),
        arguments=["clang", "-std=c11", "-c", "-o", "a.o", "src/a.c"],
        language="c",
        std="c11",
    )
    assert unit.compiler == "clang"
    assert unit.parse_arguments == ["clang", "-std=c11", "src/a.c"]
    assert unit.arguments == ["clang", "-std=c11", "-c", "-o", "a.o", "src/a.c"]


def test_plan_lookup_helpers(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path, {"src/a.c": "void a(void){}\n", "third_party/dep.c": "void dep(void){}\n"}
    )
    database = write_compdb(
        root,
        [
            compdb_entry(root, str(root / "src/a.c")),
            compdb_entry(root, str(root / "third_party/dep.c")),
        ],
    )
    plan = _plan(root, database)
    assert plan.unit_for("src/a.c") is not None
    assert plan.unit_for("src/absent.c") is None
    assert plan.excluded_by(ExclusionReason.THIRD_PARTY) == [PurePosixPath("third_party/dep.c")]
    assert plan.excluded_by(ExclusionReason.TOO_LARGE) == []


def test_a_root_that_is_not_a_directory_is_rejected(tmp_path: Path) -> None:
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    database = write_compdb(root, [compdb_entry(root, str(root / "src/a.c"))])
    with pytest.raises(IntakeError, match="not a directory"):
        load_scan_plan(root / "src" / "a.c", database, intake_config())

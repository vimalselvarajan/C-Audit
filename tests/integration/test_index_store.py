"""Part 06 store tests: T-06-13, T-06-14, and serialization.

Reproducibility is asserted on the serialized bytes rather than field by
field, because that is the property parts 08 and 12 actually depend on: two
runs over one tree have to produce the same index, or nothing downstream can
be compared between runs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.index import Index, build_index
from caudit.index.parser import ParseRequest
from caudit.index.store import IndexCache, IndexSnapshot
from caudit.intake import load_scan_plan
from caudit.intake.plan import ScanPlan
from tests.conftest import cpp_fixture, index_config

pytestmark = pytest.mark.needs_libclang


def planned(tmp_path: Path, name: str, **overrides: object) -> tuple[Path, ScanPlan, Config]:
    root, database = cpp_fixture(tmp_path, name)
    config = index_config(**overrides)
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    return root, plan, config


def test_two_builds_over_one_tree_serialize_identically(tmp_path: Path) -> None:
    """T-06-13, first half: byte-for-byte, cache or no cache."""
    _root, plan, config = planned(tmp_path, "cross_tu")
    cache = tmp_path / "cache"

    first = build_index(plan, config, cache_dir=cache).to_json()
    second = build_index(plan, config, cache_dir=cache).to_json()
    assert first == second

    fresh = build_index(plan, config, cache_dir=None).to_json()
    assert fresh == first, "a cached unit and a freshly parsed one are the same fact"


def test_an_unchanged_tree_is_not_parsed_twice(tmp_path: Path) -> None:
    """T-06-13, second half: the parse counter is zero on the second run."""
    _root, plan, config = planned(tmp_path, "cross_tu")
    cache = tmp_path / "cache"

    first = build_index(plan, config, cache_dir=cache)
    assert first.stats.parsed == 3
    assert first.stats.reused == 0

    second = build_index(plan, config, cache_dir=cache)
    assert second.stats.parsed == 0
    assert second.stats.reused == 3


def test_editing_a_header_reparses_only_the_units_that_include_it(
    tmp_path: Path,
) -> None:
    """T-06-14: `c.c` includes nothing, so it must not pay for a header edit."""
    root, plan, config = planned(tmp_path, "cross_tu")
    cache = tmp_path / "cache"
    build_index(plan, config, cache_dir=cache)

    header = root / "b.h"
    header.write_text(header.read_text(encoding="utf-8") + "int extra(void);\n", encoding="utf-8")

    second = build_index(plan, config, cache_dir=cache)
    assert second.stats.parsed == 2, "a.c and b.c include b.h"
    assert second.stats.reused == 1, "c.c does not"


def test_editing_one_source_reparses_only_that_unit(tmp_path: Path) -> None:
    root, plan, config = planned(tmp_path, "cross_tu")
    cache = tmp_path / "cache"
    build_index(plan, config, cache_dir=cache)

    source = root / "c.c"
    source.write_text(source.read_text(encoding="utf-8") + "int added(void){return 1;}\n")

    second = build_index(plan, config, cache_dir=cache)
    assert (second.stats.parsed, second.stats.reused) == (1, 2)
    assert second.symbols_named("added")


def test_a_cache_entry_written_by_another_libclang_is_ignored(tmp_path: Path) -> None:
    """The two majors can disagree on an AST, so the version is in the key."""
    root, plan, config = planned(tmp_path, "cross_tu")
    cache_dir = tmp_path / "cache"
    build_index(plan, config, cache_dir=cache_dir)

    request = ParseRequest(
        file=plan.units[0].file,
        repo_root=root,
        directory=plan.units[0].directory,
        arguments=tuple(plan.units[0].arguments),
        language=plan.units[0].language,
    )
    mine = IndexCache(directory=cache_dir, libclang="18.1.1")
    theirs = IndexCache(directory=cache_dir, libclang="19.1.0")
    assert mine.key(request) != theirs.key(request)
    assert theirs.get(request, repo_root=root) is None


def test_a_corrupt_cache_entry_is_a_miss_not_a_crash(tmp_path: Path) -> None:
    """The cache is an optimisation; it must never change what is reported."""
    _root, plan, config = planned(tmp_path, "cross_tu")
    cache_dir = tmp_path / "cache"
    build_index(plan, config, cache_dir=cache_dir)
    for entry in cache_dir.glob("*.json"):
        entry.write_text("{ this is not json", encoding="utf-8")

    second = build_index(plan, config, cache_dir=cache_dir)
    assert second.stats.parsed == 3
    assert second.stats.reused == 0


def test_an_index_round_trips_through_its_snapshot(tmp_path: Path) -> None:
    root, plan, config = planned(tmp_path, "basic")
    index = build_index(plan, config)
    path = index.write(tmp_path / "index.json")

    restored = Index.read(path, repo_root=root)
    assert restored.to_json() == index.to_json()
    assert restored.symbols_named("parse_header")[0] == index.symbols_named("parse_header")[0]
    assert restored.limitations() == index.limitations()
    assert restored.libclang == index.libclang


def test_the_snapshot_carries_no_wall_clock_or_scheduling_detail(tmp_path: Path) -> None:
    """Durations and cache provenance would make two equal runs differ."""
    _root, plan, config = planned(tmp_path, "basic")
    index = build_index(plan, config)
    decoded = json.loads(index.to_json())

    assert set(decoded) == set(IndexSnapshot.model_fields)
    assert "duration_seconds" not in json.dumps(decoded)
    assert {unit["status"] for unit in decoded["units"]} == {"indexed"}
    assert index.stats.seconds > 0.0, "the run still measures itself, out of band"


def test_the_plans_blind_spots_travel_into_the_index(tmp_path: Path) -> None:
    """One place to ask what was not seen, whatever the reason."""
    _root, plan, config = planned(tmp_path, "cross_tu")
    index = build_index(plan, config)
    assert set(plan.limitations) <= set(index.limitations())

"""T-06-20: the 200-unit budget. Marked `slow`, so deselected by default.

The numbers here are budgets, not measurements to optimise against. They exist
to catch a change that makes indexing quadratic or that leaks a translation
unit's memory across the pool — both of which are invisible on a five-file
fixture and fatal on a real repository.
"""

from __future__ import annotations

import resource
import time
from pathlib import Path

import pytest

from caudit.index import build_index
from caudit.intake import load_scan_plan
from tests.conftest import index_config, write_compdb

pytestmark = [pytest.mark.slow, pytest.mark.needs_libclang]

#: Units in the generated tree.
UNITS = 200
#: Wall-clock ceiling for a cold parallel index of that tree.
BUDGET_SECONDS = 120.0
#: Resident-set ceiling for the parent process, in MiB. The parse itself
#: happens in workers, so a parent that grows with the unit count is holding
#: on to something it should have merged and released.
BUDGET_PARENT_MIB = 1024


def generate_tree(root: Path, units: int) -> Path:
    """A synthetic repository: `units` files, each calling the one before it."""
    source = root / "src"
    source.mkdir(parents=True)
    (source / "common.h").write_text(
        "#define SCALE 4\nstruct Item { int size; char name[16]; };\n", encoding="utf-8"
    )
    for index in range(units):
        previous = f"    total += unit_{index - 1}(item);\n" if index else ""
        declaration = f"int unit_{index - 1}(struct Item *item);\n" if index else ""
        (source / f"unit_{index:03d}.c").write_text(
            '#include "common.h"\n'
            f"{declaration}"
            f"int unit_{index}(struct Item *item)\n"
            "{\n"
            "    int total = item->size * SCALE;\n"
            f"{previous}"
            "    return total;\n"
            "}\n",
            encoding="utf-8",
        )
    entries = [
        {
            "directory": str(root),
            "file": str(path),
            "arguments": ["clang", "-std=c11", "-I", str(source), "-c", str(path)],
        }
        for path in sorted(source.glob("*.c"))
    ]
    return write_compdb(root, entries)


def test_two_hundred_units_index_within_budget(tmp_path: Path) -> None:
    root = tmp_path / "big"
    root.mkdir()
    database = generate_tree(root, UNITS)
    config = index_config(in_process=False, jobs=0)
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    assert len(plan.units) == UNITS

    started = time.monotonic()
    index = build_index(plan, config, cache_dir=tmp_path / "cache")
    elapsed = time.monotonic() - started

    assert index.stats.parsed == UNITS
    assert len(index.indexed_files()) == UNITS
    assert elapsed < BUDGET_SECONDS, f"cold index took {elapsed:.1f}s"

    peak_mib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    assert peak_mib < BUDGET_PARENT_MIB, f"parent peaked at {peak_mib:.0f} MiB"

    # The second run is the one a developer actually waits on.
    started = time.monotonic()
    second = build_index(plan, config, cache_dir=tmp_path / "cache")
    warm = time.monotonic() - started
    assert second.stats.reused == UNITS
    assert warm < elapsed, f"warm index ({warm:.1f}s) was not faster than cold ({elapsed:.1f}s)"

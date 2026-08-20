"""Part 03 performance budget: T-03-18. Marked slow, deselected by default."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from caudit.evidence.store import SourceStore

#: Wall-clock budget for 2000 cached region reads, recorded so a regression
#: is visible rather than merely felt.
CACHED_READ_BUDGET_SECONDS = 2.0


@pytest.fixture
def big_tree(tmp_path: Path) -> Path:
    for index in range(2000):
        directory = tmp_path / "src" / f"pkg{index // 100:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"file{index:04d}.c").write_bytes(
            b"".join(f"int value_{line} = {line};\n".encode() for line in range(40))
        )
    return tmp_path


@pytest.mark.slow
def test_cached_region_reads_stay_inside_the_budget(big_tree: Path) -> None:
    store = SourceStore(big_tree, revision="perf", max_file_bytes=1_000_000)
    paths = [f"src/pkg{index // 100:02d}/file{index:04d}.c" for index in range(2000)]

    for path in paths:
        store.make_region(path, 1, 10)
    assert store.stats.disk_reads == 2000

    started = time.perf_counter()
    for path in paths:
        region = store.make_region(path, 5, 15)
        store.read_region(region)
    elapsed = time.perf_counter() - started

    # Second pass must hit the cache, not the disk.
    assert store.stats.disk_reads == 2000
    assert store.stats.cache_hits >= 2000
    assert elapsed < CACHED_READ_BUDGET_SECONDS, (
        f"cached reads took {elapsed:.2f}s, budget is {CACHED_READ_BUDGET_SECONDS}s"
    )

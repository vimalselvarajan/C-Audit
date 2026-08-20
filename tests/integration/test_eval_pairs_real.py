"""T-13-17 (AC-13-1): real pinned pairs, end to end.

Marked `slow`, `needs_clang` and `needs_network`, so it is deselected three
times over by default. It also skips when `benchmarks/pairs/manifest.yaml` is
empty, which it currently is: the corpus is data this repository does not have
yet, and a test that failed for the absence of data would say nothing about the
code.

The moment a pair is pinned, this starts running. That is the point of writing
it now — the harness's contract is fixed before the corpus arrives, so adding a
pair cannot quietly change what "detected" means.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from caudit.eval.pairs import (
    PairSet,
    RepoPair,
    RevisionResult,
    load_manifest,
    run_pairs,
    score_pairs,
)

pytestmark = [pytest.mark.slow, pytest.mark.needs_clang, pytest.mark.needs_network]

MANIFEST = Path("benchmarks/pairs/manifest.yaml")
POLICIES = {"matching": "1", "prompt": "2", "retrieval": "1"}


def _development_pairs() -> list[RepoPair]:
    if not MANIFEST.is_file():
        pytest.skip(f"no pair manifest at {MANIFEST}")
    pairs = load_manifest(MANIFEST).of(PairSet.DEVELOPMENT)
    if len(pairs) < 2:
        pytest.skip(
            f"{MANIFEST} pins {len(pairs)} development pair(s); T-13-17 needs at least two. "
            "See benchmarks/pairs/README.md for how to add them."
        )
    return pairs[:2]


def _checkout(pair: RepoPair, revision: str, into: Path) -> Path | None:
    """Clone and check out one revision. ``None`` when it cannot be done."""
    into.mkdir(parents=True, exist_ok=True)
    for command in (
        ["git", "clone", "--quiet", pair.repo_url, str(into)],
        ["git", "-C", str(into), "checkout", "--quiet", revision],
    ):
        completed = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        if completed.returncode != 0:
            return None
    return into


def _build(pair: RepoPair, root: Path) -> Path | None:
    """Run the recipe. ``None`` when it does not leave a usable database."""
    missing = [tool for tool in pair.build_recipe.requires if shutil.which(tool) is None]
    if missing:
        return None
    for step in pair.build_recipe.steps:
        completed = subprocess.run(
            step,
            shell=True,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=pair.build_recipe.timeout_seconds,
        )
        if completed.returncode != 0:
            return None
    database = root / pair.build_recipe.compile_commands
    return database if database.is_file() else None


def test_two_real_pairs_build_scan_and_produce_outcomes(tmp_path: Path) -> None:
    """T-13-17: both revisions of two pinned pairs, through the real scanner."""
    from rich.console import Console

    from caudit.application.scan import run_scan
    from caudit.config.loader import Config

    pairs = _development_pairs()

    def scan(pair: RepoPair, revision: str) -> RevisionResult:
        started = time.perf_counter()
        root = _checkout(pair, revision, tmp_path / pair.pair_id / revision[:12])
        if root is None:
            return RevisionResult(detected=False, failure=f"could not check out {revision[:12]}")
        database = _build(pair, root)
        if database is None:
            return RevisionResult(
                detected=False,
                failure=f"the build recipe did not produce {pair.build_recipe.compile_commands}",
            )

        result = run_scan(
            root,
            database,
            Config.model_validate({"intake": {"allow_partial_coverage": True}}),
            out=root / ".caudit-out",
            console=Console(quiet=True),
        )
        sections = result.artifacts.sections
        # A detection has to land in a file the fix touched. A finding
        # elsewhere in the repository is not evidence about this pair.
        detected = any(pair.touches(finding.location.path) for finding in sections.confirmed)
        return RevisionResult(
            detected=detected,
            citation_valid=not sections.unresolved,
            tokens=sum(
                record.input_tokens + record.output_tokens
                for record in result.artifacts.manifest.models
            ),
            wall_time_s=time.perf_counter() - started,
        )

    results = run_pairs(pairs, scan, policy_versions=POLICIES)

    # Exclusions are the expected outcome for a recipe that has rotted, and
    # they are reported rather than failing the test — the assertion is that
    # every pair produced *an answer*, not that every build still works.
    assert len(results.outcomes) + len(results.excluded) == len(pairs)
    for excluded in results.excluded:
        print(f"excluded: {excluded.describe()}")

    score = score_pairs(results, PairSet.DEVELOPMENT, policy_versions=POLICIES)
    assert score.scored + score.excluded == len(pairs)
    assert score.policy_versions == POLICIES
    print(score.describe())

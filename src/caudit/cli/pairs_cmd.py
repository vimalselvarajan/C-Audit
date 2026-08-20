"""``caudit pairs`` — run the vulnerable/fixed corpus and record what happened.

The strongest signal part 13 has, because it needs no hand-labelling: scan the
same repository at the revision that had the defect and at the revision that
fixed it. A detection that disappears is real; one that persists is a false
positive with a known answer.

The command is deliberately blunt about the two ways this corpus can lie. A
pair that will not build is **excluded with its reason and printed**, never
dropped — a corpus that quietly loses its hard cases reports a rising score for
a falling tool. And the held-out set is recorded on every access, so a policy
measured against it twice is visible in the ledger rather than only in
somebody's memory.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from caudit.config.loader import Config
from caudit.errors import UsageError
from caudit.eval.pairs import (
    HeldOutLedger,
    PairResults,
    PairSet,
    load_manifest,
    run_pairs,
    score_pairs,
)
from caudit.eval.pairs_runner import RepositoryScanner
from caudit.status import ExitCode

__all__ = ["render_results", "run_pair_suite"]

#: Where the pinned corpus lives, relative to the repository root.
DEFAULT_MANIFEST = Path("benchmarks/pairs/manifest.yaml")


def run_pair_suite(
    *,
    config: Config,
    manifest_path: Path,
    pair_set: PairSet,
    workspace: Path,
    console: Console | None = None,
    ledger_path: Path | None = None,
) -> ExitCode:
    """Scan every pair in one set. Returns the process exit code."""
    out = console or Console(soft_wrap=True, highlight=False)
    manifest = load_manifest(manifest_path)
    pairs = manifest.of(pair_set)

    if not pairs:
        raise UsageError(
            f"{manifest_path} pins no {pair_set} pairs",
            hint=(
                "The corpus is committed empty on purpose: pinning a pair means "
                "cloning it, checking out both revisions and confirming the recipe "
                "builds. See benchmarks/pairs/README.md for the procedure."
            ),
        )

    policy_versions = {
        key: str(value) for key, value in config.policy_versions.model_dump().items()
    }
    caveat: str | None = None
    if pair_set is PairSet.HELD_OUT:
        # One string, so two runs under the same policies are one bucket. The
        # ledger's whole job is counting repeats, and a key that varied with
        # dict ordering would count none.
        stamp = ",".join(f"{key}={value}" for key, value in sorted(policy_versions.items()))
        ledger = HeldOutLedger(path=ledger_path or workspace / "held-out-access.json")
        ledger.record(stamp, reason="caudit pairs --held-out")
        caveat = ledger.caveat(stamp)

    scanner = RepositoryScanner(config=config, workspace=workspace, console=out)
    results = run_pairs(pairs, scanner, policy_versions=policy_versions)
    render_results(results, out)

    if caveat:
        out.print(f"\n{caveat}")

    if not results.outcomes:
        out.print("\nNo pair produced an outcome, so there is no score to report.")
        return ExitCode.ENVIRONMENT

    score = score_pairs(results, pair_set, policy_versions=policy_versions)
    out.print(f"\n{score.describe()}")
    return ExitCode.OK if results.false_positives == 0 else ExitCode.FINDINGS


def render_results(results: PairResults, out: Console) -> None:
    """Outcomes and exclusions, in that order, both always printed."""
    table = Table(title="repository pairs")
    table.add_column("pair")
    table.add_column("vulnerable")
    table.add_column("fixed")
    table.add_column("citations")
    table.add_column("tokens", justify="right")

    for outcome in results.outcomes:
        table.add_row(
            outcome.pair_id,
            "detected" if outcome.detected_in_vulnerable else "missed",
            "still reported" if outcome.detected_in_fixed else "clean",
            "resolved" if outcome.citation_valid else "UNRESOLVED",
            str(outcome.tokens),
        )
    out.print(table)
    out.print(f"\n{results.describe()}")

    if results.excluded:
        out.print("\nExcluded, and counted in neither the numerator nor the denominator:")
        for excluded in results.excluded:
            out.print(f"  {excluded.describe()}")

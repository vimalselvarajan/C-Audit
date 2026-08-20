"""``caudit compare`` — the Milestone 2 measurement, rendered.

Takes two files written by ``caudit eval``: the analyzer-only baseline first,
the adjudicated run second. Prints per-family and macro deltas, what the model
cost, and whether the comparison may be read as a result at all.

The refusals are the point. A comparison across two matching policies, two
prompt versions, two check profiles, or two case sets produces a number that
looks exactly like a result and is not one, so this command names both values
and exits non-zero instead of printing it.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from caudit.errors import UsageError
from caudit.eval.compare import (
    ComparisonError,
    ComparisonReport,
    RunReport,
    compare_runs,
    load_run_report,
)
from caudit.status import ExitCode

__all__ = ["render_comparison", "run_compare", "write_comparison"]


def run_compare(
    baseline: Path,
    adjudicated: Path,
    *,
    console: Console | None = None,
    out: Path | None = None,
) -> ExitCode:
    """Compare two recorded runs. Returns the process exit code.

    Exits ``1`` when a hard gate is failing on either side. The spec makes the
    overall score valid only once the gates pass, so a comparison drawn from a
    run with a failing gate is reported and then flagged, never presented as a
    clean improvement.
    """
    out_console = console or Console(soft_wrap=True, highlight=False)
    left = _load(baseline)
    right = _load(adjudicated)
    try:
        report = compare_runs(left, right)
    except ComparisonError as exc:
        raise UsageError(str(exc)) from exc

    render_comparison(report, baseline, adjudicated, out_console)
    if out is not None:
        written = write_comparison(report, out)
        out_console.print(f"\ncomparison: {written}")
    if not report.valid:
        out_console.print(
            "\nThis comparison is not a result: a hard gate is failing. No overall "
            "score is reported while any gate is failing."
        )
        return ExitCode.FINDINGS
    return ExitCode.OK


def render_comparison(
    report: ComparisonReport, baseline: Path, adjudicated: Path, console: Console
) -> None:
    """Per-family deltas, the overall movement, and the cost of getting it."""
    families = Table(title=f"Per-family delta — {baseline.name} → {adjudicated.name}")
    for column in ("family", "Δ precision", "Δ recall", "Δ F2", "Δ tp", "Δ fp", "Δ fn"):
        families.add_column(column)
    for delta in report.delta.per_family.values():
        families.add_row(
            str(delta.family),
            f"{delta.precision:+.3f}",
            f"{delta.recall:+.3f}",
            f"{delta.f2:+.3f}",
            f"{delta.true_positives:+d}",
            f"{delta.false_positives:+d}",
            f"{delta.false_negatives:+d}",
        )
    console.print(families)

    overall = Table(title="Overall")
    for column in ("metric", "baseline", "adjudicated", "delta"):
        overall.add_column(column)
    for name, left, right, change in (
        ("macro_f2", report.baseline.macro_f2, report.adjudicated.macro_f2, report.delta.macro_f2),
        (
            "fp_per_kloc",
            report.baseline.fp_per_kloc,
            report.adjudicated.fp_per_kloc,
            report.delta.fp_per_kloc,
        ),
        (
            "citation_resolution_rate",
            report.baseline.citation_resolution_rate,
            report.adjudicated.citation_resolution_rate,
            report.delta.citation_resolution_rate,
        ),
        (
            "evidence_validity_rate",
            report.baseline.evidence_validity_rate,
            report.adjudicated.evidence_validity_rate,
            report.delta.evidence_validity_rate,
        ),
    ):
        overall.add_row(name, f"{left:.4f}", f"{right:.4f}", f"{change:+.4f}")
    console.print(overall)

    # Two rows, never one. A change that moved findings from confirmed to
    # needs-review is a large change, and a summed count renders it as zero.
    counts = Table(title="Counts (never added together)")
    for column in ("count", "baseline", "adjudicated", "delta"):
        counts.add_column(column)
    # Labelled with the schema's own field names, so a reader can trace a row
    # back to the model it came from rather than guessing at a prettier name.
    counts.add_row(
        "confirmed_count",
        str(report.baseline.confirmed_count),
        str(report.adjudicated.confirmed_count),
        f"{report.delta.confirmed_count:+d}",
    )
    counts.add_row(
        "review_required_count",
        str(report.baseline.review_required_count),
        str(report.adjudicated.review_required_count),
        f"{report.delta.review_required_count:+d}",
    )
    console.print(counts)

    cost = Table(title="What the adjudicated run cost beyond the baseline", show_header=False)
    cost.add_column("field")
    cost.add_column("value")
    cost.add_row("provider calls", str(report.cost.calls))
    cost.add_row("input tokens", str(report.cost.input_tokens))
    cost.add_row("output tokens", str(report.cost.output_tokens))
    cost.add_row("spend (USD)", f"{report.cost.usd:.4f}")
    cost.add_row("wall time (s)", f"{report.cost.wall_seconds:.1f}")
    console.print(cost)

    if report.policy_versions:
        console.print(
            "\nPolicies both runs share: "
            + ", ".join(f"{key} v{value}" for key, value in report.policy_versions.items())
        )
    for caveat in report.caveats:
        console.print(f"\nCaveat: {caveat}.")
    console.print(f"\n{report.headline()}")


def write_comparison(report: ComparisonReport, path: Path) -> Path:
    """Record the comparison. Sorted keys, so two runs diff cleanly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.loads(report.model_dump_json())
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _load(path: Path) -> RunReport:
    if not path.is_file():
        raise UsageError(
            f"metrics report not found: {path}",
            hint="Produce one with 'caudit eval --suite mini --out <dir>'.",
        )
    try:
        return load_run_report(path)
    except (ValueError, OSError) as exc:
        raise UsageError(f"{path} is not a metrics report written by 'caudit eval': {exc}") from exc

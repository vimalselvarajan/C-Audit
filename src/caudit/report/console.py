"""Console rendering for scan output.

This is an output adapter: it turns completed use-case data into terminal
tables and prose. It neither assembles pipelines nor mutates configuration.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from caudit.analyzers.service import AnalyzerResult
from caudit.index.store import Index, UnitStatus
from caudit.intake.plan import ExclusionReason, ScanPlan
from caudit.llm.service import ConsentDecision, DryRunReport
from caudit.model.finding import Limitation
from caudit.report.service import ReportArtifacts

__all__ = [
    "render_candidates",
    "render_consent",
    "render_index",
    "render_plan",
    "render_prompts",
    "render_report",
    "summarize_candidates",
    "summarize_index",
    "summarize_plan",
    "summarize_report",
]


def summarize_plan(plan: ScanPlan) -> list[tuple[str, str]]:
    """``(label, value)`` rows. Counts stand alone; nothing here is summed."""
    coverage = plan.coverage
    rows = [
        ("repository", str(plan.repo_root)),
        ("revision", plan.revision + (" (dirty)" if plan.dirty else "")),
        ("compile commands", str(plan.compile_commands_path)),
        ("entries in database", str(coverage.tus_in_database)),
        ("translation units selected", str(coverage.tus_selected)),
        (
            "source files covered",
            f"{coverage.source_files_covered}/{coverage.source_files_in_tree} "
            f"({coverage.coverage_ratio:.2f})",
        ),
    ]
    if coverage.duplicate_configurations:
        rows.append(("duplicate configurations resolved", str(coverage.duplicate_configurations)))
    for reason in ExclusionReason:
        count = coverage.tus_excluded.get(reason, 0)
        if count:
            rows.append((f"excluded — {reason.value}", str(count)))
    if plan.overrides:
        rows.append(("overrides in force", ", ".join(plan.overrides)))
    return rows


def render_plan(plan: ScanPlan, console: Console, *, out_dir: Path | None = None) -> None:
    """Print the scan plan and everything it knows it cannot see."""
    table = Table(title="Scan plan", show_header=False)
    table.add_column("field", overflow="fold")
    table.add_column("value", overflow="fold")
    for label, value in summarize_plan(plan):
        table.add_row(label, value)
    console.print(table)

    if not plan.is_reproducible:
        console.print(
            "This run cannot claim reproducibility: "
            + (
                "the tree is not at a pinned revision."
                if plan.revision == "unknown"
                else "the working tree has uncommitted changes."
            )
        )

    if plan.limitations:
        console.print("\nKnown blind spots:")
        _print_limitations(plan.limitations, console)

    if out_dir is not None:
        console.print(f"\nOutput directory: {out_dir}")


def summarize_index(index: Index) -> list[tuple[str, str]]:
    """``(label, value)`` rows for the index. Failures are counted separately."""
    snapshot = index.to_snapshot()
    units = index.units()
    indexed = [unit for unit in units if unit.indexed]
    rows = [
        ("translation units indexed", f"{len(indexed)}/{len(units)}"),
        ("symbols", str(len(snapshot.symbols))),
        ("call edges", str(len(snapshot.calls))),
        ("macro expansions", str(len(snapshot.macros))),
        ("libclang", index.libclang),
    ]
    for status in (UnitStatus.FAILED, UnitStatus.TIMED_OUT, UnitStatus.CRASHED):
        failed = [unit for unit in units if unit.status is status]
        if failed:
            rows.append((f"units {status.value}", ", ".join(str(unit.file) for unit in failed)))
    unresolved = sum(1 for edge in snapshot.calls if edge.callee is None)
    if unresolved:
        rows.append(("indirect calls with an unknown target", str(unresolved)))
    if index.stats.reused:
        rows.append(("units reused from cache", str(index.stats.reused)))
    return rows


def render_index(index: Index, console: Console, *, plan: ScanPlan | None = None) -> None:
    """Print the index and the blind spots the plan did not already name."""
    table = Table(title="Index", show_header=False)
    table.add_column("field", overflow="fold")
    table.add_column("value", overflow="fold")
    for label, value in summarize_index(index):
        table.add_row(label, value)
    console.print(table)

    already = set(plan.limitations) if plan is not None else set()
    fresh = [item for item in index.limitations() if item not in already]
    if fresh:
        console.print("\nWhat the index could not see:")
        _print_limitations(fresh, console)


def summarize_candidates(result: AnalyzerResult) -> list[tuple[str, str]]:
    """``(label, value)`` rows for candidate generation.

    Per-producer counts stay apart. "Three analyzers agree" and "one check
    fired three times" are different findings about a repository, and a single
    candidate count cannot tell them apart.
    """
    rows = [("check profile", f"v{result.profile_version or 'unknown'}")]
    for tool, version in sorted(result.tool_versions.items()):
        rows.append((f"analyzer — {tool}", version))
    rows.append(("candidates", str(len(result.candidates))))

    by_producer: dict[str, int] = {}
    for candidate in result.candidates:
        for entry in candidate.provenance:
            by_producer[entry.tool_name] = by_producer.get(entry.tool_name, 0) + 1
    for tool, count in sorted(by_producer.items()):
        rows.append((f"candidates naming {tool}", str(count)))

    corroborated = sum(1 for c in result.candidates if len(c.provenance) > 1)
    if corroborated:
        rows.append(("candidates more than one analyzer reported", str(corroborated)))
    unmapped = sum(1 for c in result.candidates if not c.suggested_cwe)
    if unmapped:
        rows.append(("candidates with no CWE mapping (routed to review)", str(unmapped)))
    if result.failed_runs:
        rows.append(("analyzer runs that did not complete", str(len(result.failed_runs))))
    return rows


def render_candidates(
    result: AnalyzerResult, console: Console, *, seen: list[Limitation] | None = None
) -> None:
    """Print the candidate summary, and say plainly when nothing looked."""
    table = Table(title="Candidates", show_header=False)
    table.add_column("field", overflow="fold")
    table.add_column("value", overflow="fold")
    for label, value in summarize_candidates(result):
        table.add_row(label, value)
    console.print(table)

    if not result.analyzers_that_ran:
        console.print(
            "\nNo analyzer ran. This is not a clean result: nothing was examined. "
            "Run 'caudit doctor' to see which components are missing."
        )

    already = set(seen or [])
    fresh = [item for item in result.limitations if item not in already]
    if fresh:
        console.print("\nWhat candidate generation could not see:")
        _print_limitations(fresh, console)


def render_prompts(report: DryRunReport, console: Console) -> None:
    """Print what a dry run wrote, and say plainly that nothing was sent."""
    table = Table(title="Prompts (dry run)", show_header=False)
    table.add_column("field", overflow="fold")
    table.add_column("value", overflow="fold")
    table.add_row("prompts written", str(len(report.written)))
    table.add_row("directory", str(report.directory))
    table.add_row("tokens if sent", str(report.total_tokens))
    table.add_row("redactions", report.redactions.describe())
    if report.skipped:
        table.add_row("candidates with no context", str(len(report.skipped)))
    console.print(table)
    console.print(
        "\nNothing was sent. --dry-run-prompts assembles the request bodies and "
        "writes them so they can be read before any of them is transmitted."
    )
    if report.limitations:
        console.print("\nWhat the model would not have been shown:")
        _print_limitations(report.limitations, console)


def render_consent(decision: ConsentDecision, console: Console) -> None:
    """State whether this run may transmit source, and on whose say-so."""
    if decision.granted:
        console.print(f"\nCloud consent: granted — {decision.detail}")
        return
    console.print(
        "\nCloud consent: not given, so no candidate was adjudicated by a model and "
        "this report is the deterministic baseline. Re-run with --consent-cloud to "
        "allow selected source regions to be sent."
    )


def summarize_report(artifacts: ReportArtifacts) -> list[tuple[str, str]]:
    """``(label, value)`` rows for the written report.

    The two finding counts are two rows. They are never added here and there
    is no row that could be mistaken for their sum, which is the same rule the
    Markdown and the SARIF follow.
    """
    sections = artifacts.sections
    rows = [
        ("confirmed findings", str(sections.confirmed_count)),
        ("items needing review", str(sections.review_count)),
    ]
    if sections.unresolved:
        rows.append(("moved to review by the evidence gate", str(len(sections.unresolved))))
    rows.extend(
        [
            ("report", str(artifacts.report_md)),
            ("SARIF", str(artifacts.results_sarif)),
            ("manifest", str(artifacts.run_manifest)),
        ]
    )
    return rows


def render_report(artifacts: ReportArtifacts, console: Console) -> None:
    """Print where the three artifacts went and what is in them."""
    table = Table(title="Report", show_header=False)
    table.add_column("field", overflow="fold")
    table.add_column("value", overflow="fold")
    for label, value in summarize_report(artifacts):
        table.add_row(label, value)
    console.print(table)

    for note in artifacts.sections.notes:
        console.print(f"\n{note}")


def _print_limitations(limitations: list[Limitation], console: Console) -> None:
    for limitation in limitations:
        where = f" ({limitation.affects})" if limitation.affects else ""
        console.print(f"  [{limitation.kind}]{where} {limitation.detail}")

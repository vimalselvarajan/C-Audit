"""``report.md`` — the artifact a person actually reads.

Written to be diffable. No clock reading, no duration, and no absolute path
appears here; all three live in ``run-manifest.json``, so two runs of the same
revision on two machines produce the same file and a reviewer can diff one
report against the last one and see only what changed about the code.

The two sections are separate headings with separate counts, and the summary
says out loud that they are not added. That sentence is not decoration: a
reader who skims a report and takes away one number is the failure mode the
spec's "never merged" rule exists to prevent, and a table that only *omits*
the sum leaves the reader to do the addition themselves.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from caudit.finding_policy.provenance import claim_provenance
from caudit.finding_policy.ranking import explain
from caudit.model.cwe import ALLOWLIST
from caudit.model.evidence import EvidenceItem, EvidenceKind
from caudit.model.finding import Finding, Limitation
from caudit.model.manifest import RunManifest
from caudit.report.manifest import path_redactor, repo_display_name
from caudit.report.sections import ReportSections

__all__ = ["render_markdown"]

#: Said once, prominently, and asserted by test. See the module docstring.
SEPARATION_NOTICE = (
    "Confirmed findings and items needing review are counted separately and are "
    "never added together. A review-required item is a candidate whose evidence "
    "did not fully resolve — it is not a vulnerability, and it is not a "
    "false positive either. It is unfinished work."
)

_NO_FINDINGS = (
    "No confirmed findings. This is a statement about what the analyzers "
    "reported over what they were able to examine — read the coverage and "
    "limitations below before reading it as a clean bill of health."
)


def render_markdown(sections: ReportSections, manifest: RunManifest) -> str:
    """The whole report as Markdown text, ending in exactly one newline."""
    lines: list[str] = []
    _summary(lines, sections, manifest)
    _findings_section(
        lines,
        "Confirmed findings",
        sections.confirmed,
        sections=sections,
        empty=_NO_FINDINGS,
    )
    _findings_section(
        lines,
        "Needs review",
        sections.needs_review,
        sections=sections,
        # "Every candidate's evidence resolved" is a claim about candidates,
        # and a run with none of those has not earned it.
        empty=(
            "Nothing was routed to review: every candidate's evidence resolved."
            if sections.confirmed
            else "Nothing is waiting for review."
        ),
    )
    _coverage_section(lines, sections)
    _excluded_section(lines, sections)
    _limitations_section(lines, sections)
    _provenance_section(lines, manifest)
    # Redaction is the last step, over the finished document: any free text
    # that reached the page from another part goes through it, and no future
    # renderer can be added that forgets to call it.
    return path_redactor(manifest)("\n".join(lines).rstrip("\n") + "\n")


# ------------------------------------------------------------------ summary


def _summary(lines: list[str], sections: ReportSections, manifest: RunManifest) -> None:
    # The partial marker is in the title line, not only in a note further
    # down. A reader who takes one line away from this document takes the
    # first one, and "this report is incomplete" is the fact that changes how
    # every number below it should be read.
    lines.append("# C Audit report" + (" (PARTIAL)" if manifest.partial else ""))
    lines.append("")
    lines.append(
        f"Compiler-aware, evidence-gated analysis of `{repo_display_name(manifest)}` at "
        f"revision `{manifest.revision}`"
        + (" (working tree dirty)" if manifest.revision_dirty else "")
        + "."
    )
    lines.append("")
    rows = [
        ("Confirmed findings", str(sections.confirmed_count)),
        ("Items needing review", str(sections.review_count)),
        ("Coverage", sections.coverage.describe()),
        ("caudit", manifest.caudit_version),
        ("Analyzers", ", ".join(f"{tool.name} {tool.version}" for tool in manifest.tools)),
        ("Models", _models(manifest)),
        (
            "Policies",
            ", ".join(f"{key} v{value}" for key, value in sorted(manifest.policy_versions.items())),
        ),
    ]
    lines.append("| | |")
    lines.append("| --- | --- |")
    for label, value in rows:
        lines.append(f"| {label} | {value} |")
    lines.append("")
    lines.append(f"> {SEPARATION_NOTICE}")
    lines.append("")
    for note in sections.notes:
        lines.append(f"> **{note}**")
        lines.append("")


def _models(manifest: RunManifest) -> str:
    """Which model answered at each tier — ids only, never counts.

    Call counts and token totals are deliberately absent. They are in the
    manifest, because a warm-cache run makes zero calls where the cold run that
    filled the cache made several, and a report that rendered either number
    could not be byte-identical across the two.
    """
    if not manifest.models:
        return "none consulted — this report is the deterministic analyzer baseline"
    return ", ".join(f"{record.tier} {record.model_id}" for record in manifest.models)


# ----------------------------------------------------------------- findings


def _findings_section(
    lines: list[str],
    title: str,
    findings: Sequence[Finding],
    *,
    sections: ReportSections,
    empty: str,
) -> None:
    lines.append(f"## {title} ({len(findings)})")
    lines.append("")
    if not findings:
        lines.append(empty)
        lines.append("")
        return
    for position, finding in enumerate(findings, start=1):
        _finding(lines, position, finding, sections)


def _finding(lines: list[str], position: int, finding: Finding, sections: ReportSections) -> None:
    entry = ALLOWLIST.get(finding.cwe)
    name = entry.name if entry else "outside the CWE allowlist"
    lines.append(f"### {position}. {finding.cwe} — {name}")
    lines.append("")
    where = f" in `{finding.symbol.name}`" if finding.symbol else ""
    lines.append(f"`{finding.location.describe()}`{where}")
    lines.append("")
    lines.append(f"{finding.impact.description}")
    lines.append("")
    lines.append(
        f"- **Impact** {finding.impact.kind} (severity {finding.impact.severity}); "
        f"evidence supports: {finding.impact.evidence_supports}"
    )
    lines.append(
        f"- **Reachability** {finding.reachability} · **Exploitability** "
        f"{finding.exploitability} · **Confidence** {finding.confidence} "
        f"({finding.confidence_reason})"
    )
    unresolved = sections.unresolved.get(finding.finding_id)
    if unresolved:
        lines.append(f"- **Why this needs review** the citation did not resolve — {unresolved}")
    lines.append(f"- **CWE mapping** {finding.cwe_rationale}")
    lines.append("- **Reported by** " + ", ".join(entry.describe() for entry in finding.provenance))
    lines.append(f"- **Why this rank** {explain(finding)}")
    lines.append("")

    # Every cited region names its own producer. The spec's provenance field
    # applies to supporting facts individually, so a reader can see that the
    # diagnostic came from an analyzer and the surrounding function came from
    # the index — rather than one badge saying a model was involved somewhere.
    lines.append("Evidence, and what produced each fact:")
    lines.append("")
    for item in _ordered_evidence(finding.evidence):
        producers = ", ".join(sorted({entry.tool_name for entry in item.provenance}))
        lines.append(f"- `{item.region.describe()}` — {item.kind} · from {producers}")
    lines.append("")
    lines.append(f"**Provenance.** {claim_provenance(finding).describe()}")
    lines.append("")

    if finding.preconditions:
        lines.append("Preconditions:")
        lines.append("")
        for precondition in finding.preconditions:
            lines.append(f"- {precondition}")
        lines.append("")

    lines.append(f"**Remediation.** {finding.remediation.strategy}")
    lines.append("")
    lines.append(f"{finding.remediation.rationale}")
    lines.append("")
    _maintainability(lines, finding)
    if finding.limitations:
        lines.append("Limitations on this finding:")
        lines.append("")
        _limitation_bullets(lines, finding.limitations)
        lines.append("")
    lines.append(
        f"<sub>finding id `{finding.finding_id}` · fingerprint `{finding.fingerprint}`</sub>"
    )
    lines.append("")


def _maintainability(lines: list[str], finding: Finding) -> None:
    """The four dimensions, collapsed when they all say the same thing.

    The analyzer-only baseline fills every one of them with the identical
    "not assessed" sentence, and printing it four times per finding trains a
    reader to skip the paragraph — which is the paragraph that will carry real
    content once part 10 fills it in.
    """
    impact = finding.maintainability_impact
    dimensions = [
        ("Ownership", impact.ownership),
        ("Complexity", impact.complexity),
        ("Coupling", impact.coupling),
        ("Regression risk", impact.regression_risk),
    ]
    distinct = {value for _label, value in dimensions}
    if len(distinct) == 1:
        lines.append(
            f"**Maintainability.** Ownership, complexity, coupling and regression "
            f"risk: {dimensions[0][1]} Effort: {impact.effort}."
        )
    else:
        lines.append("**Maintainability.**")
        lines.append("")
        for label, value in dimensions:
            lines.append(f"- {label}: {value}")
        lines.append(f"- Effort: {impact.effort}")
    lines.append("")


def _ordered_evidence(evidence: Iterable[EvidenceItem]) -> list[EvidenceItem]:
    """Diagnostic and code first, then the flow in the order it was walked.

    The control-flow steps keep their own sequence: renumbering or sorting
    them would change the argument the analyzer made.
    """
    items = list(evidence)
    head = [item for item in items if item.kind is not EvidenceKind.CONTROL_FLOW_STEP]
    flow = [item for item in items if item.kind is EvidenceKind.CONTROL_FLOW_STEP]
    return [*head, *flow]


# ------------------------------------------------------- coverage and gaps


def _coverage_section(lines: list[str], sections: ReportSections) -> None:
    """Always rendered, including when coverage is complete (AC-08-6)."""
    coverage = sections.coverage
    lines.append("## Coverage")
    lines.append("")
    lines.append("| | |")
    lines.append("| --- | --- |")
    lines.append(f"| Entries in the compilation database | {coverage.tus_in_database} |")
    lines.append(f"| Translation units selected | {coverage.tus_selected} |")
    lines.append(
        f"| Source files covered | {coverage.source_files_covered}/"
        f"{coverage.source_files_in_tree} ({coverage.coverage_ratio:.2f}) |"
    )
    if coverage.duplicate_configurations:
        lines.append(f"| Duplicate configurations resolved | {coverage.duplicate_configurations} |")
    for reason, count in sorted(coverage.tus_excluded.items(), key=lambda item: str(item[0])):
        if count:
            lines.append(f"| Excluded — {reason} | {count} |")
    lines.append("")
    lines.append(
        "Complete."
        if coverage.is_complete
        else "Incomplete: the files below the ratio "
        "were never examined, and nothing in this report is a statement about them."
    )
    lines.append("")


def _excluded_section(lines: list[str], sections: ReportSections) -> None:
    lines.append("## Excluded from the scan")
    lines.append("")
    if not sections.excluded:
        lines.append("Nothing was excluded.")
        lines.append("")
        return
    lines.append("| Path | Reason |")
    lines.append("| --- | --- |")
    for path, reason in sections.excluded:
        lines.append(f"| `{path}` | {reason} |")
    lines.append("")


def _limitations_section(lines: list[str], sections: ReportSections) -> None:
    lines.append("## Limitations")
    lines.append("")
    if not sections.limitations:
        lines.append("None recorded. Every unit the plan selected was examined as described.")
        lines.append("")
        return
    lines.append("What this run could not see. A blind spot is not a clean result:")
    lines.append("")
    _limitation_bullets(lines, sections.limitations)
    lines.append("")


def _limitation_bullets(lines: list[str], limitations: Sequence[Limitation]) -> None:
    for limitation in limitations:
        where = f" (`{limitation.affects}`)" if limitation.affects else ""
        lines.append(f"- **{limitation.kind}**{where} {limitation.detail}")


def _provenance_section(lines: list[str], manifest: RunManifest) -> None:
    lines.append("## Reproducing this run")
    lines.append("")
    lines.append(
        "`run-manifest.json` beside this file records the timestamps, the resolved "
        "tool paths, the effective configuration and its hash "
        f"(`{manifest.config_hash[:12]}…`), and the source-region hash of every "
        "finding here. It is the only artifact of the three that contains "
        "machine-specific values, which is what makes the other two comparable "
        "across machines."
    )
    lines.append("")

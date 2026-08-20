"""Deterministic reporting (part 08).

Turns a scan into the three artifacts the spec names — ``report.md``,
``results.sarif``, ``run-manifest.json`` — with no AI anywhere in the path.
When this package works, C Audit is already a useful tool: a build-aware
Clang scanner with reproducible, evidence-hashed reports. That is deliberate.
It is the baseline every later claim about a model is measured against, and
it is what a user who declines cloud adjudication still gets.

Four invariants hold across everything below:

* **Confirmed and needs-review never merge.** Separate lists, separate
  counts, separate SARIF ``kind``. No function here returns their sum.
* **Every rendered finding cites resolvable evidence.** The gate runs in
  :mod:`caudit.report.sections` before anything is rendered, so a confirmed
  finding with an unverified citation is not something this package declines
  to emit — it is something it cannot construct.
* **Coverage is always rendered,** including when it is complete.
* **The manifest is complete or the run fails.** A missing analyzer version,
  policy version, or revision raises rather than serializing a null.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from caudit import __version__
from caudit.analyzers.service import AnalyzerResult
from caudit.config.loader import Config
from caudit.errors import RegionError
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import CitationResolver
from caudit.evidence.store import SourceStore
from caudit.finding_policy.promotion import promote_candidate
from caudit.index.resolver import IndexResolver
from caudit.index.store import Index
from caudit.intake.plan import ScanPlan
from caudit.logging import get_logger
from caudit.model.finding import Finding, Limitation
from caudit.model.manifest import ModelRecord, RunManifest, StageRecord, StageStatus
from caudit.report.manifest import (
    VOLATILE_FIELDS,
    ReportError,
    assemble_manifest,
    config_fingerprint,
    reproducibility_diff,
)
from caudit.report.markdown import render_markdown
from caudit.report.sarif import build_sarif, render_sarif
from caudit.report.sections import ReportSections, build_sections, sort_findings

__all__ = [
    "VOLATILE_FIELDS",
    "ReportArtifacts",
    "ReportError",
    "ReportSections",
    "assemble_manifest",
    "build_report",
    "build_sarif",
    "build_sections",
    "config_fingerprint",
    "promote_candidate",
    "render_markdown",
    "render_sarif",
    "reproducibility_diff",
    "sort_findings",
    "write_report",
]

log = get_logger(__name__)

#: Filenames the spec fixes. Named here so nothing else spells them.
REPORT_MD = "report.md"
RESULTS_SARIF = "results.sarif"
RUN_MANIFEST = "run-manifest.json"

#: Stage statuses that make a report partial. Mirrors the rule
#: :class:`~caudit.model.manifest.RunManifest` applies to its own ``partial``
#: field — a run is partial when a stage failed or degraded, and never merely
#: because a stage was skipped.
_PARTIAL_STATUSES = frozenset({StageStatus.FAILED, StageStatus.DEGRADED})


@dataclass(frozen=True)
class ReportArtifacts:
    """Where the three files landed, and what is in them.

    Carries the sections and manifest as well as the paths so a caller can
    branch on the counts — ``caudit scan``'s exit code depends on
    ``sections.confirmed_count`` — without reading its own output back.
    """

    report_md: Path
    results_sarif: Path
    run_manifest: Path
    sections: ReportSections
    manifest: RunManifest

    @property
    def paths(self) -> tuple[Path, Path, Path]:
        return (self.report_md, self.results_sarif, self.run_manifest)


def write_report(sections: ReportSections, manifest: RunManifest, out_dir: Path) -> ReportArtifacts:
    """Write the three artifacts into ``out_dir`` and return where they went.

    Text is written with an explicit ``\\n`` newline and UTF-8, so a run on a
    machine whose platform newline differs still produces the byte-identical
    file AC-08-7 requires.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    report_md = out_dir / REPORT_MD
    results_sarif = out_dir / RESULTS_SARIF
    run_manifest = out_dir / RUN_MANIFEST

    _write(report_md, render_markdown(sections, manifest))
    _write(results_sarif, render_sarif(sections, manifest))
    _write(run_manifest, manifest.model_dump_json(indent=2) + "\n")

    log.info(
        "wrote %s, %s and %s: %d confirmed, %d needing review",
        REPORT_MD,
        RESULTS_SARIF,
        RUN_MANIFEST,
        sections.confirmed_count,
        sections.review_count,
    )
    return ReportArtifacts(
        report_md=report_md,
        results_sarif=results_sarif,
        run_manifest=run_manifest,
        sections=sections,
        manifest=manifest,
    )


def build_report(
    plan: ScanPlan,
    index: Index,
    analyzers: AnalyzerResult,
    config: Config,
    *,
    started_at: datetime,
    finished_at: datetime | None = None,
    findings: Sequence[Finding] | None = None,
    extra_findings: Sequence[Finding] = (),
    extra_limitations: Sequence[Limitation] = (),
    models: Sequence[ModelRecord] = (),
    stages: Sequence[StageRecord] = (),
    total_cost_usd: float = 0.0,
) -> tuple[ReportSections, RunManifest]:
    """Promote candidates, run the evidence gate, and assemble the manifest.

    The resolver is the index-backed one from part 06 whenever the index has
    anything in it, so a symbol claim is checked against where the index
    places the symbol rather than against whether the name appears in the
    bytes — a comment naming a function is not evidence about that function.

    ``findings`` is what part 12's pipeline already made of the candidates —
    adjudicated, gated, and ranked. Passing ``None`` promotes the analyzer
    candidates directly, which is the Milestone 1 baseline and stays the
    behaviour of a run without consent. The two paths share everything below
    this line, so the baseline a model-assisted run is compared against is
    rendered by the same code that renders the run.
    """
    store = SourceStore(
        plan.repo_root,
        revision=plan.revision,
        max_file_bytes=config.token_budget.max_file_bytes,
        exclude_globs=config.exclude_globs,
    )
    resolver = _resolver(store, index)
    if findings is None:
        findings = [promote_candidate(candidate, store=store) for candidate in analyzers.candidates]
    reported = [*findings, *extra_findings]

    sections = build_sections(
        reported,
        resolver=resolver,
        coverage=plan.coverage,
        limitations=_limitations(plan, index, analyzers, extra_limitations),
        excluded=plan.excluded,
        notes=_notes(plan, analyzers, stages),
    )
    units = index.units()
    parsed = sum(1 for unit in units if unit.indexed)
    manifest = assemble_manifest(
        plan=plan,
        sections=sections,
        config=config,
        caudit_version=__version__,
        started_at=started_at,
        finished_at=finished_at or datetime.now(UTC),
        analyzer_versions=_versions(index, analyzers),
        analyzers_that_ran=_tools_that_ran(analyzers),
        policy_versions=_policy_versions(config, analyzers),
        units_parsed=parsed,
        units_failed=len(units) - parsed,
        lines_of_code=_lines_of_code(plan, store),
        models=models,
        stages=stages,
        total_cost_usd=total_cost_usd,
    )
    return sections, manifest


# ---------------------------------------------------------------- internals


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def _resolver(store: SourceStore, index: Index) -> CitationResolver:
    bundle = EvidenceBundle(store)
    if index.indexed_files():
        return IndexResolver(store, bundle, index)
    return CitationResolver(store, bundle)


def _versions(index: Index, analyzers: AnalyzerResult) -> dict[str, str]:
    versions = dict(analyzers.tool_versions)
    versions["libclang"] = index.libclang
    return versions


def _tools_that_ran(analyzers: AnalyzerResult) -> list[str]:
    """Every tool whose output is in this run, analyzers and the indexer alike.

    libclang is in the list because the index it produced decides which symbol
    claims resolve. A manifest that recorded the analyzers but not the parser
    would not describe a reproducible run.
    """
    return sorted({*analyzers.analyzers_that_ran, "libclang"})


def _policy_versions(config: Config, analyzers: AnalyzerResult) -> dict[str, str]:
    policies = config.policy_versions.model_dump()
    policies["profile"] = analyzers.profile_version or ""
    return {key: str(value) for key, value in policies.items()}


def _limitations(
    plan: ScanPlan,
    index: Index,
    analyzers: AnalyzerResult,
    extra: Sequence[Limitation] = (),
) -> list[Limitation]:
    """Every blind spot the run knows about, deduplicated, in a stable order.

    Order is intake, then index, then analyzers, then anything a later stage
    added — the order the run happened in, which is the order a reader
    diagnoses it in. Two components naming the same gap produce one line, not
    two.
    """
    seen: set[tuple[str, str, str]] = set()
    ordered: list[Limitation] = []
    for limitation in [*plan.limitations, *index.limitations(), *analyzers.limitations, *extra]:
        key = (str(limitation.kind), limitation.affects or "", limitation.detail)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(limitation)
    return ordered


def _notes(
    plan: ScanPlan, analyzers: AnalyzerResult, stages: Sequence[StageRecord] = ()
) -> list[str]:
    """Run-level statements a reader has to see before believing a count.

    The partial notice comes first and names the stages, because every other
    line below it is a statement about a run that did not finish as described.
    """
    notes: list[str] = []
    broken = [record for record in stages if record.status in _PARTIAL_STATUSES]
    if broken:
        notes.append(
            "This report is PARTIAL. "
            + "; ".join(f"the {record.stage} stage {record.status}" for record in broken)
            + ". What those stages would have contributed is missing, not absent — read "
            "the limitations below before treating any count here as complete."
        )
    if not analyzers.analyzers_that_ran:
        notes.append(
            "No analyzer ran. This report is not a clean result: nothing was examined. "
            "Run 'caudit doctor' to see which components are missing."
        )
    if not plan.is_reproducible:
        notes.append(
            "This run cannot claim reproducibility: "
            + (
                "the tree is not at a pinned revision."
                if plan.revision == "unknown"
                else "the working tree has uncommitted changes."
            )
        )
    if plan.overrides:
        notes.append("Overrides in force: " + ", ".join(plan.overrides) + ".")
    return notes


def _lines_of_code(plan: ScanPlan, store: SourceStore) -> int:
    """Physical lines in the selected units. Zero when a file cannot be read."""
    total = 0
    for unit in plan.units:
        try:
            total += store.line_count(unit.file)
        except (RegionError, ValueError, OSError):
            continue
    return total

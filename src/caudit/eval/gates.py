"""The spec's hard gates. A failing gate fails the run.

The overall score is 50% security and 50% maintainability, but that average
is only meaningful once these pass. A gain in maintainability must not be
able to compensate for invented evidence or very poor recall, so the gates
are evaluated first and an overall score is refused outright while any of
them is failing.

Four gates, straight from the spec:

1. at least 95% of cited locations and symbols resolve exactly;
2. zero fabricated files, functions, analyzer names, or snippets;
3. confirmed findings and review-required candidates are never merged;
4. security recall and precision floors are established against the non-AI
   static-analysis baseline before an overall score is reported.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from caudit.config.loader import Config
from caudit.eval.metrics import SUMMABLE_COUNT_FIELDS, Metrics
from caudit.evidence.resolver import Resolution, ResolutionStatus
from caudit.model.finding import Finding

__all__ = [
    "CITATION_RESOLUTION_THRESHOLD",
    "KNOWN_PRODUCER_TOOLS",
    "FabricationKind",
    "FabricationSignal",
    "GateResult",
    "evaluate_gates",
    "fabrication_signals",
    "gates_passed",
    "model_producer_tools",
    "overall_score",
]

#: The spec's threshold, inclusive: exactly 95% passes.
CITATION_RESOLUTION_THRESHOLD = 0.95

#: Analyzer names a finding may claim. An unrecognised name is a fabricated
#: analyzer, which the spec lists alongside fabricated files and functions.
#:
#: This is the *static* floor: the deterministic components, whose names are
#: compiled in. It is deliberately not the whole allowlist. Model identifiers
#: are configuration — three tiers, any string — so they are threaded in per
#: run by :func:`model_producer_tools` rather than guessed here. ``gemini``
#: stays because a fixture may use the bare family name, but no real run
#: writes it: provenance records the model *id*, which is why a hardcoded
#: ``gemini`` failed every adjudicated run with a fabrication signal.
KNOWN_PRODUCER_TOOLS: frozenset[str] = frozenset(
    {
        "clang",
        "clang++",
        "clang-tidy",
        "clang-static-analyzer",
        "scan-build",
        # The index is built through the libclang wheel and records itself
        # under that name on the evidence it contributes.
        "libclang",
        "caudit-index",
        "caudit-retrieval",
        "caudit-fixture",
        "gemini",
    }
)


def model_producer_tools(config: Config) -> frozenset[str]:
    """The model identifiers this configuration is allowed to credit.

    Read from configuration rather than hardcoded, for the reason model ids
    live in configuration at all: they change, and a run must be able to name
    the model that answered. A model cannot write this field — caudit fills it
    in from the same config — so widening the allowlist to cover it does not
    weaken the gate against anything a model could do. What the gate still
    catches is a finding crediting a model that this run was not configured to
    call.
    """
    return frozenset(str(value) for value in config.models.model_dump().values())


class FabricationKind(StrEnum):
    """What was invented."""

    FILE = "fabricated_file"
    SYMBOL = "fabricated_symbol"
    EVIDENCE_ID = "fabricated_evidence_id"
    ANALYZER = "fabricated_analyzer"
    SNIPPET = "fabricated_snippet"
    OUTSIDE_REPO = "outside_repository"


#: Resolution failures that mean something was invented, as opposed to
#: something that merely could not be checked.
_FABRICATION_STATUSES: Mapping[ResolutionStatus, FabricationKind] = {
    ResolutionStatus.MISSING_FILE: FabricationKind.FILE,
    ResolutionStatus.UNKNOWN_EVIDENCE_ID: FabricationKind.EVIDENCE_ID,
    ResolutionStatus.SYMBOL_NOT_FOUND: FabricationKind.SYMBOL,
    ResolutionStatus.OUTSIDE_REPO_ROOT: FabricationKind.OUTSIDE_REPO,
    ResolutionStatus.HASH_MISMATCH: FabricationKind.SNIPPET,
    ResolutionStatus.LINE_OUT_OF_RANGE: FabricationKind.FILE,
}


@dataclass(frozen=True)
class FabricationSignal:
    """One piece of evidence that something was invented."""

    kind: FabricationKind
    subject: str
    detail: str

    def describe(self) -> str:
        return f"{self.kind}: {self.subject} — {self.detail}"


def fabrication_signals(
    findings: Sequence[Finding],
    resolutions: Sequence[Resolution],
    known_tools: Iterable[str] = KNOWN_PRODUCER_TOOLS,
) -> list[FabricationSignal]:
    """Every fabrication the deterministic checks can see.

    Deduplicated by ``(kind, subject)``: one invented file cited from four
    places is one fabrication, not four. The gate's observed value is a count
    of things invented, not of times they were mentioned.
    """
    signals: list[FabricationSignal] = []
    for resolution in resolutions:
        kind = _FABRICATION_STATUSES.get(resolution.status)
        if kind is None:
            continue
        subject = (
            resolution.citation.path
            or resolution.citation.evidence_id
            or resolution.citation.describe()
        )
        signals.append(FabricationSignal(kind=kind, subject=subject, detail=resolution.detail))

    allowed = {name.lower() for name in known_tools}
    for finding in findings:
        provenances = list(finding.provenance)
        provenances.extend(p for item in finding.evidence for p in item.provenance)
        for provenance in provenances:
            if provenance.tool_name.lower() not in allowed:
                signals.append(
                    FabricationSignal(
                        kind=FabricationKind.ANALYZER,
                        subject=provenance.tool_name,
                        detail=(
                            f"finding {finding.finding_id} credits an analyzer that did "
                            "not run in this configuration"
                        ),
                    )
                )

    seen: dict[tuple[FabricationKind, str], FabricationSignal] = {}
    for signal in signals:
        seen.setdefault((signal.kind, signal.subject), signal)
    return list(seen.values())


class GateResult(BaseModel):
    """One gate's verdict, with the number that produced it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    passed: bool
    observed: float | int
    threshold: float | int
    detail: str = Field(default="")


def evaluate_gates(
    metrics: Metrics,
    findings: Sequence[Finding],
    resolutions: Sequence[Resolution],
    *,
    baseline: Metrics | None = None,
    is_baseline_run: bool = False,
    known_tools: Iterable[str] = KNOWN_PRODUCER_TOOLS,
) -> list[GateResult]:
    """Apply every hard gate. Order is stable so output is diffable."""
    results: list[GateResult] = []

    # 1. Citation resolution.
    rate = metrics.citation_resolution_rate
    unresolved = [r for r in resolutions if not r.ok]
    results.append(
        GateResult(
            name="citation_resolution",
            passed=rate >= CITATION_RESOLUTION_THRESHOLD,
            observed=round(rate, 6),
            threshold=CITATION_RESOLUTION_THRESHOLD,
            detail=(
                f"{len(resolutions) - len(unresolved)}/{len(resolutions)} citations "
                f"resolved at revision scan time"
                + ("; first failure: " + unresolved[0].detail if unresolved else "")
            ),
        )
    )

    # 2. Zero fabrication.
    signals = fabrication_signals(findings, resolutions, known_tools)
    results.append(
        GateResult(
            name="zero_fabrication",
            passed=not signals,
            observed=len(signals),
            threshold=0,
            detail=(
                "no fabricated files, functions, analyzer names, or snippets"
                if not signals
                else "; ".join(signal.describe() for signal in signals[:5])
            ),
        )
    )

    # 3. Counts kept separate. Structural, not statistical: the check is that
    #    the metrics object cannot express a merged count.
    merged_fields = [
        name
        for name in type(metrics).model_fields
        if name not in SUMMABLE_COUNT_FIELDS
        and any(token in name for token in ("total_findings", "all_findings", "findings_total"))
    ]
    results.append(
        GateResult(
            name="counts_separate",
            passed=not merged_fields,
            observed=len(merged_fields),
            threshold=0,
            detail=(
                f"confirmed={metrics.confirmed_count}, "
                f"review_required={metrics.review_required_count}, reported separately"
                if not merged_fields
                else f"metrics exposes a merged count field: {merged_fields}"
            ),
        )
    )

    # 4. Baseline floors must exist before an overall score is reported. A
    #    baseline run is what establishes them, so it satisfies the gate by
    #    definition rather than failing for lacking a predecessor.
    if baseline is None and is_baseline_run:
        results.append(
            GateResult(
                name="baseline_floor",
                passed=True,
                observed=round(metrics.macro_f2, 6),
                threshold=0,
                detail=(
                    f"analyzer-only run; this establishes the floor at macro-F2 "
                    f"{metrics.macro_f2:.4f}. No AI was in the pipeline, so there is "
                    "nothing to compare against yet."
                ),
            )
        )
    elif baseline is None:
        results.append(
            GateResult(
                name="baseline_floor",
                passed=False,
                observed=0,
                threshold=1,
                detail=(
                    "no non-AI baseline supplied; security recall and precision floors "
                    "must be established against the analyzers alone before an overall "
                    "score is reported"
                ),
            )
        )
    else:
        metrics.assert_comparable(baseline)
        floor = baseline.macro_f2
        results.append(
            GateResult(
                name="baseline_floor",
                passed=metrics.macro_f2 >= floor,
                observed=round(metrics.macro_f2, 6),
                threshold=round(floor, 6),
                detail=(
                    f"macro-F2 {metrics.macro_f2:.4f} against the analyzer-only "
                    f"baseline {floor:.4f}"
                ),
            )
        )

    return results


def gates_passed(results: Sequence[GateResult]) -> bool:
    return all(result.passed for result in results)


def overall_score(
    security_score: float, maintainability_score: float, results: Sequence[GateResult]
) -> float:
    """0.5·security + 0.5·maintainability — refused while a gate is failing."""
    failing = [r.name for r in results if not r.passed]
    if failing:
        raise ValueError(
            "refusing to report an overall score while hard gates are failing: "
            + ", ".join(failing)
        )
    return 0.5 * security_score + 0.5 * maintainability_score

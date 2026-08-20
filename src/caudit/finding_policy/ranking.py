"""What deserves attention first, and why.

Ranking is the last place an unverified judgement could reach the top of a
report, so every input here is a value the pipeline *derived* rather than one a
model offered. That is the whole design:

* **Severity comes from the committed CWE family table**, not from
  ``impact.severity``. A model chooses ``impact.kind`` from a fixed enum and
  writes prose; it does not get to declare its own finding critical. The impact
  kind can only *lower* the family's severity, never raise it — the same
  direction part 11's downgrades run in.
* **Confidence is part 11's**, computed from whether the citations resolved.
  :attr:`~caudit.model.adjudication.Adjudication.confidence_self_report` is not
  read here and is not reachable from a :class:`~caudit.model.finding.Finding`.
* **Reachability is the gate's capped value**, so a ``demonstrated`` claim with
  no control-flow evidence has already become ``argued`` before it is ranked.
* **Agreement counts distinct external analyzers.** ``index`` and ``llm``
  provenance are components of this tool; counting them would let a finding
  corroborate itself.
* **Effort is measured from the evidence span**, because that is checkable.

Review-required items are ranked in their own list. There is no code path that
puts one in the confirmed ranking, because
:class:`~caudit.report.sections.ReportSections` will not hold one there —
ranking is applied to each list separately after the split, never before it.

Each finding renders a one-line explanation built from the same five inputs, so
a reader can audit the position rather than trust it. The explanation and the
sort key are generated from one :class:`RankInputs` object for exactly that
reason: an explanation that could disagree with the order would be worse than
none.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.model.cwe import WeaknessFamily, family_of
from caudit.model.evidence import ANALYZER_PRODUCERS
from caudit.model.finding import (
    Confidence,
    Finding,
    ImpactKind,
    Reachability,
    Severity,
)

__all__ = [
    "EffortEstimate",
    "RankInputs",
    "effort_of",
    "explain",
    "provenance_agreement",
    "rank_findings",
    "rank_inputs",
    "rank_key",
    "severity_of",
]


class EffortEstimate(StrEnum):
    """How far a fix has to reach, from the span of the cited evidence.

    Ordered cheapest first. It is a scope estimate, not a time estimate: a
    one-line fix inside one function is ``local`` whether it takes five minutes
    or an afternoon, and the ranking only ever uses it to break a tie between
    findings of equal weight.
    """

    LOCAL = "local"
    FUNCTION = "function"
    CROSS_MODULE = "cross_module"


#: Family severity, before the impact kind is allowed to lower it. The same
#: numbers part 08's promotion uses, kept in one table so the analyzer-only
#: baseline and an adjudicated run rank a given weakness identically — if they
#: did not, the M2 comparison would be measuring two different orderings.
_SEVERITY_BY_FAMILY: Final[Mapping[WeaknessFamily, Severity]] = {
    WeaknessFamily.OUT_OF_BOUNDS: Severity.HIGH,
    WeaknessFamily.MEMORY_LIFETIME: Severity.HIGH,
    WeaknessFamily.INJECTION: Severity.HIGH,
    WeaknessFamily.NULL_UNINITIALIZED: Severity.MEDIUM,
    WeaknessFamily.INTEGER: Severity.MEDIUM,
    WeaknessFamily.RESOURCE_LEAK: Severity.MEDIUM,
}

#: The most a given impact kind can be worth, whatever family it is attached
#: to. Applied as a ceiling and never as a floor: a model that classifies an
#: out-of-bounds write as ``incorrect_result`` gets a quieter finding, and one
#: that classifies a resource leak as ``code_execution`` does not get a louder
#: one. Only ``code_execution`` reaches ``critical``, and no family table entry
#: does, so critical is a rank a finding earns from what it can do rather than
#: from what it is called.
_CEILING_BY_IMPACT: Final[Mapping[ImpactKind, Severity]] = {
    ImpactKind.CODE_EXECUTION: Severity.CRITICAL,
    ImpactKind.MEMORY_CORRUPTION: Severity.HIGH,
    ImpactKind.INFORMATION_DISCLOSURE: Severity.HIGH,
    ImpactKind.DENIAL_OF_SERVICE: Severity.MEDIUM,
    ImpactKind.RESOURCE_EXHAUSTION: Severity.MEDIUM,
    ImpactKind.UNDEFINED_BEHAVIOR: Severity.MEDIUM,
    ImpactKind.INCORRECT_RESULT: Severity.LOW,
}

#: Most severe first — the order a report is read in, not the order
#: :class:`~caudit.model.finding.Severity` is declared in.
_SEVERITY_RANK: Final[Mapping[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

#: Strongest first. ``review_required`` is present for completeness only: it
#: never appears in the confirmed ranking, and within the needs-review list
#: every entry carries it, so it never decides an ordering either.
_CONFIDENCE_RANK: Final[Mapping[Confidence, int]] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.REVIEW_REQUIRED: 2,
}

#: Demonstrated above argued above unknown.
_REACHABILITY_RANK: Final[Mapping[Reachability, int]] = {
    Reachability.DEMONSTRATED: 0,
    Reachability.ARGUED: 1,
    Reachability.UNKNOWN: 2,
}

#: Cheapest first, so a cheap high-value fix surfaces above an expensive one of
#: equal weight.
_EFFORT_RANK: Final[Mapping[EffortEstimate, int]] = {
    EffortEstimate.LOCAL: 0,
    EffortEstimate.FUNCTION: 1,
    EffortEstimate.CROSS_MODULE: 2,
}


class RankInputs(BaseModel):
    """The five verified values a finding's position is computed from.

    Built once per finding and used for both the sort key and the explanation,
    so the two cannot disagree about why something is where it is.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Severity
    confidence: Confidence
    reachability: Reachability
    effort: EffortEstimate
    #: Distinct external analyzers that reported this. One is the normal case;
    #: two or more is independent corroboration.
    provenance_agreement: int = Field(ge=0)

    def key(self) -> tuple[int, int, int, int, int]:
        """The ordering, without the tie-break. Lower sorts first."""
        return (
            _SEVERITY_RANK[self.severity],
            _CONFIDENCE_RANK[self.confidence],
            _REACHABILITY_RANK[self.reachability],
            # Negated: more agreement sorts first, and every other component
            # here is already "smaller is stronger".
            -self.provenance_agreement,
            _EFFORT_RANK[self.effort],
        )


def severity_of(finding: Finding) -> Severity:
    """Severity from the CWE family, capped by what the impact kind can do.

    Never reads ``finding.impact.severity``. That field is the model's own
    grading in an adjudicated run, and a ranking that consulted it would let a
    proposal argue for its own position at the top of the report.
    """
    family = family_of(finding.cwe)
    base = _SEVERITY_BY_FAMILY.get(family, Severity.LOW) if family is not None else Severity.LOW
    ceiling = _CEILING_BY_IMPACT[finding.impact.kind]
    return base if _SEVERITY_RANK[base] >= _SEVERITY_RANK[ceiling] else ceiling


def provenance_agreement(finding: Finding) -> int:
    """How many distinct external analyzers reported this finding.

    Only :data:`~caudit.model.evidence.ANALYZER_PRODUCERS` count. An index
    entry says where a symbol is and a model entry says which tier answered;
    neither is a second opinion about whether the defect is real, and counting
    them would let one analyzer plus one model outrank two analyzers.
    """
    return len(
        {entry.tool_name for entry in finding.provenance if entry.producer in ANALYZER_PRODUCERS}
    )


def effort_of(finding: Finding) -> EffortEstimate:
    """How far the fix reaches, measured from the span of the cited evidence.

    A proxy for remediation scope, and deliberately a checkable one: every
    region counted here was resolved against the scanned revision, so this is
    not an opinion about how hard the work is. Evidence in more than one file
    is ``cross_module``; more than one region in one file is ``function``; a
    single region is ``local``.
    """
    regions = {
        (str(item.region.path), item.region.start_line, item.region.end_line)
        for item in finding.evidence
    }
    regions.add(
        (
            str(finding.location.path),
            finding.location.start_line,
            finding.location.end_line,
        )
    )
    paths: set[str] = {path for path, _start, _end in regions}
    if len(paths) > 1:
        return EffortEstimate.CROSS_MODULE
    if len(regions) > 1:
        return EffortEstimate.FUNCTION
    return EffortEstimate.LOCAL


def rank_inputs(finding: Finding) -> RankInputs:
    """Everything the ordering depends on, derived from verified values."""
    return RankInputs(
        severity=severity_of(finding),
        confidence=finding.confidence,
        reachability=finding.reachability,
        effort=effort_of(finding),
        provenance_agreement=provenance_agreement(finding),
    )


def rank_key(finding: Finding) -> tuple[int, int, int, int, int, str]:
    """Total order over findings. Ties break on ``finding_id``.

    Total because ``finding_id`` is unique within a report: two findings can
    compare equal on all five inputs, and never on the sixth. Shuffling the
    input therefore cannot change the output, which is what makes a diff
    between two runs a diff about the code.
    """
    return (*rank_inputs(finding).key(), finding.finding_id)


def rank_findings(findings: Iterable[Finding]) -> list[Finding]:
    """One section's findings, most deserving of attention first."""
    return sorted(findings, key=rank_key)


def explain(finding: Finding, inputs: RankInputs | None = None) -> str:
    """One line saying why this finding sits where it does.

    Built from the same :class:`RankInputs` the key is built from, and it names
    every component in key order — so a reader comparing two adjacent findings
    can see which term separated them rather than inferring it.
    """
    values = inputs or rank_inputs(finding)
    agreement = (
        "reported by one analyzer"
        if values.provenance_agreement == 1
        else f"{values.provenance_agreement} independent analyzers agree"
        if values.provenance_agreement > 1
        else "no analyzer named itself"
    )
    return (
        f"severity {values.severity} (from the {_family_label(finding)} family, "
        f"capped at what {finding.impact.kind} can do) · "
        f"confidence {values.confidence} · reachability {values.reachability} · "
        f"{agreement} · {values.effort} fix"
    )


def _family_label(finding: Finding) -> str:
    family = family_of(finding.cwe)
    return str(family) if family is not None else "unmapped"

"""Tier-routing policy for model adjudication."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict

from caudit.config.schema import LLMConfig
from caudit.model.adjudication import Adjudication, Tier, TriageDisposition, TriageResult
from caudit.model.candidate import Candidate
from caudit.model.finding import Severity
from caudit.retrieval.context import EvidenceContext

__all__ = [
    "DEFAULT_ROUTING",
    "RoutingPolicy",
    "escalation_input",
    "route",
]


class RoutingPolicy(BaseModel):
    """When the expensive tier is allowed to be asked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_escalation: bool = True
    #: "High impact" as a threshold rather than a feeling.
    escalate_at: Severity = Severity.HIGH

    @classmethod
    def from_config(cls, config: LLMConfig) -> RoutingPolicy:
        return cls(allow_escalation=config.allow_escalation)


DEFAULT_ROUTING = RoutingPolicy()

_SEVERITY_RANK: Mapping[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def route(
    candidate: Candidate,
    context: EvidenceContext,
    triage: TriageResult,
    *,
    policy: RoutingPolicy = DEFAULT_ROUTING,
) -> Tier:
    """Which tier answers next.

    The rule the plan states, as a table over ``(ambiguity x impact)``:

    ==========  =========  ===============  ==============
    disposition ambiguous  impact           tier
    ==========  =========  ===============  ==============
    dismiss     any        any              ``triage``
    adjudicate  false      any              ``adjudication``
    adjudicate  true       below threshold  ``adjudication``
    adjudicate  true       at or above      ``escalation``
    ==========  =========  ===============  ==============

    Three clauses narrow the last row, and each one describes a case where the
    expensive tier cannot change the outcome:

    * escalation is disabled by configuration;
    * the context holds no code — a stronger model reading the same nothing
      returns the same nothing, at a higher price;
    * no suggested CWE is in scope, so the candidate is review-required
      whatever comes back (part 11 routes it to ``out_of_scope_family``).
    """
    if triage.disposition is TriageDisposition.DISMISS:
        return Tier.TRIAGE
    if not triage.ambiguous:
        return Tier.ADJUDICATION
    if _SEVERITY_RANK[triage.impact.severity] < _SEVERITY_RANK[policy.escalate_at]:
        return Tier.ADJUDICATION
    if not policy.allow_escalation or not context.primary_units or candidate.out_of_scope:
        return Tier.ADJUDICATION
    return Tier.ESCALATION


def escalation_input(adjudication: Adjudication) -> TriageResult:
    """The adjudication tier's answer, expressed for the routing table.

    Escalation is decided by the same table that chose the adjudication tier,
    reading the adjudication's own verdict and impact. One table, two callers,
    no second rule to drift.
    """
    return TriageResult.from_verdict(
        adjudication.verdict,
        adjudication.impact,
        rationale=(
            adjudication.cwe_rationale.strip()
            or f"the adjudication tier returned {adjudication.verdict}"
        ),
    )

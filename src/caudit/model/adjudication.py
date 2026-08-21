"""What a model is allowed to say, as types.

An :class:`Adjudication` is a **proposal**. It is not a finding, it is not
evidence, and nothing here decides anything: part 11 resolves every citation
against the scanned revision and either accepts the proposal or routes the
candidate to review. That separation is the whole product claim, so the
vocabulary keeps it visible — this module never imports
:class:`~caudit.model.finding.Finding`, and no field of an ``Adjudication`` is
copied into one without passing the gate.

The validators below are deliberately narrow. They reject objects that are
*incoherent* — a confirmation citing nothing, a confirmation of no weakness —
and nothing else. Whether the evidence actually supports the claim is a
question about the repository, not about the object, and answering it here
would let a schema retry quietly stand in for a verification failure.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.model.cwe import CweId
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Impact,
    MaintainabilityImpact,
    Reachability,
    Remediation,
)

__all__ = [
    "Adjudication",
    "CallEdgeClaim",
    "ProviderResponse",
    "Quotation",
    "Tier",
    "TriageDisposition",
    "TriageResult",
    "Usage",
    "Verdict",
]


class Tier(StrEnum):
    """Capability tiers from the spec. The model *id* for each is configuration."""

    #: Cheap: classify, dedup, plan queries.
    TRIAGE = "triage"
    #: Repository reasoning and evidence synthesis.
    ADJUDICATION = "adjudication"
    #: A second opinion, for ambiguous and high-impact candidates only.
    ESCALATION = "escalation"


class Verdict(StrEnum):
    """The model's proposed disposition. Never the final state."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REVIEW_REQUIRED = "review_required"


class TriageDisposition(StrEnum):
    """What the cheap tier thinks should happen next."""

    #: Not a defect worth spending the adjudication tier on.
    DISMISS = "dismiss"
    #: Worth a full adjudication.
    ADJUDICATE = "adjudicate"


class TriageResult(BaseModel):
    """The triage tier's answer, and the input to :func:`~caudit.llm.provider.route`.

    ``ambiguous`` and ``impact`` are separate from ``disposition`` because the
    routing truth table is over those two alone. Reusing this type for the
    adjudication tier's answer — see :meth:`from_verdict` — is what keeps the
    escalation rule a single table rather than two rules that can drift.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: TriageDisposition
    #: The tier could not tell. Half of the escalation truth table.
    ambiguous: bool
    #: Worst case if the candidate is real. The other half of the table.
    impact: Impact
    rationale: str = Field(min_length=1)

    @classmethod
    def from_verdict(cls, verdict: Verdict, impact: Impact, rationale: str) -> TriageResult:
        """The same table applied to an adjudication that has already run.

        A ``review_required`` verdict *is* the adjudication tier saying it
        could not tell, so it maps onto ``ambiguous`` and escalation follows
        from the one truth table instead of from a second rule beside it.
        """
        return cls(
            disposition=(
                TriageDisposition.DISMISS
                if verdict is Verdict.REJECTED
                else TriageDisposition.ADJUDICATE
            ),
            ambiguous=verdict is Verdict.REVIEW_REQUIRED,
            impact=impact,
            rationale=rationale,
        )


class Quotation(BaseModel):
    """Text the model says appears at a region it was issued.

    The only claim *about source* that a machine can settle exactly: the bytes
    either match or they do not. Prose describing code is not checkable and is
    never treated as though it were, which is why quoting is a field rather
    than something read back out of a rationale.

    Part 11 compares this against the captured bytes with no normalisation at
    all — not whitespace, not line endings. A quotation that has been tidied up
    is a quotation of something the compiler never saw.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1)
    text: str = Field(min_length=1)


class CallEdgeClaim(BaseModel):
    """ "``caller`` calls ``callee``" — checked against the index's call graph.

    Separate from :attr:`Adjudication.cited_evidence_ids` because an edge is
    not a region: two functions can both be cited, both resolve, and have no
    call between them. That is precisely the claim a reachability argument
    rests on and the one a region citation cannot express.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    caller: str = Field(min_length=1)
    callee: str = Field(min_length=1)


class Adjudication(BaseModel):
    """The model's proposal. Not a :class:`Finding` until part 11 accepts it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: Verdict
    #: Ids issued by this candidate's bundle, and nothing else. An id the
    #: bundle never handed out is rejected before any file is opened.
    cited_evidence_ids: list[str]
    #: Required and nullable rather than optional: a model that has no weakness
    #: to name has to say ``null``, which is a claim, where an omitted field is
    #: only a silence.
    cwe: CweId | None
    cwe_rationale: str
    #: What has to be true at runtime for the defect to fire.
    trigger_conditions: list[str]
    impact: Impact
    reachability: Reachability
    exploitability: Exploitability
    remediation: Remediation
    maintainability_impact: MaintainabilityImpact
    #: Required, never defaulted. An empty list is the model stating that it
    #: found none; an absent field is a schema violation, because "I did not
    #: mention any" and "there are none" are different claims and only one of
    #: them is checkable (AC-10-14).
    unresolved_assumptions: list[str]
    #: Exact text the model says is at a region it cited. Every entry is
    #: checked byte-for-byte in part 11.
    #:
    #: Defaulted where ``unresolved_assumptions`` is required, and the
    #: difference is not an inconsistency. The gate branches on an *empty*
    #: assumption list — asserting there are none is a claim it can contradict —
    #: whereas quoting nothing and omitting the field leave it with exactly the
    #: same work to do. Requiring quotations would also push a model to quote
    #: when it has no reason to, and every unnecessary quotation is a new way
    #: for a sound finding to fail on a stray space.
    quoted_evidence: list[Quotation] = Field(default_factory=list)
    #: Call edges the argument depends on, checked against the call graph for
    #: the same reason. Defaulted for the same reason.
    asserted_call_edges: list[CallEdgeClaim] = Field(default_factory=list)
    #: Advisory. Never copied into a finding's confidence: that is decided by
    #: whether the citations resolve, not by how sure the model says it is.
    confidence_self_report: Confidence

    @model_validator(mode="after")
    def _check_confirmation_is_argued(self) -> Self:
        if self.verdict is not Verdict.CONFIRMED:
            return self
        if not self.cited_evidence_ids:
            raise ValueError(
                "a confirmed verdict citing no evidence is an assertion, not an "
                "argument; cite the ids this candidate's context issued"
            )
        if self.cwe is None:
            raise ValueError("a confirmed verdict must say which weakness was confirmed")
        if self.confidence_self_report is Confidence.REVIEW_REQUIRED:
            raise ValueError(
                "verdict=confirmed contradicts confidence_self_report=review_required; "
                "use verdict=review_required to say the question is open"
            )
        return self

    @model_validator(mode="after")
    def _check_citations_are_distinct(self) -> Self:
        seen = set(self.cited_evidence_ids)
        if len(seen) != len(self.cited_evidence_ids):
            raise ValueError("cited_evidence_ids contains the same id more than once")
        if any(not identifier.strip() for identifier in self.cited_evidence_ids):
            raise ValueError("cited_evidence_ids contains a blank id")
        return self

    @model_validator(mode="after")
    def _check_quotations_are_cited(self) -> Self:
        """A quotation from a region the answer never cited is incoherent.

        Structural, like the validators above, and not a verification: whether
        the quoted text is *correct* is a question about the repository and is
        settled in part 11. This only refuses an object that quotes from
        nowhere.
        """
        cited = set(self.cited_evidence_ids)
        stray = sorted({quote.evidence_id for quote in self.quoted_evidence} - cited)
        if stray:
            raise ValueError(
                f"quoted_evidence quotes {len(stray)} id(s) that cited_evidence_ids does "
                f"not list: {', '.join(stray)}; quote only from what you cite"
            )
        return self


class Usage(BaseModel):
    """Detailed provider-reported usage; local estimates never enter this model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    thinking_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    tool_use_tokens: int = Field(default=0, ge=0)
    #: Provider total when available; otherwise the sum of reported components.
    total_tokens: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _derive_total(self) -> Self:
        components = (
            self.input_tokens
            + self.output_tokens
            + self.thinking_tokens
            + self.cached_input_tokens
            + self.tool_use_tokens
        )
        if self.total_tokens == 0 and components:
            object.__setattr__(self, "total_tokens", components)
        if self.total_tokens and self.total_tokens < components:
            raise ValueError("total_tokens cannot be smaller than reported usage components")
        return self

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            thinking_tokens=self.thinking_tokens + other.thinking_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
            tool_use_tokens=self.tool_use_tokens + other.tool_use_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


class ProviderResponse(BaseModel):
    """One raw answer from a backend, before anything has been parsed.

    ``text`` is whatever came back — valid JSON, truncated JSON, or a confident
    paragraph. Keeping it unparsed at this boundary is what makes "prose is
    never converted into a finding" a property of the pipeline rather than a
    hope about the model: the only path out of this type is
    :meth:`Adjudication.model_validate_json`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: Tier
    model_id: str = Field(min_length=1)
    text: str
    usage: Usage = Field(default_factory=Usage)
    #: The provider's own word for why generation stopped, recorded verbatim.
    finish_reason: str = "unknown"
    from_cache: bool = False

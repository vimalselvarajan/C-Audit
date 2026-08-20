"""The finding contract, as types.

This is where the spec's separation of *impact* from *reachability* and
*exploitability* stops being prose. They are three fields; no code path in
this package infers one from another, and the model refuses to let a
high-impact claim quietly imply a reachable one.

Every field of the spec's finding contract table is required. A candidate
that cannot fill one is not a finding — it is a review-required item, which
is a different thing with a different count.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from caudit.model.cwe import CweId, CweStatus, WeaknessFamily, classify_cwe, family_of
from caudit.model.cwe import suggest_replacement as _suggest_replacement
from caudit.model.evidence import EvidenceItem, Provenance
from caudit.model.source import SourceRegion, Symbol

__all__ = [
    "SCHEMA_VERSION",
    "Confidence",
    "Exploitability",
    "Finding",
    "Impact",
    "ImpactKind",
    "Limitation",
    "LimitationKind",
    "MaintainabilityImpact",
    "Reachability",
    "Remediation",
    "ReviewReason",
    "Severity",
]

#: Bumped whenever an exported schema changes shape. CI diffs the committed
#: schemas against a fresh export and fails unless this moved in the same
#: change.
SCHEMA_VERSION = "1.7.0"


class Confidence(StrEnum):
    """From the spec's finding contract. ``review_required`` is not a score."""

    HIGH = "high"
    MEDIUM = "medium"
    REVIEW_REQUIRED = "review_required"


class ReviewReason(StrEnum):
    """A machine-checkable reason — a value part 11 branches on, not free text."""

    ALL_CITATIONS_RESOLVED = "all_citations_resolved"
    HASH_MISMATCH = "hash_mismatch"
    SYMBOL_UNRESOLVED = "symbol_unresolved"
    MISSING_FILE = "missing_file"
    #: The cited region cannot be read at the scanned revision for a reason
    #: that is not a deletion: excluded by a filter, above the size cap, or
    #: resolving outside the repository root. Kept apart from
    #: ``missing_file`` because the file is sitting right there, and a reader
    #: told otherwise would go looking for a deletion that never happened.
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    IMPACT_EXCEEDS_EVIDENCE = "impact_exceeds_evidence"
    ASSUMPTIONS_UNSTATED = "assumptions_unstated"
    #: The code needed to judge this candidate did not fit the token budget
    #: (part 09). Nothing was sent to a model, because the alternative — a
    #: half-function with the bounds check cut off — produces a confident
    #: answer to a question nobody asked.
    CONTEXT_BUDGET_EXCEEDED = "context_budget_exceeded"
    #: The model cited an evidence id that was never issued to it (part 10).
    #: Distinct from ``missing_file``: nothing was looked up, because the
    #: handle does not name anything in the closed world the model was given.
    #: Checked cheaply here and authoritatively again in part 11.
    CITATION_UNRESOLVED = "citation_unresolved"
    #: A claim of the form "``caller`` calls ``callee``" that the call graph
    #: does not record (part 11). Deliberately distinct from
    #: ``symbol_unresolved``: both functions may exist perfectly well, and the
    #: thing that does not resolve is the edge between them. The wording of the
    #: rejection matters too — the index recording no such edge is not the same
    #: claim as no such call existing, and when unresolved indirect calls are in
    #: the graph the detail says so.
    CALL_EDGE_UNRESOLVED = "call_edge_unresolved"
    #: The cited evidence does not contain the structural preconditions the
    #: claimed weakness family needs — a use-after-free with no release site
    #: among its evidence, an out-of-bounds write with no write (part 11). It
    #: is a statement about the *argument*, not about the bug: the defect may
    #: be perfectly real and argued from evidence that was never cited.
    EVIDENCE_DOES_NOT_SUPPORT_CWE = "evidence_does_not_support_cwe"
    #: The adjudicating model read the code and argued the analyzer was wrong
    #: (part 11). The candidate stays in the report because deleting an
    #: analyzer's diagnostic on a model's say-so is the failure this project is
    #: built to avoid; a human confirms the dismissal.
    MODEL_REJECTED = "model_rejected"
    #: The adjudicating model read the code and said the page did not settle
    #: the question (part 11). Distinct from ``model_rejected``, which is an
    #: argument, and from ``provider_unavailable``, where nothing was read at
    #: all — this is an answer, and the answer is "I could not tell".
    MODEL_INCONCLUSIVE = "model_inconclusive"
    #: Every attempt to get a schema-valid response failed (part 10). The last
    #: response is not partially salvaged: prose is never parsed into a
    #: finding, and half a valid object is prose.
    SCHEMA_INVALID_RESPONSE = "schema_invalid_response"
    #: The provider could not be reached, refused the request, or kept timing
    #: out (part 10). Nothing was learned about this candidate, which is a
    #: different statement from "nothing was found".
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    #: The run's token or cost ceiling bound before this candidate was sent
    #: (part 10). No model was asked, so nothing in the report is a statement
    #: about it — which is why this is never a quiet omission.
    RUN_BUDGET_EXHAUSTED = "run_budget_exhausted"
    ANALYZER_ONLY = "analyzer_only"
    OUT_OF_SCOPE_FAMILY = "out_of_scope_family"
    UNRESOLVED_INDIRECT_CALL = "unresolved_indirect_call"
    INCOMPLETE_BUILD_CONTEXT = "incomplete_build_context"
    SCHEMA_VIOLATION = "schema_violation"
    CWE_MAPPING_REJECTED = "cwe_mapping_rejected"
    CONFLICTING_ANALYZERS = "conflicting_analyzers"


#: Reasons that are only ever compatible with ``review_required``. Anything
#: else would let a failed check be reported as a confident finding.
BLOCKING_REVIEW_REASONS: frozenset[ReviewReason] = frozenset(
    {
        ReviewReason.HASH_MISMATCH,
        ReviewReason.SYMBOL_UNRESOLVED,
        ReviewReason.MISSING_FILE,
        ReviewReason.EVIDENCE_UNAVAILABLE,
        ReviewReason.IMPACT_EXCEEDS_EVIDENCE,
        ReviewReason.ASSUMPTIONS_UNSTATED,
        ReviewReason.CONTEXT_BUDGET_EXCEEDED,
        ReviewReason.CITATION_UNRESOLVED,
        ReviewReason.CALL_EDGE_UNRESOLVED,
        ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE,
        ReviewReason.MODEL_REJECTED,
        ReviewReason.MODEL_INCONCLUSIVE,
        ReviewReason.SCHEMA_INVALID_RESPONSE,
        ReviewReason.PROVIDER_UNAVAILABLE,
        ReviewReason.RUN_BUDGET_EXHAUSTED,
        ReviewReason.OUT_OF_SCOPE_FAMILY,
        ReviewReason.SCHEMA_VIOLATION,
        ReviewReason.CWE_MAPPING_REJECTED,
    }
)


class Reachability(StrEnum):
    """Whether the defect can be reached — argued separately from impact."""

    UNKNOWN = "unknown"
    ARGUED = "argued"
    DEMONSTRATED = "demonstrated"


class Exploitability(StrEnum):
    """Whether an attacker can drive it — never inferred from impact."""

    UNKNOWN = "unknown"
    UNLIKELY = "unlikely"
    PLAUSIBLE = "plausible"
    DEMONSTRATED = "demonstrated"


class Severity(StrEnum):
    """Weakness severity in isolation, before reachability is considered."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ImpactKind(StrEnum):
    """What can happen if the defect is triggered."""

    MEMORY_CORRUPTION = "memory_corruption"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    CODE_EXECUTION = "code_execution"
    UNDEFINED_BEHAVIOR = "undefined_behavior"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    INCORRECT_RESULT = "incorrect_result"


class Impact(BaseModel):
    """What can happen — deliberately silent about whether it can be reached."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ImpactKind
    severity: Severity
    description: str = Field(min_length=1)
    #: What the evidence in this finding actually shows, as distinct from what
    #: the weakness class can do in general. Part 11 compares the two.
    evidence_supports: str = Field(min_length=1)


class LimitationKind(StrEnum):
    """Blind spots the run knows about. Recorded, never implicit."""

    MISSING_BUILD_TARGET = "missing_build_target"
    #: The scanned tree is not a repository, or its revision could not be
    #: resolved. The report exists but cannot claim reproducibility (part 05).
    REVISION_UNAVAILABLE = "revision_unavailable"
    #: One file is compiled more than once with different flags, and only one
    #: of those configurations was analysed (part 05).
    AMBIGUOUS_BUILD_CONFIG = "ambiguous_build_config"
    UNRESOLVED_INDIRECT_CALL = "unresolved_indirect_call"
    GENERATED_CODE_UNAVAILABLE = "generated_code_unavailable"
    MACRO_EXPANSION_UNAVAILABLE = "macro_expansion_unavailable"
    #: No cross-function retrieval ran for this finding — true of every
    #: analyzer-only baseline result, and worth saying out loud.
    NO_EVIDENCE_EXPANSION = "no_evidence_expansion"
    FILE_TOO_LARGE = "file_too_large"
    EXCLUDED_BY_FILTER = "excluded_by_filter"
    PARSE_FAILED = "parse_failed"
    #: An analyzer crashed, timed out, or refused a translation unit (part 07).
    #: Deliberately distinct from ``parse_failed``: the unit may be perfectly
    #: valid, and the absence of a candidate in it means nothing.
    ANALYZER_FAILED = "analyzer_failed"
    TOKEN_BUDGET_EXHAUSTED = "token_budget_exhausted"
    INLINE_ASSEMBLY = "inline_assembly"
    TOOLCHAIN_UNAVAILABLE = "toolchain_unavailable"
    #: A claim was weakened because the evidence did not reach it — a
    #: ``demonstrated`` reachability with no control-flow evidence, say
    #: (part 11). The finding survives at the lower claim, and this is how the
    #: weakening reaches the page: a downgrade a reader cannot see is a
    #: silently edited finding.
    CLAIM_DOWNGRADED = "claim_downgraded"
    #: The gate could not check a finding's provenance against the set of
    #: analyzers that actually ran, because no set was supplied (part 11).
    #: Recorded rather than skipped: a check that quietly does not run is
    #: indistinguishable from one that passed.
    PROVENANCE_UNCHECKED = "provenance_unchecked"


class Limitation(BaseModel):
    """One named blind spot, with enough detail to act on it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: LimitationKind
    detail: str = Field(min_length=1)
    affects: str | None = None


class Remediation(BaseModel):
    """A fix strategy. The MVP recommends; it does not modify code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    strategy: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    #: Illustrative only, and labelled as such wherever it is rendered.
    example: str | None = None
    references: list[str] = Field(default_factory=list)


class MaintainabilityImpact(BaseModel):
    """How the recommendation lands on the code that has to live with it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ownership: str = Field(min_length=1)
    complexity: str = Field(min_length=1)
    coupling: str = Field(min_length=1)
    regression_risk: str = Field(min_length=1)
    #: ``low``/``medium``/``high`` effort for the developer who takes the fix.
    effort: Severity = Severity.MEDIUM


def _impact_text(impact: object) -> str:
    """Free text from an Impact, whether it arrives as a model or a dict."""
    if isinstance(impact, Impact):
        return f"{impact.description} {impact.evidence_supports}"
    if isinstance(impact, dict):
        return f"{impact.get('description', '')} {impact.get('evidence_supports', '')}"
    return ""


class Finding(BaseModel):
    """A reported vulnerability, or a review-required candidate.

    Which of the two it is depends on ``confidence`` alone. The two are never
    summed anywhere in this codebase.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1)
    fingerprint: str = Field(min_length=1)
    cwe: CweId
    cwe_rationale: str
    location: SourceRegion
    symbol: Symbol | None = None
    evidence: list[EvidenceItem] = Field(min_length=1)
    preconditions: list[str]
    impact: Impact
    reachability: Reachability
    exploitability: Exploitability
    provenance: list[Provenance] = Field(min_length=1)
    confidence: Confidence
    confidence_reason: ReviewReason
    remediation: Remediation
    maintainability_impact: MaintainabilityImpact
    limitations: list[Limitation]
    schema_version: str = SCHEMA_VERSION

    # ------------------------------------------------------------ validators

    @model_validator(mode="before")
    @classmethod
    def _reject_prohibited_mapping(cls, data: Any) -> Any:
        """Runs before field validation so the rationale can rank suggestions."""
        if not isinstance(data, dict):
            return data
        cwe = data.get("cwe")
        if not isinstance(cwe, str) or classify_cwe(cwe) is not CweStatus.PROHIBITED:
            return data
        context = " ".join(
            str(part)
            for part in (
                data.get("cwe_rationale", ""),
                _impact_text(data.get("impact")),
            )
        )
        suggestions = _suggest_replacement(cwe, context)
        shortlist = ", ".join(suggestions[:3]) if suggestions else "a Base or Variant entry"
        raise ValueError(
            f"{cwe} is a Class or Pillar entry and is prohibited for mapping; "
            f"use the most specific Base or Variant entry that applies — {shortlist}"
        )

    @field_validator("cwe")
    @classmethod
    def _check_cwe_allowed(cls, value: str) -> str:
        status = classify_cwe(value)
        if status is CweStatus.OUT_OF_SCOPE:
            raise ValueError(
                f"{value} is not in the C Audit CWE allowlist. Out-of-family candidates "
                "are not dropped: record them with confidence=review_required and "
                "confidence_reason=out_of_scope_family instead of forcing a mapping"
            )
        return value

    @model_validator(mode="after")
    def _check_mapping_rules(self) -> Self:
        if classify_cwe(self.cwe) is CweStatus.DISCOURAGED and not self.cwe_rationale.strip():
            raise ValueError(
                f"{self.cwe} is a discouraged mapping; cwe_rationale must explain why no "
                "Base or Variant entry applies"
            )
        return self

    @model_validator(mode="after")
    def _check_confidence_consistency(self) -> Self:
        if (
            self.confidence is not Confidence.REVIEW_REQUIRED
            and self.confidence_reason in BLOCKING_REVIEW_REASONS
        ):
            raise ValueError(
                f"confidence_reason={self.confidence_reason} is only compatible with "
                f"confidence=review_required, not {self.confidence}"
            )
        if (
            self.confidence is Confidence.REVIEW_REQUIRED
            and self.confidence_reason is ReviewReason.ALL_CITATIONS_RESOLVED
        ):
            raise ValueError(
                "confidence=review_required needs a reason that says what is unresolved"
            )
        return self

    # --------------------------------------------------------------- helpers

    @property
    def family(self) -> WeaknessFamily | None:
        """The scoring family, used by the evaluation harness."""
        return family_of(self.cwe)

    @property
    def is_confirmed(self) -> bool:
        """True for a reported vulnerability, false for a review candidate.

        There is deliberately no ``total`` counterpart anywhere: confirmed and
        review-required counts are never merged.
        """
        return self.confidence is not Confidence.REVIEW_REQUIRED

    def rejection_hint(self) -> list[str]:
        """Better CWE suggestions, ranked using this finding's own text."""
        context = " ".join(
            [self.cwe_rationale, self.impact.description, self.impact.evidence_supports]
        )
        return _suggest_replacement(self.cwe, context)

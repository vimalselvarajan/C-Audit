"""The gate: a proposal in, a finding or a review item out, no model consulted.

This is the component that makes the product claim true — *use AI to connect
and explain evidence, not to invent it* — so the shape of the code is part of
the argument, not an implementation detail.

**It is deterministic and model-free.** Nothing in this module or anything it
imports opens a socket. A gate that could ask a model whether its own output
was trustworthy would be circular, and one that could ask *anything* over a
network would make two runs of one revision able to disagree.

**Failures accumulate.** Every check runs, and every one that fails is
reported. A review item saying only "hash mismatch" when the CWE was also wrong
costs the reviewer the second discovery, and the gate already knows.

**Nothing is discarded.** A proposal that fails becomes a
:class:`ReviewItem` — the same candidate, the same evidence, the same
provenance, with the reasons attached. The spec's needs-review section is a
queue, not a bin. That holds for the model's own rejections too: a candidate
the adjudicator argued against stays in the report, because deleting an
analyzer's diagnostic on a model's say-so is the exact failure this project is
built around.

**Downgrade precedes rejection.** When only the *strength* of a claim outruns
its evidence, the finding survives at the weaker claim (see
:mod:`caudit.verify.claims`). The hard gate is on fabricated evidence, not on
cautious findings.

**Confidence is computed here.** From the resolutions, never copied from
:attr:`~caudit.model.adjudication.Adjudication.confidence_self_report`. How sure
a model says it is, is not evidence about anything.

One structural note. Building a review item reuses part 08's candidate-to-
finding policy rather than growing a second one: if the gate's fallback
disagreed with :func:`~caudit.finding_policy.promotion.promote_candidate` about what a
candidate means, the analyzer-only baseline and the adjudicated run would be
describing different things and the M2 comparison would be measuring the
difference between two promoters.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.evidence.resolver import Resolution
from caudit.evidence.store import SourceStore
from caudit.finding_policy.promotion import primary_cwe, promote_candidate
from caudit.index.resolver import IndexResolver
from caudit.index.store import Index
from caudit.model.adjudication import Adjudication, Verdict
from caudit.model.candidate import Candidate
from caudit.model.evidence import ANALYZER_PRODUCERS, EvidenceItem, Provenance
from caudit.model.finding import (
    BLOCKING_REVIEW_REASONS,
    Confidence,
    Exploitability,
    Finding,
    Limitation,
    LimitationKind,
    Reachability,
    ReviewReason,
)
from caudit.model.ids import dedup_fingerprint, finding_id
from caudit.retrieval.context import EvidenceContext
from caudit.verify import citations as citation_checks
from caudit.verify import cwe_check
from caudit.verify.claims import Downgrade, assumption_failures, review_claims
from caudit.verify.reasons import Failure, ordered, summarize

__all__ = ["GateOutcome", "ReviewItem", "verify"]

#: The one failure that weakens a finding rather than rejecting it. Everything
#: else in :data:`~caudit.model.finding.BLOCKING_REVIEW_REASONS` sends the
#: candidate to review.
_DOWNGRADE_ONLY: Final[frozenset[ReviewReason]] = frozenset({ReviewReason.IMPACT_EXCEEDS_EVIDENCE})


class ReviewItem(BaseModel):
    """A candidate that did not pass, kept whole with the reasons it did not."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: Finding
    reasons: list[ReviewReason] = Field(min_length=1)
    #: One line per reason, in the same order, so a reader matching the third
    #: reason to the third line is matching the right one.
    details: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_it_is_actually_under_review(self) -> Self:
        if self.finding.is_confirmed:
            raise ValueError(
                "a review item holds a review-required finding; this one is "
                f"{self.finding.confidence}, which would let a rejected proposal be "
                "counted as a confirmed vulnerability"
            )
        if self.finding.confidence_reason not in self.reasons:
            raise ValueError(
                f"the finding's confidence_reason ({self.finding.confidence_reason}) is "
                "not among the reasons the gate recorded; the report and the audit "
                "trail would disagree"
            )
        return self


class GateOutcome(BaseModel):
    """What the gate decided, and everything it looked at to decide it.

    There is deliberately no field, property, or method here that adds the
    confirmed and review-required counts. The separation the spec requires is
    not a convention this package follows — it is a thing this package cannot
    express.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    accepted: bool
    finding: Finding | None = None
    #: Never ``None`` when :attr:`accepted` is false.
    review_item: ReviewItem | None = None
    #: Every applicable reason, in report order. Non-empty even when accepted:
    #: a downgraded finding carries ``impact_exceeds_evidence`` here while
    #: staying confirmed.
    reasons: list[ReviewReason] = Field(default_factory=list)
    details: list[str] = Field(default_factory=list)
    downgrades: list[Downgrade] = Field(default_factory=list)
    #: The full audit trail: one entry per claim the gate resolved, whether or
    #: not it held.
    resolutions: list[Resolution] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_exactly_one_result(self) -> Self:
        if self.accepted and (self.finding is None or self.review_item is not None):
            raise ValueError("an accepted outcome carries a finding and no review item")
        if not self.accepted and (self.review_item is None or self.finding is not None):
            raise ValueError(
                "a refused outcome carries a review item and no finding; nothing is "
                "discarded, so there is no third state where neither exists"
            )
        return self

    @model_validator(mode="after")
    def _check_acceptance_is_argued(self) -> Self:
        blocking = [
            reason
            for reason in self.reasons
            if reason in BLOCKING_REVIEW_REASONS and reason not in _DOWNGRADE_ONLY
        ]
        if self.accepted and blocking:
            raise ValueError(
                f"accepted with {len(blocking)} blocking reason(s): {', '.join(sorted(blocking))}"
            )
        return self

    @property
    def resolution_rate(self) -> float:
        """Fraction of claims that resolved. Vacuously 1.0 when there are none."""
        if not self.resolutions:
            return 1.0
        return sum(1 for item in self.resolutions if item.ok) / len(self.resolutions)


def verify(
    adjudication: Adjudication,
    context: EvidenceContext,
    index: Index,
    store: SourceStore,
    *,
    analyzers: Collection[str] | None = None,
    model_provenance: Provenance | None = None,
) -> GateOutcome:
    """Decide whether one proposal becomes a confirmed finding.

    ``analyzers`` is the set of tools that actually ran, used to reject a
    fabricated name in provenance (AC-11-4). Passing ``None`` does not skip the
    check quietly — the finding carries a limitation saying the check could not
    run, because a check that silently does not run is indistinguishable from
    one that passed.

    ``model_provenance`` records that a model participated. Optional because
    the proposal itself does not know which tier answered it; part 12 supplies
    the record from the outcome that carried it.
    """
    resolver = IndexResolver(store, context.bundle, index)
    claims = citation_checks.citations_for(adjudication, context)
    resolutions = citation_checks.resolve(claims, resolver)

    failures: list[Failure] = []
    failures.extend(_unissued_failures(adjudication, context))
    failures.extend(citation_checks.location_failures(resolutions))
    edge_failures = citation_checks.edge_failures(resolutions, resolver, index)
    failures.extend(edge_failures)
    failures.extend(citation_checks.quotation_failures(adjudication, context))
    failures.extend(_provenance_failures(context.candidate, analyzers))
    failures.extend(assumption_failures(adjudication, context))
    failures.extend(_verdict_failures(adjudication))

    verified_edges = len(adjudication.asserted_call_edges) - len(edge_failures)
    claim_review = review_claims(adjudication, context, verified_edges=max(0, verified_edges))
    failures.extend(claim_review.failures)

    if adjudication.verdict is Verdict.CONFIRMED:
        failures.extend(_weakness_failures(adjudication, context))

    blocking = [
        failure
        for failure in failures
        if failure.reason in BLOCKING_REVIEW_REASONS and failure.reason not in _DOWNGRADE_ONLY
    ]
    accepted = adjudication.verdict is Verdict.CONFIRMED and not blocking
    reasons = ordered(failure.reason for failure in failures)
    details = summarize(failures)

    # Computed from the resolutions, never from confidence_self_report. A
    # downgraded finding is confirmed but not high-confidence: something in it
    # was weakened, and saying "high" would be reporting the claim the gate
    # just refused.
    if not accepted:
        confidence = Confidence.REVIEW_REQUIRED
    elif claim_review.downgrades:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.HIGH

    finding = _build_finding(
        adjudication,
        context,
        store,
        claim_review.reachability,
        claim_review.exploitability,
        confidence=confidence,
        reason=ReviewReason.ALL_CITATIONS_RESOLVED if accepted else _primary_reason(blocking),
        downgrades=claim_review.downgrades,
        analyzers=analyzers,
        model_provenance=model_provenance,
    )
    if accepted:
        return GateOutcome(
            accepted=True,
            finding=finding,
            reasons=reasons,
            details=details,
            downgrades=list(claim_review.downgrades),
            resolutions=resolutions,
        )
    return GateOutcome(
        accepted=False,
        review_item=ReviewItem(finding=finding, reasons=reasons, details=details),
        reasons=reasons,
        details=details,
        downgrades=list(claim_review.downgrades),
        resolutions=resolutions,
    )


# --------------------------------------------------------------------- checks


def _unissued_failures(adjudication: Adjudication, context: EvidenceContext) -> list[Failure]:
    """Cited ids the context never handed out. Checked before any file is opened."""
    return [
        Failure(
            reason=ReviewReason.CITATION_UNRESOLVED,
            detail=(
                f"evidence id {identifier!r} was never issued to this candidate; a model "
                f"may cite only the {len(context.evidence_ids())} id(s) its own context "
                "listed"
            ),
            subject=identifier,
        )
        for identifier in citation_checks.unissued_ids(adjudication, context)
    ]


def _provenance_failures(candidate: Candidate, analyzers: Collection[str] | None) -> list[Failure]:
    """Analyzer names in provenance that this run does not have (AC-11-4).

    Reported as a schema violation rather than an evidence failure: nothing
    about the repository is wrong, the *object* is — it attributes a diagnostic
    to a program that did not run, and no amount of reading the code settles
    that.
    """
    if analyzers is None:
        return []
    known = set(analyzers)
    return [
        Failure(
            reason=ReviewReason.SCHEMA_VIOLATION,
            detail=(
                f"provenance attributes this to {entry.tool_name!r}, which did not run: "
                f"this run's analyzers are {', '.join(sorted(known)) or 'none'}"
            ),
            subject=entry.tool_name,
        )
        for entry in candidate.provenance
        if entry.producer in ANALYZER_PRODUCERS and entry.tool_name not in known
    ]


def _verdict_failures(adjudication: Adjudication) -> list[Failure]:
    """The two verdicts that are answers but not confirmations."""
    if adjudication.verdict is Verdict.REJECTED:
        return [
            Failure(
                reason=ReviewReason.MODEL_REJECTED,
                detail=(
                    "the adjudicating model argued the analyzer was wrong: "
                    f"{adjudication.cwe_rationale.strip() or 'no rationale given'}. The "
                    "candidate stays in the report — a diagnostic is not deleted on a "
                    "model's word"
                ),
                subject="verdict",
            )
        ]
    if adjudication.verdict is Verdict.REVIEW_REQUIRED:
        return [
            Failure(
                reason=ReviewReason.MODEL_INCONCLUSIVE,
                detail=(
                    "the adjudicating model read the evidence and could not settle the "
                    "question: "
                    + (
                        "; ".join(adjudication.unresolved_assumptions)
                        or adjudication.cwe_rationale.strip()
                        or "no rationale given"
                    )
                ),
                subject="verdict",
            )
        ]
    return []


def _weakness_failures(adjudication: Adjudication, context: EvidenceContext) -> list[Failure]:
    """Clause 2: the CWE is allowed, and the cited evidence contains what it needs."""
    cwe = adjudication.cwe
    status = cwe_check.status_failure(cwe, adjudication.cwe_rationale)
    if status is not None or cwe is None:
        # The precondition check is about a family, and this proposal has none
        # that can be scored. Running it anyway would report the same problem
        # twice under two reasons.
        return [status] if status is not None else []
    chunks = _cited_bytes(adjudication, context)
    if not chunks:
        # Nothing citable survived, which ``citation_unresolved`` already says.
        # Running the preconditions over an empty document would add "the
        # evidence does not support the weakness" — a statement about an
        # argument that does not exist, and a second reason for one fault.
        return []
    return cwe_check.precondition_failures(cwe, cwe_check.cited_text(chunks))


def _cited_bytes(adjudication: Adjudication, context: EvidenceContext) -> list[bytes]:
    """The captured bytes behind every cited region, in citation order.

    From the bundle rather than from disk: the question is what the model was
    shown, and re-reading the file would search a different document.
    """
    chunks: list[bytes] = []
    for identifier in adjudication.cited_evidence_ids:
        try:
            chunks.append(context.bundle.zoom(identifier))
        except KeyError:
            continue
    return chunks


def _primary_reason(blocking: Sequence[Failure]) -> ReviewReason:
    """The reason the finding itself carries. The most severe, by report order.

    A finding has one ``confidence_reason`` and the gate has a list; this is
    where the list narrows. The full list travels on the
    :class:`ReviewItem` alongside, so nothing is lost by the narrowing.
    """
    if not blocking:  # pragma: no cover - unreachable: callers pass a failure
        return ReviewReason.SCHEMA_VIOLATION
    return ordered(failure.reason for failure in blocking)[0]


# -------------------------------------------------------------------- building


def _build_finding(
    adjudication: Adjudication,
    context: EvidenceContext,
    store: SourceStore,
    reachability: Reachability,
    exploitability: Exploitability,
    *,
    confidence: Confidence,
    reason: ReviewReason,
    downgrades: Sequence[Downgrade],
    analyzers: Collection[str] | None,
    model_provenance: Provenance | None,
) -> Finding:
    """One finding, whether it is being confirmed or routed to review.

    Deliberately one function for both. Two would be two places for the
    location, the evidence, or the provenance to be assembled differently, and
    a review item that described the candidate differently from a confirmed one
    would make the two sections incomparable.
    """
    candidate = context.candidate
    baseline = promote_candidate(candidate, store=store, limitations=())
    cwe = cwe_check.usable_cwe(adjudication.cwe, candidate, fallback=primary_cwe(candidate))
    symbol = candidate.symbol if candidate.enclosing_region else None
    symbol_name = symbol.name if symbol else None

    return Finding(
        finding_id=finding_id(
            cwe,
            candidate.region.path,
            symbol_name,
            candidate.message,
            start_byte=candidate.region.start_byte,
            end_byte=candidate.region.end_byte,
        ),
        fingerprint=dedup_fingerprint(cwe, candidate.region.path, symbol_name, candidate.message),
        cwe=cwe,
        cwe_rationale=_rationale(adjudication, cwe, baseline.cwe_rationale),
        location=candidate.region,
        symbol=symbol,
        evidence=_evidence(adjudication, context, fallback=baseline.evidence),
        preconditions=list(adjudication.trigger_conditions),
        impact=adjudication.impact,
        reachability=reachability,
        exploitability=exploitability,
        provenance=[*candidate.provenance, *([model_provenance] if model_provenance else [])],
        confidence=confidence,
        confidence_reason=reason,
        remediation=adjudication.remediation,
        maintainability_impact=adjudication.maintainability_impact,
        limitations=_limitations(
            context,
            downgrades=downgrades,
            analyzers=analyzers,
            affects=str(candidate.region.path),
        ),
    )


def _rationale(adjudication: Adjudication, carried: str, baseline: str) -> str:
    """Why this finding carries this CWE.

    The model's own words when its entry survived. When it did not, the
    baseline's rationale plus a statement of what happened — silently
    substituting a CWE would put a mapping in the report that nobody argued
    for, and the substitution has two quite different causes worth telling
    apart: a mapping the run refused, and a proposal that named no weakness
    because it was not confirming one.
    """
    proposed = adjudication.cwe
    if proposed == carried and adjudication.cwe_rationale.strip():
        return adjudication.cwe_rationale
    if proposed == carried:
        return baseline
    if proposed is None:
        return (
            f"{baseline} The adjudication returned {adjudication.verdict} and named no "
            f"weakness, so {carried} is the analyzer's own classification and is what "
            "this item is about."
        )
    named = proposed
    return (
        f"{baseline} The adjudication proposed {named}, which this run cannot carry; "
        f"{carried} comes from the analyzer's own classification instead, and the "
        "refusal is recorded in this item's reasons."
    )


def _evidence(
    adjudication: Adjudication, context: EvidenceContext, *, fallback: Sequence[EvidenceItem]
) -> list[EvidenceItem]:
    """The cited items, in citation order, or the candidate's own if none survive.

    A finding needs at least one evidence item, and a proposal that cited
    nothing resolvable still describes a real analyzer diagnostic at a real
    location. Falling back to that is not a repair of the proposal — the
    proposal is being refused — it is the report keeping the thing that was
    true before the model was asked.
    """
    cited = [
        item
        for item in (context.bundle.get(name) for name in adjudication.cited_evidence_ids)
        if item is not None
    ]
    return cited or list(fallback)


def _limitations(
    context: EvidenceContext,
    *,
    downgrades: Sequence[Downgrade],
    analyzers: Collection[str] | None,
    affects: str,
) -> list[Limitation]:
    """Everything a reader has to know about what this finding did not see.

    The citations that failed are *not* here. They are the review item's
    reasons, which is a different statement: a limitation says what the run
    could not look at, and a citation that does not resolve is something the
    run looked at and rejected.
    """
    collected: list[Limitation] = list(context.limitations)
    collected.extend(downgrade.as_limitation(affects) for downgrade in downgrades)
    if analyzers is None:
        collected.append(
            Limitation(
                kind=LimitationKind.PROVENANCE_UNCHECKED,
                detail=(
                    "this finding's provenance was not checked against the set of "
                    "analyzers that ran, because no set was supplied to the gate"
                ),
                affects=affects,
            )
        )
    deduplicated: list[Limitation] = []
    for limitation in collected:
        if limitation not in deduplicated:
            deduplicated.append(limitation)
    return deduplicated

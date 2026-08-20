"""Where the parts stop being components and become a tool.

Parts 05 to 11 each answer one question well and none of them produces a
report. This module is the join: it walks every candidate through retrieval,
adjudication and the gate, turns the outcomes into the two sections part 08
renders, and completes the manifest with what the run actually cost.

Four things it is careful about.

**Every candidate produces exactly one finding.** Confirmed, or review-required
with a reason — never nothing. A candidate that could not be expanded, could not
be sent, could not be answered, or was answered and refused all still appear,
because a diagnostic that vanishes because a *later* stage failed is the worst
possible outcome: the report looks clean and the defect is still there.

**The order candidates are visited in is fixed before any budget is spent.**
When the run's token ceiling binds, the order decides which candidates were
adjudicated and which were only promoted, so it must not depend on dict
iteration or on which analyzer happened to finish first.

**A failed stage degrades the run; it does not end it.** :class:`StageLog`
records how long each stage took and how it ended, and a failure inside a timed
stage is caught, recorded, and left to the caller's fallback. That is what turns
"the index crashed" into a partial report with a limitation rather than a
traceback and no artifacts.

**AI provenance is per claim.** The spec's provenance field applies to
supporting facts individually, so :func:`claim_provenance` separates what an
analyzer reported from what the index supplied from what the model argued. A
finding does not get one badge saying a model touched it; it says which parts a
model is responsible for.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from caudit.application.stages import Stage, StageLog, StageNote
from caudit.config.loader import Config
from caudit.evidence.store import SourceStore
from caudit.finding_policy.promotion import promote_candidate
from caudit.finding_policy.provenance import (
    MODEL_AUTHORED_FIELDS,
    ClaimProvenance,
    claim_provenance,
)
from caudit.index.store import Index
from caudit.llm.service import (
    AdjudicationOutcome,
    ConsentDecision,
    LLMProvider,
    ResponseCache,
    RunAccount,
    adjudicate,
)
from caudit.logging import get_logger
from caudit.model.candidate import Candidate
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import (
    BLOCKING_REVIEW_REASONS,
    Confidence,
    Finding,
    Limitation,
    ReviewReason,
)
from caudit.retrieval.context import EvidenceContext
from caudit.retrieval.policy import ExpansionPolicy
from caudit.retrieval.service import RunLedger, expand
from caudit.verify import GateOutcome, verify

__all__ = [
    "MODEL_AUTHORED_FIELDS",
    "CandidateOutcome",
    "ClaimProvenance",
    "PipelineResult",
    "Stage",
    "StageLog",
    "StageNote",
    "adjudicate_candidates",
    "claim_provenance",
    "model_provenance",
    "promote_only",
    "sort_candidates",
]

log = get_logger(__name__)


#: Fields the deterministic gate computes, listed beside the model's so a
#: reader can see that the two sets do not overlap. ``reachability`` and
#: ``exploitability`` are here rather than above because part 11 caps whatever
#: was proposed at what the citations support.
GATE_COMPUTED_FIELDS: Final[tuple[str, ...]] = (
    "confidence",
    "confidence_reason",
    "reachability",
    "exploitability",
)


# ------------------------------------------------------------------ outcomes


@dataclass(frozen=True)
class CandidateOutcome:
    """What the pipeline made of one candidate.

    ``finding`` is never ``None``: every candidate reaches the report, as a
    confirmed finding or as a review item. The stages that did not run are
    ``None``, which is how a reader of an outcome can tell "the model rejected
    this" from "no model was asked".
    """

    candidate: Candidate
    finding: Finding
    context: EvidenceContext | None = None
    adjudication: AdjudicationOutcome | None = None
    gate: GateOutcome | None = None
    limitations: tuple[Limitation, ...] = ()

    @property
    def adjudicated(self) -> bool:
        """Whether a model actually answered about this candidate."""
        return self.adjudication is not None and self.adjudication.adjudication is not None


@dataclass(frozen=True)
class PipelineResult:
    """Every candidate's outcome, plus what the run spent getting them."""

    outcomes: tuple[CandidateOutcome, ...]
    account: RunAccount | None = None
    limitations: tuple[Limitation, ...] = ()

    @property
    def findings(self) -> list[Finding]:
        return [outcome.finding for outcome in self.outcomes]

    @property
    def adjudicated_count(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.adjudicated)

    @property
    def confirmed_count(self) -> int:
        """Findings the gate accepted. Never added to the review count."""
        return sum(1 for outcome in self.outcomes if outcome.finding.is_confirmed)

    @property
    def review_count(self) -> int:
        """Candidates needing review. Counted apart from the confirmed ones."""
        return sum(1 for outcome in self.outcomes if not outcome.finding.is_confirmed)


def sort_candidates(candidates: Sequence[Candidate]) -> list[Candidate]:
    """A fixed visit order, decided before any budget is spent.

    Path, then line, then id. The run ledger hands out the tail of a token
    budget in the order candidates are visited, so when the ceiling binds this
    order decides which candidates a model saw. Leaving that to whatever order
    part 07 happened to emit would make a budget-limited run irreproducible for
    a reason nothing in the report could explain.
    """
    return sorted(
        candidates,
        key=lambda candidate: (
            str(candidate.region.path),
            candidate.region.start_line,
            candidate.candidate_id,
        ),
    )


# ------------------------------------------------------------------ pipeline


def promote_only(candidates: Sequence[Candidate], store: SourceStore) -> PipelineResult:
    """The analyzer-only path: part 08's baseline, unchanged.

    Used when consent was not given. It is deliberately the same call part 08
    and ``caudit eval --baseline`` make, not a reimplementation of it: the M1
    number an adjudicated run is compared against has to be the number M1
    actually produced.
    """
    return PipelineResult(
        outcomes=tuple(
            CandidateOutcome(candidate=candidate, finding=promote_candidate(candidate, store=store))
            for candidate in sort_candidates(candidates)
        )
    )


def adjudicate_candidates(
    candidates: Sequence[Candidate],
    index: Index,
    store: SourceStore,
    config: Config,
    *,
    provider: LLMProvider,
    consent: ConsentDecision,
    analyzers: Sequence[str],
    account: RunAccount | None = None,
    cache: ResponseCache | None = None,
) -> PipelineResult:
    """Retrieval, adjudication and the gate, once per candidate.

    Returns an outcome for every candidate in a fixed order. Nothing raises
    past this function for a per-candidate problem: a provider that will not
    answer, a context that will not fit, a proposal the gate refuses are all
    outcomes carrying a reason, because one bad candidate must not cost the
    report the other forty.
    """
    ledger = RunLedger(budget=config.token_budget)
    ledger_account = account if account is not None else RunAccount(config=config)
    policy = ExpansionPolicy.from_config(config)
    outcomes: list[CandidateOutcome] = []

    for candidate in sort_candidates(candidates):
        if ledger.exhausted:
            starved = ledger.starve(candidate.candidate_id)
            outcomes.append(
                _refused(candidate, store, ReviewReason.RUN_BUDGET_EXHAUSTED, [starved])
            )
            continue

        context = expand(
            candidate,
            index,
            store,
            policy,
            config.token_budget,
            allowance=ledger.allowance(),
        )
        ledger.charge(context.total_tokens)

        outcome = adjudicate(
            context,
            config=config,
            provider=provider,
            consent=consent,
            account=ledger_account,
            cache=cache,
        )
        if outcome.adjudication is None:
            outcomes.append(
                _refused(
                    candidate,
                    store,
                    outcome.review_reason or ReviewReason.PROVIDER_UNAVAILABLE,
                    list(outcome.limitations),
                    context=context,
                    adjudication=outcome,
                )
            )
            continue

        gated = verify(
            outcome.adjudication,
            context,
            index,
            store,
            analyzers=analyzers,
            model_provenance=model_provenance(outcome, config),
        )
        finding = gated.finding if gated.finding is not None else _refused_finding(gated)
        outcomes.append(
            CandidateOutcome(
                candidate=candidate,
                finding=finding,
                context=context,
                adjudication=outcome,
                gate=gated,
                limitations=tuple(outcome.limitations),
            )
        )

    return PipelineResult(
        outcomes=tuple(outcomes),
        account=ledger_account,
        limitations=tuple(ledger_account.limitations()),
    )


def _refused_finding(gated: GateOutcome) -> Finding:
    """The finding inside a refused gate outcome.

    ``GateOutcome`` guarantees exactly one of the two is present, so this
    cannot fail — but the type is ``Finding | None`` on both, and asserting the
    invariant here is cheaper than teaching every caller about it.
    """
    if gated.review_item is None:  # pragma: no cover - forbidden by GateOutcome
        raise ValueError("a refused gate outcome always carries a review item")
    return gated.review_item.finding


def _refused(
    candidate: Candidate,
    store: SourceStore,
    reason: ReviewReason,
    limitations: Sequence[Limitation],
    *,
    context: EvidenceContext | None = None,
    adjudication: AdjudicationOutcome | None = None,
) -> CandidateOutcome:
    """A candidate no model answered about, kept in the report with the reason.

    The analyzer's own claim is what survives, which is the point: the model
    stage failing tells you nothing about whether the diagnostic was right.
    A non-blocking reason — triage deciding this was not worth the expensive
    tier — leaves the finding exactly as the analyzer reported it, because that
    decision was about cost, not about the code.
    """
    finding = promote_candidate(candidate, store=store, limitations=limitations)
    if reason in BLOCKING_REVIEW_REASONS:
        finding = finding.model_copy(
            update={"confidence": Confidence.REVIEW_REQUIRED, "confidence_reason": reason}
        )
    return CandidateOutcome(
        candidate=candidate,
        finding=finding,
        context=context,
        adjudication=adjudication,
        limitations=tuple(limitations),
    )


def model_provenance(outcome: AdjudicationOutcome, config: Config) -> Provenance:
    """A record that a model contributed to this finding, and which one.

    ``tool_version`` is the prompt policy version rather than a model version
    string. A hosted model behind a moving alias has no version we can read,
    and the prompt version is the thing that actually changes what comes back —
    so it is the honest answer to "what produced this, and would it produce it
    again". ``rule_id`` carries the tier for the same reason an analyzer's
    ``rule_id`` carries its check: it says which capability answered.
    """
    return Provenance(
        producer=Producer.LLM,
        tool_name=outcome.model_id,
        tool_version=config.policy_versions.prompt,
        rule_id=str(outcome.tier),
        detail=(
            "adjudicated under prompt policy "
            f"v{config.policy_versions.prompt}; every claim was checked by the "
            "verification gate before it reached this report"
        ),
    )

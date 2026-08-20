"""Clauses 3 and 4: does the claim outrun the evidence, and were gaps admitted?

Clause 3 is the one place in this package where a failed check does **not**
route the candidate to review. When only the *strength* of a claim is
unsupported, the finding is kept and the claim is weakened, because the spec's
hard gate is on fabricated evidence rather than on cautious findings — and
because a real defect discarded for over-claiming its reachability is a real
defect that nobody fixes.

That leniency is bounded in three ways:

* a claim is only ever lowered. Every rule computes a *ceiling* and the kept
  value is ``min(claimed, ceiling)``, so a cautious answer is never raised to
  meet the evidence;
* the weakening is recorded twice — as a
  :class:`~caudit.model.finding.ReviewReason` on the gate's outcome and as a
  :class:`~caudit.model.finding.Limitation` on the finding itself, which is how
  it reaches the page. A downgrade a reader cannot see is a silently edited
  finding;
* the ceilings are computed from what was *cited*, not from what was
  retrieved. A caller sitting unused in the context does not make a
  reachability argument; citing it does.

Clause 4 is the contradiction check. ``unresolved_assumptions`` is required by
the schema, so its presence is not in question — what is checkable is an empty
list standing next to a context that dropped units or an index that recorded an
indirect call in this code. "There are none" is a claim, and that is the
evidence against it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.model.adjudication import Adjudication
from caudit.model.evidence import EvidenceKind
from caudit.model.finding import (
    Exploitability,
    Limitation,
    LimitationKind,
    Reachability,
    ReviewReason,
)
from caudit.retrieval.context import EvidenceContext
from caudit.retrieval.policy import UnitRole
from caudit.verify.reasons import Failure

__all__ = ["ClaimReview", "Downgrade", "assumption_failures", "review_claims"]


class Downgrade(BaseModel):
    """A claim that was kept at a weaker value than the one proposed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: ``reachability`` or ``exploitability``. A string rather than an enum
    #: because it names a field of the finding, not a value of one.
    field_name: str = Field(min_length=1)
    claimed: str = Field(min_length=1)
    kept: str = Field(min_length=1)
    detail: str = Field(min_length=1)

    def as_limitation(self, affects: str) -> Limitation:
        """How the weakening reaches the report.

        A ``Limitation`` rather than a note, because that is the model the
        renderer already carries to the page and the one part 04 can count.
        """
        return Limitation(
            kind=LimitationKind.CLAIM_DOWNGRADED,
            detail=(
                f"{self.field_name} was proposed as {self.claimed} and is reported as "
                f"{self.kept}: {self.detail}"
            ),
            affects=affects,
        )


@dataclass(frozen=True)
class ClaimReview:
    """What the two impact claims survive as, and what that cost."""

    reachability: Reachability
    exploitability: Exploitability
    downgrades: tuple[Downgrade, ...] = ()
    failures: tuple[Failure, ...] = ()
    #: What the citations were found to establish, kept so a caller can explain
    #: a ceiling without recomputing it.
    signals: Mapping[str, bool] = field(default_factory=dict)


_REACHABILITY_RANK: Final[dict[Reachability, int]] = {
    Reachability.UNKNOWN: 0,
    Reachability.ARGUED: 1,
    Reachability.DEMONSTRATED: 2,
}

_EXPLOITABILITY_RANK: Final[dict[Exploitability, int]] = {
    Exploitability.UNKNOWN: 0,
    Exploitability.UNLIKELY: 1,
    Exploitability.PLAUSIBLE: 2,
    Exploitability.DEMONSTRATED: 3,
}

#: Roles that put a cited unit *upstream* of the defect: something that supplies
#: the value rather than something the defect reaches. Attacker influence is a
#: claim about where the input comes from, so it is these that can support it.
_UPSTREAM_ROLES: Final[frozenset[UnitRole]] = frozenset({UnitRole.CALLER, UnitRole.FLOW_FUNCTION})

#: Evidence kinds that are a traced path rather than a location.
_FLOW_KINDS: Final[frozenset[EvidenceKind]] = frozenset(
    {EvidenceKind.CONTROL_FLOW_STEP, EvidenceKind.CALL_EDGE}
)


def review_claims(
    adjudication: Adjudication,
    context: EvidenceContext,
    *,
    verified_edges: int = 0,
) -> ClaimReview:
    """Cap ``reachability`` and ``exploitability`` at what the citations support.

    ``verified_edges`` is how many asserted call edges the index confirmed. An
    edge that resolved is the strongest reachability evidence available on a
    page of code — it is the compiler's own answer — so it counts even when the
    cited regions alone would not reach ``demonstrated``.
    """
    signals = _signals(adjudication, context, verified_edges=verified_edges)

    reach_ceiling = _reachability_ceiling(signals)
    exploit_ceiling = _exploitability_ceiling(signals)

    downgrades: list[Downgrade] = []
    reachability = _weaker(adjudication.reachability, reach_ceiling, _REACHABILITY_RANK)
    if reachability is not adjudication.reachability:
        downgrades.append(
            Downgrade(
                field_name="reachability",
                claimed=str(adjudication.reachability),
                kept=str(reachability),
                detail=_reachability_detail(signals),
            )
        )

    exploitability = _weaker(adjudication.exploitability, exploit_ceiling, _EXPLOITABILITY_RANK)
    if exploitability is not adjudication.exploitability:
        downgrades.append(
            Downgrade(
                field_name="exploitability",
                claimed=str(adjudication.exploitability),
                kept=str(exploitability),
                detail=_exploitability_detail(signals),
            )
        )

    failures = tuple(
        Failure(
            reason=ReviewReason.IMPACT_EXCEEDS_EVIDENCE,
            detail=downgrade.detail,
            subject=downgrade.field_name,
        )
        for downgrade in downgrades
    )
    return ClaimReview(
        reachability=reachability,
        exploitability=exploitability,
        downgrades=tuple(downgrades),
        failures=failures,
        signals=signals,
    )


def _signals(
    adjudication: Adjudication, context: EvidenceContext, *, verified_edges: int
) -> dict[str, bool]:
    """What the cited evidence establishes, as three independent booleans."""
    kinds: list[EvidenceKind] = []
    roles: list[UnitRole] = []
    for identifier in adjudication.cited_evidence_ids:
        item = context.bundle.get(identifier)
        if item is not None:
            kinds.append(item.kind)
        unit = context.unit(identifier)
        if unit is not None:
            roles.append(unit.role)
    return {
        "control_flow": bool(verified_edges)
        or any(kind in _FLOW_KINDS for kind in kinds)
        or any(role is UnitRole.FLOW_FUNCTION for role in roles),
        "code": any(kind is not EvidenceKind.ANALYZER_DIAGNOSTIC for kind in kinds),
        "upstream": bool(verified_edges) or any(role in _UPSTREAM_ROLES for role in roles),
    }


def _reachability_ceiling(signals: Mapping[str, bool]) -> Reachability:
    if signals["control_flow"]:
        return Reachability.DEMONSTRATED
    if signals["code"]:
        return Reachability.ARGUED
    return Reachability.UNKNOWN


def _exploitability_ceiling(signals: Mapping[str, bool]) -> Exploitability:
    """ "Above ``unlikely`` requires evidence of attacker-influenced input."

    ``demonstrated`` additionally needs the path, which is a strict refinement
    of the plan's sentence rather than a relaxation of it: without it that
    value could never be reached through the gate at all.
    """
    if signals["upstream"] and signals["control_flow"]:
        return Exploitability.DEMONSTRATED
    if signals["upstream"]:
        return Exploitability.PLAUSIBLE
    return Exploitability.UNLIKELY


def _weaker[T](claimed: T, ceiling: T, rank: Mapping[T, int]) -> T:
    """The weaker of the two. Never raises a claim, only lowers one."""
    return claimed if rank[claimed] <= rank[ceiling] else ceiling


def _reachability_detail(signals: Mapping[str, bool]) -> str:
    if not signals["code"]:
        return (
            "no code was cited — an analyzer diagnostic says where a check fired, not "
            "that the line can be reached"
        )
    return (
        "no control-flow evidence connects an entry point to the site: none of the cited "
        "evidence is a traced path, a resolved call edge, or a function on the analyzer's "
        "own reported flow"
    )


def _exploitability_detail(signals: Mapping[str, bool]) -> str:
    if not signals["upstream"]:
        return (
            "nothing upstream of the defect was cited, so there is no evidence that an "
            "attacker influences the value that reaches it; a claim above 'unlikely' "
            "needs a caller, a flow function, or a resolved call edge"
        )
    return (
        "an attacker-influenced input was argued but no traced path reaches the site, "
        "which is the difference between a plausible route and a demonstrated one"
    )


def assumption_failures(adjudication: Adjudication, context: EvidenceContext) -> list[Failure]:
    """Clause 4: an empty assumption list contradicted by the run's own record.

    Only fires when the list is empty. A model that *stated* assumptions has
    satisfied the clause, whatever it chose to state — judging whether it named
    the right ones would be judging the answer, which is not what a
    deterministic gate can do.
    """
    if adjudication.unresolved_assumptions:
        return []

    contradictions: list[str] = []
    if context.dropped:
        contradictions.append(
            f"{len(context.dropped)} retrieved unit(s) did not fit the budget and were not shown"
        )
    kinds = sorted({str(limitation.kind) for limitation in context.limitations})
    if kinds:
        contradictions.append(
            f"the run recorded {len(context.limitations)} blind spot(s) touching this "
            f"code ({', '.join(kinds)})"
        )
    if not contradictions:
        return []
    return [
        Failure(
            reason=ReviewReason.ASSUMPTIONS_UNSTATED,
            detail=(
                "the answer asserts there are no unresolved assumptions, but "
                + "; and ".join(contradictions)
                + ". An empty list is a claim, and this run contradicts it"
            ),
            subject="unresolved_assumptions",
        )
    ]

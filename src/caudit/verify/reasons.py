"""The reason vocabulary, as the gate uses it.

:class:`~caudit.model.finding.ReviewReason` is part 02's enum and stays there:
it is on the finding contract, it is exported as JSON Schema, and a second
copy declared here would be a second thing to keep in step. What lives here is
everything *around* it — how a resolver verdict becomes a reason, how a reason
is worded for a reader, and the total order the gate reports them in.

That order is not cosmetic. AC-11-12 requires every applicable reason, and
AC-11-15 requires the same input to produce the same output; together those
mean the *sequence* has to be a function of the reasons themselves rather than
of the order the checks happened to run in. So :func:`ordered` sorts by a fixed
rank, and a reason with no rank sorts last by name rather than crashing — a new
member of the enum must not be able to make the gate non-deterministic before
anyone remembers to rank it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from caudit.evidence.resolver import REASON_FOR_STATUS, Resolution, ResolutionStatus
from caudit.model.finding import ReviewReason

__all__ = [
    "Failure",
    "ordered",
    "reason_for",
    "summarize",
]

#: Report order. Roughly "how far from the truth is this": a citation that does
#: not exist comes before a claim that is merely stronger than its evidence,
#: because the first tells a reader to stop reading and the second tells them
#: to read on with a correction in mind.
_RANK: Final[dict[ReviewReason, int]] = {
    ReviewReason.CITATION_UNRESOLVED: 0,
    ReviewReason.MISSING_FILE: 1,
    ReviewReason.SYMBOL_UNRESOLVED: 2,
    ReviewReason.CALL_EDGE_UNRESOLVED: 3,
    ReviewReason.HASH_MISMATCH: 4,
    ReviewReason.EVIDENCE_UNAVAILABLE: 5,
    ReviewReason.SCHEMA_VIOLATION: 6,
    ReviewReason.SCHEMA_INVALID_RESPONSE: 7,
    ReviewReason.CWE_MAPPING_REJECTED: 8,
    ReviewReason.OUT_OF_SCOPE_FAMILY: 9,
    ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE: 10,
    ReviewReason.IMPACT_EXCEEDS_EVIDENCE: 11,
    ReviewReason.ASSUMPTIONS_UNSTATED: 12,
    ReviewReason.UNRESOLVED_INDIRECT_CALL: 13,
    ReviewReason.INCOMPLETE_BUILD_CONTEXT: 14,
    ReviewReason.CONFLICTING_ANALYZERS: 15,
    ReviewReason.MODEL_REJECTED: 16,
    ReviewReason.MODEL_INCONCLUSIVE: 17,
    ReviewReason.CONTEXT_BUDGET_EXCEEDED: 18,
    ReviewReason.PROVIDER_UNAVAILABLE: 19,
    ReviewReason.RUN_BUDGET_EXHAUSTED: 20,
    ReviewReason.ANALYZER_ONLY: 21,
    ReviewReason.ALL_CITATIONS_RESOLVED: 22,
}

#: Sorts an unranked reason last, by name. Deterministic without being
#: prescient: a member added to the enum without a rank still produces a stable
#: report rather than an arbitrary one.
_UNRANKED: Final = len(_RANK)


@dataclass(frozen=True)
class Failure:
    """One thing the gate checked and did not accept.

    The reason is what a router branches on; ``detail`` is what a human needs
    in order to disagree with the gate. Both are kept, because a review queue
    that says only ``symbol_unresolved`` costs the reviewer the work the gate
    already did.
    """

    reason: ReviewReason
    detail: str
    #: What was being checked — an evidence id, a symbol, an edge. Empty when
    #: the failure is about the answer as a whole.
    subject: str = ""

    def describe(self) -> str:
        where = f" ({self.subject})" if self.subject else ""
        return f"{self.reason}{where}: {self.detail}"


def reason_for(resolution: Resolution) -> ReviewReason:
    """The review reason a failed resolution routes to.

    Reads the citation as well as the status, because
    :class:`~caudit.index.resolver.IndexResolver` reports a missing call edge
    as ``SYMBOL_NOT_FOUND`` — both functions may exist perfectly well, and what
    failed is the edge between them. Only the caller knows which question it
    asked, so only the caller can tell those two apart.
    """
    citation = resolution.citation
    if citation.caller and citation.callee and resolution.status in _EDGE_STATUSES:
        return ReviewReason.CALL_EDGE_UNRESOLVED
    if resolution.status is ResolutionStatus.UNKNOWN_EVIDENCE_ID:
        return ReviewReason.CITATION_UNRESOLVED
    return REASON_FOR_STATUS.get(resolution.status, ReviewReason.SCHEMA_VIOLATION)


#: The verdicts an edge check can produce. Narrow on purpose: a citation that
#: names an edge *and* a region can fail on the region, and that is a location
#: failure rather than an edge one.
_EDGE_STATUSES: Final[frozenset[ResolutionStatus]] = frozenset({ResolutionStatus.SYMBOL_NOT_FOUND})


def ordered(reasons: Iterable[ReviewReason]) -> list[ReviewReason]:
    """Deduplicated, in report order. Total, so two runs cannot disagree."""
    unique = dict.fromkeys(reasons)
    return sorted(unique, key=lambda reason: (_RANK.get(reason, _UNRANKED), str(reason)))


def summarize(failures: Sequence[Failure]) -> list[str]:
    """One line per failure, in report order, deduplicated.

    Ordered by the same rank as :func:`ordered` so that a review item's
    reasons and its explanations read in the same sequence; a reader matching
    the third reason to the third line must not be matching the wrong one.
    """
    ranked = sorted(
        failures,
        key=lambda failure: (
            _RANK.get(failure.reason, _UNRANKED),
            str(failure.reason),
            failure.subject,
            failure.detail,
        ),
    )
    lines: list[str] = []
    for failure in ranked:
        line = failure.describe()
        if line not in lines:
            lines.append(line)
    return lines

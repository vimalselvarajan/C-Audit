"""Merging duplicate candidates without losing a producer.

Provenance is what lets a reader tell "three analyzers agree" from "one noisy
check fired twice", so the merge is a **union**: every distinct provenance
entry that went in comes out, attached to the candidate that absorbed it. The
only entries that disappear are ones that were already indistinguishable —
same producer, tool, version, rule, and detail — and those carried no
information to lose.

Grouping is by ``dedup_fingerprint``, which deliberately excludes line
numbers, so the same defect still matches after the code around it moves. A
fingerprint alone is not enough to merge, though: two identical diagnostics in
two different functions of one file share a fingerprint and are two defects.
:func:`merge_candidates` therefore requires agreement on *place* as well —
the same enclosing symbol when the index knows one, or a line distance within
tolerance when it does not.

Order is fixed before anything merges. Two runs whose translation units
finish in a different order must produce the same list, so the input is sorted
by a total key and clusters are formed greedily in that order.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from caudit.model.candidate import Candidate

__all__ = ["DEFAULT_LINE_TOLERANCE", "merge_candidates", "sort_candidates"]

#: How far apart two same-fingerprint candidates may sit and still be one
#: defect when neither has a proven enclosing function. Chosen to span a small
#: statement group — a `malloc` and the store through it — without spanning a
#: whole function.
DEFAULT_LINE_TOLERANCE: Final = 12


def sort_candidates(candidates: Sequence[Candidate]) -> list[Candidate]:
    """A total order over candidates, independent of who produced them first.

    ``candidate_id`` is the final tiebreaker: it is a content hash, so it is
    stable across processes and machines in a way ``id()`` or arrival order
    can never be.
    """
    return sorted(
        candidates,
        key=lambda item: (
            str(item.region.path),
            item.region.start_line,
            item.region.start_byte,
            item.region.end_line,
            item.candidate_id,
        ),
    )


def merge_candidates(
    candidates: Sequence[Candidate], *, line_tolerance: int = DEFAULT_LINE_TOLERANCE
) -> list[Candidate]:
    """Group by ``dedup_fingerprint``. Provenance is unioned; never truncated.

    Returns the merged candidates in :func:`sort_candidates` order. Merging is
    greedy over that order: each candidate joins the first cluster of its
    fingerprint that it agrees with on place, or starts a new one. Greedy
    rather than transitive closure because "same defect" is not transitive —
    three candidates spread over 20 lines are not one defect just because each
    is close to the next — and because a greedy pass over a sorted input gives
    the same answer every time.
    """
    clusters: dict[str, list[Candidate]] = {}
    for candidate in sort_candidates(candidates):
        group = clusters.setdefault(candidate.fingerprint, [])
        for position, existing in enumerate(group):
            if _same_defect(existing, candidate, line_tolerance):
                group[position] = existing.merged_with(candidate)
                break
        else:
            group.append(candidate)
    return sort_candidates([merged for group in clusters.values() for merged in group])


def _same_defect(left: Candidate, right: Candidate, line_tolerance: int) -> bool:
    """Whether two same-fingerprint candidates point at one place.

    The index's answer wins when it has one. Two candidates the index places in
    different functions are different defects however similar their text, and
    two it places in the same function are the same defect however far apart
    their lines — a leak reported at the allocation and at the return are one
    leak.
    """
    left_symbol = _symbol_key(left)
    right_symbol = _symbol_key(right)
    if left_symbol is not None and right_symbol is not None:
        return left_symbol == right_symbol
    return abs(left.region.start_line - right.region.start_line) <= line_tolerance


def _symbol_key(candidate: Candidate) -> tuple[str, str] | None:
    """A symbol identity, but only one the candidate can prove.

    A symbol with no region containing it is a name an analyzer printed, not a
    fact — part 02 makes the same distinction — so it does not get to decide
    whether two candidates merge. USR first, because two `static` helpers in
    different files share a name and do not share a USR.
    """
    symbol = candidate.symbol
    if symbol is None or candidate.enclosing_region is None:
        return None
    return (str(candidate.enclosing_region.path), symbol.usr or symbol.name)

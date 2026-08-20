"""The verification gate (part 11).

:func:`~caudit.verify.gate.verify` decides, deterministically and without
consulting any model, whether an adjudication becomes a confirmed finding. It
implements the spec's four clauses over one proposal:

1. every cited file, line, symbol, and call edge resolves against the scanned
   revision — and every quotation is the bytes it claims to be;
2. the cited evidence contains the structure the claimed weakness needs;
3. the reported impact does not exceed what the evidence proves, which weakens
   the claim rather than discarding the finding;
4. unresolved assumptions are stated, and an empty list is a claim the run's
   own record can contradict.

Nothing here opens a socket, reads a clock, or asks a model anything. Given the
same proposal, context, index, and revision, it returns the same outcome with
the same reasons in the same order — which is what makes it something a report
can be held to rather than another opinion in the pipeline.

Part 12 assembles this into ``caudit scan``. Until it does, this is a library
entry point: part 10 produces proposals, this package judges them, and neither
is wired into a command yet.
"""

from __future__ import annotations

from caudit.verify.citations import (
    citations_for,
    edge_failures,
    location_failures,
    quotation_failures,
    unissued_ids,
)
from caudit.verify.claims import ClaimReview, Downgrade, assumption_failures, review_claims
from caudit.verify.cwe_check import (
    Precondition,
    precondition_failures,
    preconditions_for,
    status_failure,
)
from caudit.verify.gate import GateOutcome, ReviewItem, verify
from caudit.verify.reasons import Failure, ordered, reason_for, summarize

__all__ = [
    "ClaimReview",
    "Downgrade",
    "Failure",
    "GateOutcome",
    "Precondition",
    "ReviewItem",
    "assumption_failures",
    "citations_for",
    "edge_failures",
    "location_failures",
    "ordered",
    "precondition_failures",
    "preconditions_for",
    "quotation_failures",
    "reason_for",
    "review_claims",
    "status_failure",
    "summarize",
    "unissued_ids",
    "verify",
]

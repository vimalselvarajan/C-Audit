"""Every claim an adjudication makes about the tree, extracted and resolved.

The gate's first clause is "every cited file, line, symbol, and call edge
resolves against the scanned revision", and this module is the part that turns
a proposal into that list of claims. Three things it does deliberately:

**It checks issuance before it checks the repository.** An id the context never
handed out is rejected without opening a file. The distinction matters for the
reason a reader is given: ``citation_unresolved`` says the handle names nothing
in the closed world the model was given, which is a different failure from a
region that has since changed, and points at a different fix.

**It resolves in a fixed order.** Citations are sorted by a total key before
anything is resolved, so shuffling ``cited_evidence_ids`` cannot change the
sequence of resolutions a run reports (AC-11-15).

**It compares quotations byte for byte.** No whitespace normalisation, no line
ending translation, no trimming. The hash is over exact bytes everywhere else
in this codebase and a quotation is not the place to start being lenient: a
dropped operator and a dropped space are the same edit to a comparison that
forgives either.
"""

from __future__ import annotations

from collections.abc import Sequence

from caudit.evidence.hashing import hash_bytes
from caudit.evidence.resolver import Citation, CitationResolver, Resolution
from caudit.index.store import Index
from caudit.model.adjudication import Adjudication
from caudit.model.finding import ReviewReason
from caudit.retrieval.context import EvidenceContext
from caudit.verify.reasons import Failure, reason_for

__all__ = [
    "citations_for",
    "edge_failures",
    "location_failures",
    "quotation_failures",
    "resolve",
    "unissued_ids",
]

#: Labels, so a resolution can be reported against what it was checking.
_CITED = "cited_evidence"
_LOCATION = "candidate_location"
_EDGE = "asserted_call_edge"


def unissued_ids(adjudication: Adjudication, context: EvidenceContext) -> list[str]:
    """Cited ids this candidate's context never issued, sorted.

    Part 10 already rejects these on the way out of the provider. Checked again
    here because that check protects one call path and this one protects the
    finding: an :class:`~caudit.model.adjudication.Adjudication` reaching the gate
    from a cache, a cassette, or a future batch runner has not necessarily
    passed through the loop that made the request.
    """
    issued = set(context.evidence_ids())
    return sorted({name for name in adjudication.cited_evidence_ids if name not in issued})


def citations_for(adjudication: Adjudication, context: EvidenceContext) -> list[Citation]:
    """Every checkable claim, in a stable order.

    The candidate's own location is included even though the model did not
    "cite" it: a finding is reported *at* that region, and a report whose
    location does not resolve is wrong in the one place a reader looks first.
    """
    claims: list[Citation] = [
        Citation.from_region(context.candidate.region, label=_LOCATION),
    ]
    for identifier in adjudication.cited_evidence_ids:
        item = context.bundle.get(identifier)
        if item is None:
            # Unissued ids are reported by unissued_ids(); resolving one here
            # would report the same fault twice under two different reasons.
            continue
        claims.append(
            Citation.from_evidence(
                identifier,
                symbol=item.symbol.name if item.symbol else None,
                label=_CITED,
            )
        )
    claims.extend(
        Citation(caller=edge.caller, callee=edge.callee, label=_EDGE)
        for edge in adjudication.asserted_call_edges
    )
    return sorted(claims, key=_order)


def _order(citation: Citation) -> tuple[str, str, str, str, int]:
    """Total order over claims. Ties are impossible, so shuffling is a no-op."""
    return (
        citation.label,
        citation.evidence_id or "",
        citation.caller or "",
        citation.callee or "",
        citation.start_line or 0,
    )


def resolve(citations: Sequence[Citation], resolver: CitationResolver) -> list[Resolution]:
    """Resolve every claim. Deterministic: same claims, same verdicts, same order."""
    return [resolver.resolve(citation) for citation in citations]


def location_failures(resolutions: Sequence[Resolution]) -> list[Failure]:
    """Every resolution that did not hold, as failures. All of them, not the first.

    Call-edge claims are excluded here and handled by :func:`edge_failures`, so
    that a caller can require an index-backed resolver for edges without
    requiring one for regions.
    """
    return [
        Failure(
            reason=reason_for(resolution),
            detail=resolution.detail,
            subject=resolution.citation.describe(),
        )
        for resolution in resolutions
        if not resolution.ok and resolution.citation.label != _EDGE
    ]


def edge_failures(
    resolutions: Sequence[Resolution], resolver: CitationResolver, index: Index
) -> list[Failure]:
    """Asserted call edges that did not hold, told apart by *why*.

    Two failures wear the same resolver status and are not the same fault. A
    function the index has never heard of is a fabricated name — the model
    invented ``validate_input`` — and reports as ``symbol_unresolved``. Two real
    functions with no recorded call between them is ``call_edge_unresolved``,
    and the wording is careful: the index recording no edge is not the claim
    that no call can happen, which is why the resolver's own detail is passed
    through rather than rewritten.

    A resolver that cannot check edges does not get to report that one holds.
    :attr:`~caudit.evidence.resolver.CitationResolver.verifies_call_edges` is
    false for part 03's resolver, and an unchecked edge is recorded as
    unverified rather than passed through as verified — the same rule the index
    applies to an indirect call.
    """
    edges = [resolution for resolution in resolutions if resolution.citation.label == _EDGE]
    if not edges:
        return []
    if not resolver.verifies_call_edges:
        return [
            Failure(
                reason=ReviewReason.CALL_EDGE_UNRESOLVED,
                detail=(
                    "this resolver has no call graph, so the asserted edge could not be "
                    "checked; an unverified edge is not a verified one"
                ),
                subject=_edge_subject(resolution),
            )
            for resolution in edges
        ]

    failures: list[Failure] = []
    for resolution in edges:
        if resolution.ok:
            continue
        missing = [
            name
            for name in (resolution.citation.caller, resolution.citation.callee)
            if name and not _known(index, name)
        ]
        if missing:
            failures.append(
                Failure(
                    reason=ReviewReason.SYMBOL_UNRESOLVED,
                    detail=(
                        f"the asserted call edge names {', '.join(repr(n) for n in missing)}, "
                        f"which the index does not know at revision {index.revision}"
                    ),
                    subject=_edge_subject(resolution),
                )
            )
            continue
        failures.append(
            Failure(
                reason=ReviewReason.CALL_EDGE_UNRESOLVED,
                detail=resolution.detail,
                subject=_edge_subject(resolution),
            )
        )
    return failures


def _edge_subject(resolution: Resolution) -> str:
    return f"{resolution.citation.caller} -> {resolution.citation.callee}"


def _known(index: Index, name: str) -> bool:
    """Does the index have this symbol, by USR or by name?

    Mirrors :meth:`~caudit.index.resolver.IndexResolver._lookup`, because a
    citation that names a symbol the way the resolver accepts must not be
    reported as fabricated by a laxer check here.
    """
    if name.startswith(_USR_PREFIX):
        return index.symbol(name) is not None
    return bool(index.symbols_named(name))


#: Clang USRs start with this. A citation naming one resolves by identity.
_USR_PREFIX = "c:"


def quotation_failures(adjudication: Adjudication, context: EvidenceContext) -> list[Failure]:
    """Quotations whose bytes do not occur in the region they name.

    Containment rather than equality: a region is a whole function and a
    quotation is usually one line of it, so requiring the two to be equal would
    make the field unusable for the thing it exists for. What is *not* relaxed
    is the comparison itself — the quoted bytes have to be present exactly,
    with the same spacing and the same operators.

    Compared against what the bundle captured rather than what is on disk now,
    for the same reason part 09's ``zoom`` reads from the bundle: the question
    is whether the model quoted the code it was shown, and re-reading the file
    would answer a different one.

    Both hashes go in the detail. "These do not match" is unactionable; the two
    digests plus the id let a reviewer pull the region and see the difference.
    """
    failures: list[Failure] = []
    for quote in sorted(adjudication.quoted_evidence, key=lambda q: (q.evidence_id, q.text)):
        try:
            captured = context.bundle.zoom(quote.evidence_id)
        except KeyError:
            failures.append(
                Failure(
                    reason=ReviewReason.CITATION_UNRESOLVED,
                    detail=(
                        f"the answer quotes evidence id {quote.evidence_id!r}, which this "
                        "candidate's context never issued"
                    ),
                    subject=quote.evidence_id,
                )
            )
            continue
        quoted = quote.text.encode("utf-8")
        if quoted in captured:
            continue
        failures.append(
            Failure(
                reason=ReviewReason.HASH_MISMATCH,
                detail=(
                    f"the quoted text does not occur in this region (quotation "
                    f"{hash_bytes(quoted)[:12]}…, region {hash_bytes(captured)[:12]}…); "
                    "quotations are compared exactly, including whitespace"
                ),
                subject=quote.evidence_id,
            )
        )
    return failures

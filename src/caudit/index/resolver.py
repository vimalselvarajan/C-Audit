"""Citation resolution, version 2: index-backed.

Version 1 (part 03) answers "does this identifier appear in these bytes?".
That is satisfied by a comment. The example the plan gives is exact: a claim
citing ``parse_header`` at a region containing only ``/* see parse_header */``
resolves as OK under v1, and a model that has learned to produce plausible
citations will produce exactly that.

This resolver answers a different question — "does the *index* place that
symbol at that region?" — using the same :class:`ResolutionStatus` values, so
part 11 branches on the status and never on which resolver ran.

It also verifies what v1 cannot represent at all: an asserted call edge. The
rejection wording matters there. "The index records no such edge" is not the
same claim as "no such call exists", and when unresolved indirect calls are in
the graph the detail says so, because a report that turned an unresolved edge
into a denial would be exactly the failure this part exists to prevent.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import Citation, CitationResolver, Resolution, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.index.symbols import Symbol
from caudit.model.source import SourceRegion, normalize_repo_path

__all__ = ["IndexResolver"]

#: Clang USRs start with this; a citation naming one is resolved by identity
#: rather than by name.
_USR_PREFIX = "c:"


class IndexResolver(CitationResolver):
    """A resolver that checks symbols and call edges against the index."""

    verifies_call_edges = True

    def __init__(self, store: SourceStore, bundle: EvidenceBundle, index: Index) -> None:
        super().__init__(store, bundle)
        self._index = index

    # ---------------------------------------------------------------- public

    def resolve(self, citation: Citation) -> Resolution:
        """Location, then symbol, then the asserted call edge.

        A citation that names only a call edge — no path, no evidence id — is
        resolved on the edge alone; every other citation must survive the
        location checks first, because an edge between two functions in a file
        that changed is not evidence of anything.
        """
        if citation.caller and citation.callee and not citation.path and not citation.evidence_id:
            return self._check_call_edge(citation) or _ok(
                citation,
                f"the index records {citation.caller} -> {citation.callee}",
            )
        resolution = super().resolve(citation)
        if not resolution.ok:
            return resolution
        if citation.caller and citation.callee:
            return self._check_call_edge(citation) or resolution
        return resolution

    def resolve_call_edge(self, caller: str, callee: str, label: str = "") -> Resolution:
        """Convenience for a bare edge assertion, with no location attached."""
        return self.resolve(Citation(caller=caller, callee=callee, label=label))

    # --------------------------------------------------------------- symbols

    def _check_symbol(self, citation: Citation, region: SourceRegion) -> Resolution | None:
        """The symbol must be *at* the region, not merely mentioned in it."""
        name = citation.symbol
        if not name:
            return None

        path = normalize_repo_path(str(citation.path or region.path))
        if not self._covers(path):
            return _not_found(
                citation,
                (
                    f"{path} is not in the index — it was not parsed, or its unit "
                    "failed to parse — so no symbol in it can be verified"
                ),
                observed=str(path),
            )

        matches = self._lookup(name)
        if not matches:
            return _not_found(
                citation,
                (
                    f"no symbol named {name!r} exists at revision "
                    f"{self._index.revision}; the index knows this file"
                ),
                observed=str(path),
            )

        here = [symbol for symbol in matches if _overlaps(symbol, region)]
        if here:
            return None
        return _not_found(
            citation,
            (
                f"{name!r} is not declared or defined at {region.describe()}; "
                f"the index places it at {_where(matches)}"
            ),
            observed=_where(matches),
        )

    # ------------------------------------------------------------ call edges

    def _check_call_edge(self, citation: Citation) -> Resolution | None:
        """``None`` when the index records the asserted edge."""
        caller_name = citation.caller or ""
        callee_name = citation.callee or ""
        callers = self._lookup(caller_name)
        callees = self._lookup(callee_name)
        if not callers:
            return _not_found(
                citation,
                f"the asserted call edge names {caller_name!r}, which is not in the index",
                observed=caller_name,
            )
        if not callees:
            return _not_found(
                citation,
                f"the asserted call edge names {callee_name!r}, which is not in the index",
                observed=callee_name,
            )
        for caller in callers:
            for callee in callees:
                if self._index.has_call_edge(caller.usr, callee.usr):
                    return None
        return _not_found(citation, self._missing_edge_detail(caller_name, callee_name, callers))

    def _missing_edge_detail(
        self, caller_name: str, callee_name: str, callers: list[Symbol]
    ) -> str:
        """Say that the edge is unrecorded — never that the call cannot happen."""
        detail = (
            f"the index records no call from {caller_name} to {callee_name} "
            f"at revision {self._index.revision}"
        )
        unresolved = sum(len(self._index.callees_of(caller.usr).unresolved) for caller in callers)
        if unresolved:
            return (
                f"{detail}; {caller_name} does make {unresolved} indirect call(s) whose "
                "target is unknown, so the edge is unverified rather than disproved"
            )
        return detail

    # --------------------------------------------------------------- helpers

    def _lookup(self, name: str) -> list[Symbol]:
        """By USR when it looks like one, else by name — overloads included."""
        if name.startswith(_USR_PREFIX):
            symbol = self._index.symbol(name)
            return [symbol] if symbol else []
        return self._index.symbols_named(name)

    def _covers(self, path: PurePosixPath) -> bool:
        """Does the index know this file at all?

        A header is never a translation unit of its own, so "was it parsed?" is
        the wrong question for one; "did any parsed unit see symbols in it?" is
        the right one.
        """
        return self._index.is_indexed(path) or bool(self._index.symbols_in(path))


def _overlaps(symbol: Symbol, region: SourceRegion) -> bool:
    """True when any of the symbol's regions shares a line with ``region``."""
    path = str(region.path)
    return any(
        str(known.path) == path
        and known.start_line <= region.end_line
        and known.end_line >= region.start_line
        for known in symbol.regions
    )


def _where(symbols: list[Symbol]) -> str:
    places = [region.describe() for symbol in symbols for region in symbol.regions]
    return ", ".join(places) if places else "nowhere with a region"


def _not_found(citation: Citation, detail: str, observed: str | None = None) -> Resolution:
    return Resolution(
        status=ResolutionStatus.SYMBOL_NOT_FOUND,
        citation=citation,
        detail=detail,
        observed=observed,
    )


def _ok(citation: Citation, detail: str) -> Resolution:
    return Resolution(status=ResolutionStatus.OK, citation=citation, detail=detail)

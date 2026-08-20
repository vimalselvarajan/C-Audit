"""Call, include, type, and macro graphs.

The one rule that shapes every type in this module: **unresolved is not the
same as absent.** A call through a function pointer is a real edge whose
target is unknown, and a report that treats it as "no edge" can say a
function is never called when in truth the caller was invisible. So an
unresolved call is stored as an edge with ``callee=None``, and the answer to
"who calls this?" is a :class:`CallQuery` that carries both what was found and
what could not be resolved — not a list that silently reads as complete.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from caudit.model.source import SourceRegion

__all__ = [
    "CallEdge",
    "CallGraph",
    "CallKind",
    "CallQuery",
    "IncludeEdge",
    "IncludeGraph",
    "MacroExpansion",
    "MacroTable",
    "ReferenceTable",
    "sort_edges",
]


class CallKind(StrEnum):
    """How control reaches the callee, which decides how much we can claim."""

    DIRECT = "direct"
    VIRTUAL = "virtual"
    FUNCTION_POINTER = "function_pointer"
    MACRO_EXPANDED = "macro_expanded"


class CallEdge(BaseModel):
    """One call site. ``callee`` is ``None`` when the target is unknown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: USR of the function containing the call site.
    caller: str = Field(min_length=1)
    #: USR of the callee, or ``None`` for an unresolved indirect call.
    callee: str | None = None
    site: SourceRegion
    kind: CallKind
    #: What the source wrote at the call site, kept even when the callee could
    #: not be resolved — ``handler`` says more to a reader than "unresolved".
    spelling: str | None = None
    #: True for an edge synthesized from a virtual override set rather than
    #: observed at the call site. The set is a best effort over the TUs that
    #: were parsed, which is why it comes with a limitation.
    inferred: bool = False

    @property
    def resolved(self) -> bool:
        return self.callee is not None

    def describe(self) -> str:
        target = self.callee or f"<unresolved {self.spelling or 'call'}>"
        return f"{self.caller} -> {target} at {self.site.describe()} ({self.kind})"


def sort_edges(edges: Iterable[CallEdge]) -> list[CallEdge]:
    """Total order over edges, so a serialized graph is byte-stable."""
    return sorted(
        edges,
        key=lambda edge: (
            edge.caller,
            edge.callee or "",
            str(edge.site.path),
            edge.site.start_line,
            edge.site.start_byte,
            str(edge.kind),
            edge.spelling or "",
            edge.inferred,
        ),
    )


@dataclass(frozen=True)
class CallQuery:
    """The answer to "who calls this?" — or "what does this call?".

    Deliberately not a list and deliberately without ``__len__`` or
    ``__bool__``: ``if not index.callers_of(usr):`` would read as "nothing
    calls it" while unresolved indirect calls sat in the same result. Callers
    must reach for :attr:`edges` or :attr:`is_complete`, which makes the
    handling of unresolved calls visible in review.
    """

    direction: Literal["callers", "callees"]
    target: str
    edges: tuple[CallEdge, ...] = ()
    #: Call sites whose target could not be resolved. For ``callers`` these are
    #: every unresolved site in the index: any of them could be this call, and
    #: a conservative answer is the only honest one.
    unresolved: tuple[CallEdge, ...] = ()

    @property
    def is_complete(self) -> bool:
        """True only when nothing could have been missed."""
        return not self.unresolved

    def __iter__(self) -> Iterator[CallEdge]:
        return iter(self.edges)

    def describe(self) -> str:
        if self.is_complete:
            return f"{len(self.edges)} {self.direction} of {self.target}"
        return (
            f"{len(self.edges)} known {self.direction} of {self.target}, "
            f"plus {len(self.unresolved)} unresolved indirect call site(s)"
        )


class CallGraph:
    """Call edges in both directions, with unresolved sites kept alongside."""

    def __init__(self, edges: Iterable[CallEdge] = ()) -> None:
        self._edges: list[CallEdge] = []
        self._out: dict[str, list[CallEdge]] = defaultdict(list)
        self._in: dict[str, list[CallEdge]] = defaultdict(list)
        self._unresolved: list[CallEdge] = []
        for edge in edges:
            self.add(edge)

    def add(self, edge: CallEdge) -> None:
        self._edges.append(edge)
        self._out[edge.caller].append(edge)
        if edge.callee is None:
            self._unresolved.append(edge)
        else:
            self._in[edge.callee].append(edge)

    def extend(self, edges: Iterable[CallEdge]) -> None:
        for edge in edges:
            self.add(edge)

    def edges(self) -> list[CallEdge]:
        """Every edge, in serialization order."""
        return sort_edges(self._edges)

    def unresolved_edges(self) -> list[CallEdge]:
        return sort_edges(self._unresolved)

    def callees_of(self, usr: str, depth: int = 1) -> CallQuery:
        """What ``usr`` calls, out to ``depth`` hops."""
        found, unresolved = self._walk(usr, depth, self._out, lambda edge: edge.callee)
        return CallQuery(
            direction="callees", target=usr, edges=tuple(found), unresolved=tuple(unresolved)
        )

    def callers_of(self, usr: str, depth: int = 1) -> CallQuery:
        """What calls ``usr``, out to ``depth`` hops.

        The unresolved set is every unresolved site in the index rather than
        only those reachable from ``usr``: an indirect call's target is by
        definition unknown, so none of them can be ruled out.
        """
        found, _ = self._walk(usr, depth, self._in, lambda edge: edge.caller)
        return CallQuery(
            direction="callers",
            target=usr,
            edges=tuple(found),
            unresolved=tuple(self.unresolved_edges()),
        )

    def _walk(
        self,
        usr: str,
        depth: int,
        adjacency: dict[str, list[CallEdge]],
        step: Callable[[CallEdge], str | None],
    ) -> tuple[list[CallEdge], list[CallEdge]]:
        """Breadth-first over ``depth`` hops, collecting edges as it goes."""
        if depth < 1:
            return [], []
        seen_nodes = {usr}
        frontier = [usr]
        collected: list[CallEdge] = []
        unresolved: list[CallEdge] = []
        for _ in range(depth):
            next_frontier: list[str] = []
            for node in frontier:
                for edge in adjacency.get(node, []):
                    if edge.callee is None:
                        unresolved.append(edge)
                        continue
                    collected.append(edge)
                    target = step(edge)
                    if target is not None and target not in seen_nodes:
                        seen_nodes.add(target)
                        next_frontier.append(target)
            frontier = next_frontier
            if not frontier:
                break
        return sort_edges(collected), sort_edges(unresolved)

    def has_edge(self, caller: str, callee: str) -> bool:
        """Exact edge existence. Used by the citation resolver, not by reports."""
        return any(edge.callee == callee for edge in self._out.get(caller, []))

    def __len__(self) -> int:
        return len(self._edges)


class MacroExpansion(BaseModel):
    """One use of a macro, with both regions the spec asks for.

    A macro that hides a bounds check is exactly the evidence that must not be
    lost, and reading it needs two places at once: where it was used and what
    it expands to.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    #: USR of the macro definition, normalized like every other USR.
    usr: str = Field(min_length=1)
    #: Where ``#define`` is.
    definition: SourceRegion
    #: Where the macro was used.
    expansion: SourceRegion

    def describe(self) -> str:
        return (
            f"{self.name} expanded at {self.expansion.describe()}, "
            f"defined at {self.definition.describe()}"
        )


class MacroTable:
    """Macro expansions, queryable by the region a candidate sits in."""

    def __init__(self, expansions: Iterable[MacroExpansion] = ()) -> None:
        self._expansions: list[MacroExpansion] = list(expansions)

    def add(self, expansion: MacroExpansion) -> None:
        self._expansions.append(expansion)

    def extend(self, expansions: Iterable[MacroExpansion]) -> None:
        self._expansions.extend(expansions)

    def all(self) -> list[MacroExpansion]:
        return sorted(
            set(self._expansions),
            key=lambda item: (
                str(item.expansion.path),
                item.expansion.start_line,
                item.expansion.start_byte,
                item.usr,
            ),
        )

    def expanded_in(self, region: SourceRegion) -> list[MacroExpansion]:
        """Every expansion overlapping ``region``, in source order."""
        path = str(region.path)
        return [
            item
            for item in self.all()
            if str(item.expansion.path) == path
            and item.expansion.start_line <= region.end_line
            and item.expansion.end_line >= region.start_line
        ]

    def named(self, name: str) -> list[MacroExpansion]:
        return [item for item in self.all() if item.name == name]

    def __len__(self) -> int:
        return len(self._expansions)


class IncludeEdge(BaseModel):
    """``includer`` includes ``included``, at a hashed directive line.

    The region is the ``#include`` line itself, so an include is citable
    evidence like everything else in the index rather than an unverifiable
    line number.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    includer: PurePosixPath
    #: Repository-relative when :attr:`in_repo`, otherwise the path Clang
    #: resolved — a system header we can name but never cite.
    included: str = Field(min_length=1)
    site: SourceRegion
    in_repo: bool

    @property
    def line(self) -> int:
        return self.site.start_line

    @property
    def repo_path(self) -> PurePosixPath | None:
        return PurePosixPath(self.included) if self.in_repo else None


class IncludeGraph:
    """Which file pulls in which. Headers outside the tree are kept, not hidden."""

    def __init__(self, edges: Iterable[IncludeEdge] = ()) -> None:
        self._edges: list[IncludeEdge] = list(edges)

    def add(self, edge: IncludeEdge) -> None:
        self._edges.append(edge)

    def extend(self, edges: Iterable[IncludeEdge]) -> None:
        self._edges.extend(edges)

    def all(self) -> list[IncludeEdge]:
        return sorted(
            set(self._edges),
            key=lambda edge: (str(edge.includer), edge.site.start_line, edge.included),
        )

    def includes(self, path: PurePosixPath | str) -> list[PurePosixPath]:
        """In-repository headers included by ``path``, deduplicated."""
        wanted = str(path)
        seen: dict[str, PurePosixPath] = {}
        for edge in self.all():
            if str(edge.includer) == wanted and edge.in_repo:
                seen.setdefault(edge.included, PurePosixPath(edge.included))
        return [seen[key] for key in sorted(seen)]

    def external_includes(self, path: PurePosixPath | str) -> list[str]:
        """Headers outside the tree — nothing in them can be cited."""
        wanted = str(path)
        return sorted(
            {
                edge.included
                for edge in self.all()
                if str(edge.includer) == wanted and not edge.in_repo
            }
        )

    def included_by(self, path: PurePosixPath | str) -> list[PurePosixPath]:
        wanted = str(path)
        return sorted(
            {edge.includer for edge in self.all() if edge.in_repo and edge.included == wanted},
            key=str,
        )

    def __len__(self) -> int:
        return len(self._edges)


class ReferenceTable:
    """Which symbols each symbol's signature and body mention, keyed by USR.

    Two instances are kept per index and never mixed: one for the types a
    symbol names, one for the file-scope variables it touches. They are the
    same shape and deliberately the same class, but a caller asking for types
    must not receive a global — part 09 pulls the two in at different
    :class:`~caudit.retrieval.policy.UnitClass` levels, and conflating them
    would put a global's declaration where a struct layout belongs.
    """

    def __init__(self, pairs: Iterable[tuple[str, str]] = ()) -> None:
        self._by_symbol: dict[str, set[str]] = defaultdict(set)
        for symbol_usr, type_usr in pairs:
            self.add(symbol_usr, type_usr)

    def add(self, symbol_usr: str, type_usr: str) -> None:
        self._by_symbol[symbol_usr].add(type_usr)

    def merge(self, other: ReferenceTable) -> None:
        for symbol_usr, types in other.items():
            for type_usr in types:
                self.add(symbol_usr, type_usr)

    def of(self, symbol_usr: str) -> list[str]:
        return sorted(self._by_symbol.get(symbol_usr, set()))

    def items(self) -> list[tuple[str, list[str]]]:
        return [(usr, sorted(self._by_symbol[usr])) for usr in sorted(self._by_symbol)]

    def pairs(self) -> list[tuple[str, str]]:
        """Flat, sorted form — what the serialized index stores."""
        return [(usr, type_usr) for usr, types in self.items() for type_usr in types]

    def __len__(self) -> int:
        return len(self._by_symbol)

"""Callers, callees, and the error paths that were supposed to clean up.

Two different kinds of retrieval live here, and they answer two different
questions.

*Callers and callees* answer "where does this value come from, and where does
it go?". Each one is pulled in as a complete function, never as the call site
alone, because a caller that merely proves a call happened does not show
whether the argument it passed was checked.

*Cleanup paths* answer "was the release supposed to happen somewhere I am not
looking?". For a leak or a use-after-free the decisive code is often the
`goto cleanup` block at the bottom of the function and the `free` on the error
branch — bytes the containing function already carries, but which nothing in
the context would otherwise point at. Naming them as their own units makes them
addressable: a claim can cite the exact line the release did or did not happen
on, which is what the evidence gate checks later.

The release lexicon below decides what extra code to show and how to rank it.
It never decides what to report.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

from caudit.errors import RegionError
from caudit.index.store import Index
from caudit.index.symbols import Symbol as IndexSymbol
from caudit.model.finding import Limitation, LimitationKind
from caudit.model.source import SourceRegion
from caudit.retrieval.budget import UnitFactory
from caudit.retrieval.closure import best_region
from caudit.retrieval.context import ContextUnit, on_flow_path
from caudit.retrieval.policy import ExpansionPolicy, UnitRole

__all__ = [
    "CALLEE_LOWER_BOUND",
    "PathResult",
    "callee_units",
    "caller_units",
    "cleanup_units",
    "flow_units",
]

Direction = Literal["callers", "callees"]

#: Functions whose name says a resource is being given back. Deliberately
#: short: a wrong entry costs a few tokens of extra context, a missing one
#: costs nothing at all, since the containing function is present whole either
#: way. Nothing here is evidence of anything.
_RELEASE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "free",
        "cfree",
        "kfree",
        "vfree",
        "g_free",
        "xfree",
        "delete",
        "fclose",
        "close",
        "closedir",
        "munmap",
        "unlink",
        "pthread_mutex_unlock",
        "pthread_rwlock_unlock",
        "pthread_spin_unlock",
        "mtx_unlock",
        "sem_post",
        "fflush",
    }
)

_RELEASE_SUFFIXES: Final[tuple[str, ...]] = (
    "_free",
    "_release",
    "_destroy",
    "_close",
    "_unlock",
    "_delete",
    "_dispose",
    "_put",
)

_RELEASE_PREFIXES: Final[tuple[str, ...]] = (
    "free_",
    "release_",
    "destroy_",
    "close_",
    "unlock_",
)

_GOTO = re.compile(r"\bgoto\s+([A-Za-z_]\w*)\s*;")
#: A label at the start of a line. The negative lookahead keeps C++'s ``::``
#: and a ternary's ``:`` out of it.
_LABEL = re.compile(r"^\s*([A-Za-z_]\w*)\s*:(?!:|=)")


def is_release_call(name: str | None) -> bool:
    """Whether a called name reads as giving a resource back."""
    if not name:
        return False
    lowered = name.lower()
    return (
        lowered in _RELEASE_NAMES
        or lowered.endswith(_RELEASE_SUFFIXES)
        or lowered.startswith(_RELEASE_PREFIXES)
    )


@dataclass(frozen=True)
class PathResult:
    """Units retrieved along the call graph, plus what the graph could not see."""

    units: tuple[ContextUnit, ...]
    limitations: tuple[Limitation, ...] = ()


# ----------------------------------------------------------------- flow units


def flow_units(
    containing_usr: str | None,
    flow: Sequence[SourceRegion],
    *,
    index: Index,
    factory: UnitFactory,
) -> PathResult:
    """Complete functions for every step of the analyzer's reported path.

    A source-to-sink diagnostic that crosses three functions needs all three
    whole (AC-09-1, T-09-18). They are ``PRIMARY``: the path *is* the argument
    the analyzer made, and dropping a link in it to save tokens would leave a
    claim whose middle is missing.
    """
    units: list[ContextUnit] = []
    seen: set[str] = set()
    for step in flow:
        symbol = index.enclosing_function(step.path, step.start_line)
        if symbol is None or symbol.usr == containing_usr or symbol.usr in seen:
            continue
        seen.add(symbol.usr)
        region = symbol.definition
        if region is None:  # pragma: no cover - enclosing_function requires one
            continue
        unit = factory.build(
            region,
            role=UnitRole.FLOW_FUNCTION,
            symbol=symbol.as_model_symbol(),
            depth=1,
            on_dataflow_path=True,
        )
        if unit is not None:
            units.append(unit)
    return PathResult(units=tuple(units))


# -------------------------------------------------------- callers and callees


def caller_units(
    symbol: IndexSymbol,
    *,
    index: Index,
    factory: UnitFactory,
    policy: ExpansionPolicy,
    flow: Sequence[SourceRegion] = (),
) -> PathResult:
    """Functions that call this one, to ``policy.caller_depth``."""
    return _walk(
        symbol,
        direction="callers",
        role=UnitRole.CALLER,
        depth_limit=policy.caller_depth,
        index=index,
        factory=factory,
        flow=flow,
    )


def callee_units(
    symbol: IndexSymbol,
    *,
    index: Index,
    factory: UnitFactory,
    policy: ExpansionPolicy,
    flow: Sequence[SourceRegion] = (),
) -> PathResult:
    """Functions this one calls, to ``policy.callee_depth``."""
    return _walk(
        symbol,
        direction="callees",
        role=UnitRole.CALLEE,
        depth_limit=policy.callee_depth,
        index=index,
        factory=factory,
        flow=flow,
    )


def _walk(
    symbol: IndexSymbol,
    *,
    direction: Direction,
    role: UnitRole,
    depth_limit: int,
    index: Index,
    factory: UnitFactory,
    flow: Sequence[SourceRegion],
) -> PathResult:
    """Breadth-first one hop at a time, so each function knows its distance.

    Asking the index for ``depth`` hops in one call would return a flat edge
    set with no way to tell a direct caller from a distant one, and distance is
    the ranking signal that decides which callers survive a binding budget.
    """
    units: list[ContextUnit] = []
    limitations: list[Limitation] = []
    seen = {symbol.usr}
    frontier = [symbol.usr]
    incomplete = False

    for hop in range(1, depth_limit + 1):
        next_frontier: list[str] = []
        for usr in frontier:
            query = index.callers_of(usr, 1) if direction == "callers" else index.callees_of(usr, 1)
            if not query.is_complete:
                incomplete = True
            for edge in query.edges:
                other = edge.caller if direction == "callers" else edge.callee
                if other is None or other in seen:
                    continue
                seen.add(other)
                next_frontier.append(other)
        frontier = sorted(next_frontier)
        for usr in frontier:
            unit, gap = _function_unit(
                usr, role=role, depth=hop, index=index, factory=factory, flow=flow
            )
            if unit is not None:
                units.append(unit)
            if gap is not None:
                limitations.append(gap)
        if not frontier:
            break

    if incomplete:
        limitations.append(_incomplete_call_set(symbol, direction))
    return PathResult(units=tuple(units), limitations=tuple(limitations))


def _function_unit(
    usr: str,
    *,
    role: UnitRole,
    depth: int,
    index: Index,
    factory: UnitFactory,
    flow: Sequence[SourceRegion],
) -> tuple[ContextUnit | None, Limitation | None]:
    """A complete function, or a limitation saying why there is not one.

    A USR the index cannot resolve to a symbol is a function outside the tree —
    ``strcpy`` and friends. That is not a gap in this run's knowledge, it is
    the boundary of the repository, and part 06 already records the external
    includes, so it produces no limitation of its own.
    """
    symbol = index.symbol(usr)
    if symbol is None:
        return None, None
    if symbol.definition is None:
        declared = best_region(symbol)
        return None, Limitation(
            kind=LimitationKind.NO_EVIDENCE_EXPANSION,
            detail=(
                f"{symbol.name} is declared at revision {index.revision} but no parsed "
                "translation unit contained its body, so it is named in the call graph "
                "and absent from the context"
            ),
            affects=str(declared.path) if declared is not None else symbol.name,
        )
    unit = factory.build(
        symbol.definition,
        role=role,
        symbol=symbol.as_model_symbol(),
        depth=depth,
        on_dataflow_path=on_flow_path(symbol.definition, flow),
    )
    return unit, None


def _incomplete_call_set(symbol: IndexSymbol, direction: Direction) -> Limitation:
    """Say the set is a lower bound. Never that it is the whole set."""
    if direction == "callers":
        detail = (
            f"the callers of {symbol.name} retrieved here are the ones the index could "
            "resolve; the run also recorded call sites whose target is not known "
            "statically, any of which could reach this function, so the caller set is a "
            "lower bound"
        )
    else:
        detail = (
            f"{symbol.name} makes at least one call whose target is not known "
            f"statically, so the callees retrieved here are a lower bound and "
            f"{CALLEE_LOWER_BOUND}"
        )
    return Limitation(
        kind=LimitationKind.UNRESOLVED_INDIRECT_CALL,
        detail=detail,
        affects=f"{symbol.definition.path}::{symbol.name}" if symbol.definition else symbol.name,
    )


#: The phrase that marks a limitation as the *callee* direction of an
#: incomplete call set. Both directions carry
#: :attr:`~caudit.model.finding.LimitationKind.UNRESOLVED_INDIRECT_CALL`, and
#: only this one means "traversal could not follow a function pointer".
#:
#: Named rather than matched as a literal because the ablation counts these,
#: and the two directions are worth counting apart: ``callers_of`` reports the
#: whole index's unresolved set, so on a real C codebase its limitation is
#: attached to essentially every candidate and distinguishes nothing.
#: T-09-25 asserts the marker still appears where the counter expects it.
CALLEE_LOWER_BOUND: Final = "code reached through a function pointer is not on the page"


# --------------------------------------------------------------- cleanup paths


def cleanup_units(
    symbol: IndexSymbol,
    region: SourceRegion,
    *,
    index: Index,
    factory: UnitFactory,
    flow: Sequence[SourceRegion] = (),
) -> PathResult:
    """The error path: cleanup labels, release call sites, release bodies."""
    units: list[ContextUnit] = []
    units.extend(_label_blocks(region, factory=factory, flow=flow))
    units.extend(_release_sites(symbol, region, index=index, factory=factory, flow=flow))
    return PathResult(units=tuple(units))


def _label_blocks(
    region: SourceRegion, *, factory: UnitFactory, flow: Sequence[SourceRegion]
) -> list[ContextUnit]:
    """The block each ``goto`` in this function jumps to.

    Read out of the function's own bytes rather than the index, because Clang
    exposes labels as statements inside a body and part 06 records symbols, not
    statements. This is a scan of code that is already present and already
    hashed — it locates a line, it does not assert anything about one — so the
    usual objection to matching text does not apply.
    """
    try:
        text = factory.store.decode_for_display(factory.store.read_region(region))
    except RegionError:  # pragma: no cover - the caller already read this region
        return []

    lines = text.split("\n")
    targets = set(_GOTO.findall(text))
    if not targets:
        return []

    units: list[ContextUnit] = []
    for offset, line in enumerate(lines):
        match = _LABEL.match(line)
        if match is None or match.group(1) not in targets:
            continue
        start = region.start_line + offset
        if start >= region.end_line:
            continue
        try:
            block = factory.store.make_region(region.path, start, region.end_line)
        except (RegionError, ValueError):  # pragma: no cover - bounds already checked
            continue
        unit = factory.build(
            block, role=UnitRole.CLEANUP_PATH, on_dataflow_path=on_flow_path(block, flow)
        )
        if unit is not None:
            units.append(unit)
    return units


def _release_sites(
    symbol: IndexSymbol,
    region: SourceRegion,
    *,
    index: Index,
    factory: UnitFactory,
    flow: Sequence[SourceRegion],
) -> list[ContextUnit]:
    """Every call inside the function that reads as giving a resource back.

    Both the site and, when the callee lives in this repository, its body: a
    project's ``buffer_release`` may or may not actually free, and that is the
    fact a leak claim turns on.
    """
    units: list[ContextUnit] = []
    seen_bodies: set[str] = set()
    for edge in index.callees_of(symbol.usr, 1).edges:
        if not _inside(edge.site, region):
            continue
        callee = index.symbol(edge.callee) if edge.callee else None
        name = edge.spelling or (callee.name if callee else None)
        if not is_release_call(name):
            continue
        site = factory.build(
            edge.site, role=UnitRole.CLEANUP_PATH, on_dataflow_path=on_flow_path(edge.site, flow)
        )
        if site is not None:
            units.append(site)
        if callee is None or callee.definition is None or callee.usr in seen_bodies:
            continue
        seen_bodies.add(callee.usr)
        body = factory.build(
            callee.definition,
            role=UnitRole.CLEANUP_PATH,
            symbol=callee.as_model_symbol(),
            depth=1,
            on_dataflow_path=on_flow_path(callee.definition, flow),
        )
        if body is not None:
            units.append(body)
    return units


def _inside(site: SourceRegion, region: SourceRegion) -> bool:
    return (
        str(site.path) == str(region.path)
        and region.start_line <= site.start_line
        and site.end_line <= region.end_line
    )

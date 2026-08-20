"""Dependency closure: the definitions without which the code lies.

A function body is not self-describing. `if (len < MAX)` is a bounds check or
it is not, depending on a `#define` in a header; `p->count` is in range or it
is not, depending on a struct layout three files away. The spec is blunt about
this — omitting the macro that hides a bounds check changes the verdict — so
closure is computed, not sampled: every type, typedef, macro, and file-scope
variable the *index* attributes to the primary function is retrieved, and what
could not be retrieved is named.

"Complete" is therefore a claim about the index, not about the universe. A
type declared in a system header was never parsed and cannot be cited; that is
recorded as an external include by part 06 and is not something this module can
close over. What it does guarantee is that nothing the index knew about was
quietly left out.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from caudit.index.store import Index
from caudit.index.symbols import Symbol as IndexSymbol
from caudit.model.source import SourceRegion
from caudit.retrieval.budget import UnitFactory
from caudit.retrieval.context import ContextUnit, on_flow_path
from caudit.retrieval.policy import ExpansionPolicy, UnitRole

__all__ = ["ClosureResult", "best_region", "close_over"]


def best_region(symbol: IndexSymbol) -> SourceRegion | None:
    """The definition if this run saw one, else the first declaration.

    A declaration is enough for a global — the plan's expansion order asks for
    *declarations* of the globals a function touches — and in C a file-scope
    ``int counter;`` is a tentative definition that Clang reports as a
    declaration, so insisting on a definition would lose the common case.
    """
    if symbol.definition is not None:
        return symbol.definition
    return symbol.declarations[0] if symbol.declarations else None


@dataclass(frozen=True)
class ClosureResult:
    """What the closure retrieved, and whether it is whole."""

    units: tuple[ContextUnit, ...]
    #: False when anything the index named could not be turned into a unit.
    complete: bool
    #: One line per gap, in the wording a report shows.
    missing: tuple[str, ...]

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(unit.evidence_id for unit in self.units)


def close_over(
    symbol: IndexSymbol,
    region: SourceRegion,
    *,
    index: Index,
    factory: UnitFactory,
    policy: ExpansionPolicy,
    flow: Sequence[SourceRegion] = (),
) -> ClosureResult:
    """Types, macros, and globals for one primary function.

    ``region`` is the function's own extent: macro expansions are found by
    where they were *used*, not by what the symbol table says the function
    mentions, because a macro that expands to nothing still hides whatever the
    reader expected to be there.

    Types are closed over first because they seed the macro pass. A struct
    whose field is declared ``char buf[BUF_LEN]`` puts the constant that sizes
    the buffer inside the *type*, not inside the function, and a closure that
    stopped at the function body would hand a reader a bound with no value.
    """
    units: list[ContextUnit] = []
    missing: list[str] = []

    types = _types(symbol, index=index, factory=factory, policy=policy, flow=flow, gaps=missing)
    units.extend(types)
    units.extend(
        _macros(
            [region, *(unit.region for unit in types)],
            index=index,
            factory=factory,
            flow=flow,
            gaps=missing,
        )
    )
    if policy.include_global_decls:
        units.extend(_globals(symbol, index=index, factory=factory, flow=flow, gaps=missing))

    return ClosureResult(units=tuple(units), complete=not missing, missing=tuple(missing))


# ------------------------------------------------------------------------ types


def _types(
    symbol: IndexSymbol,
    *,
    index: Index,
    factory: UnitFactory,
    policy: ExpansionPolicy,
    flow: Sequence[SourceRegion],
    gaps: list[str],
) -> list[ContextUnit]:
    """Breadth-first over the types a function names, then the types those name.

    Sorted at every hop and guarded by a visited set, so the result does not
    depend on the order the index happened to iterate (AC-09-12) and a struct
    that contains a pointer to itself does not run forever.
    """
    units: list[ContextUnit] = []
    seen = {symbol.usr}
    frontier = [symbol.usr]
    for hop in range(1, policy.type_closure_depth + 1):
        next_frontier: list[str] = []
        for usr in frontier:
            for referenced in index.types_referenced_by(usr):
                if referenced.usr in seen:
                    continue
                seen.add(referenced.usr)
                next_frontier.append(referenced.usr)
                unit = _unit_for(
                    referenced,
                    role=UnitRole.TYPE_DECL,
                    depth=hop,
                    factory=factory,
                    flow=flow,
                    gaps=gaps,
                )
                if unit is not None:
                    units.append(unit)
        frontier = sorted(next_frontier)
        if not frontier:
            break
    return units


# ----------------------------------------------------------------------- macros


def _macros(
    seeds: Sequence[SourceRegion],
    *,
    index: Index,
    factory: UnitFactory,
    flow: Sequence[SourceRegion],
    gaps: list[str],
) -> list[ContextUnit]:
    """Macros expanded in any retrieved region, and the macros *those* expand.

    Transitive, because one ``#define`` standing on another is the usual shape:
    ``CHECK_LEN(n)`` reads as a bounds check only once ``BUF_LEN`` is on the
    page too, and a closure that stopped at the first hop would deliver the
    guard without the number it guards against.
    """
    units: list[ContextUnit] = []
    seen: set[str] = set()
    pending = list(seeds)
    while pending:
        current = pending.pop(0)
        for expansion in index.macros_expanded_in(current):
            if expansion.usr in seen:
                continue
            seen.add(expansion.usr)
            unit = factory.build(
                expansion.definition,
                role=UnitRole.MACRO_DEF,
                depth=1,
                on_dataflow_path=on_flow_path(expansion.definition, flow),
            )
            if unit is None:
                gaps.append(
                    f"the definition of macro {expansion.name}, expanded at "
                    f"{expansion.expansion.describe()}, could not be read"
                )
                continue
            units.append(unit)
            pending.append(expansion.definition)
    return units


# ---------------------------------------------------------------------- globals


def _globals(
    symbol: IndexSymbol,
    *,
    index: Index,
    factory: UnitFactory,
    flow: Sequence[SourceRegion],
    gaps: list[str],
) -> list[ContextUnit]:
    """Declarations of the file-scope variables the function reads or writes."""
    units: list[ContextUnit] = []
    for referenced in index.globals_referenced_by(symbol.usr):
        unit = _unit_for(
            referenced,
            role=UnitRole.GLOBAL_DECL,
            depth=1,
            factory=factory,
            flow=flow,
            gaps=gaps,
        )
        if unit is not None:
            units.append(unit)
    return units


# ---------------------------------------------------------------------- helpers


def _unit_for(
    symbol: IndexSymbol,
    *,
    role: UnitRole,
    depth: int,
    factory: UnitFactory,
    flow: Sequence[SourceRegion],
    gaps: list[str],
) -> ContextUnit | None:
    region = best_region(symbol)
    if region is None:
        gaps.append(
            f"{symbol.name} is referenced but this run saw neither its definition "
            "nor a declaration, so it has no region to cite"
        )
        return None
    unit = factory.build(
        region,
        role=role,
        symbol=symbol.as_model_symbol(),
        depth=depth,
        on_dataflow_path=on_flow_path(region, flow),
    )
    if unit is None:
        gaps.append(f"{symbol.name} at {region.describe()} could not be read")
    return unit

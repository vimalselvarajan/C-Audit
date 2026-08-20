"""Budgeted evidence expansion (part 09).

:func:`expand` turns one analyzer candidate into the code an auditor would
actually need to judge it: the whole containing function, the types and macros
it depends on, the callers that supply its inputs, the cleanup paths that
should have run — inside a token budget, and without ever damaging the code
that decides the answer.

The order of operations matters and is not an implementation detail. Every
region is read, hash-checked, and captured in the bundle **before** the budget
looks at anything. Selection then decides only what appears on the page, so a
unit that was dropped is still addressable, still hashed, and still
recoverable through :func:`~caudit.retrieval.context.zoom`. That is what makes
the compression reversible in the sense the spec requires, and it is why
nothing in this package ever narrows a region to make it fit.
"""

from __future__ import annotations

from collections.abc import Sequence

from caudit.config.loader import TokenBudget
from caudit.errors import RegionError
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.index.symbols import Symbol as IndexSymbol
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceKind, Producer, Provenance
from caudit.model.finding import Limitation, LimitationKind, ReviewReason
from caudit.model.source import SourceRegion
from caudit.retrieval.budget import (
    DEFAULT_TOKENIZER,
    HeuristicTokenizer,
    RunLedger,
    Selection,
    Tokenizer,
    UnitFactory,
    select,
)
from caudit.retrieval.closure import ClosureResult, close_over
from caudit.retrieval.context import (
    ContextUnit,
    DroppedUnit,
    DropReason,
    EvidenceContext,
    context_limitations,
    sort_units,
    zoom,
)
from caudit.retrieval.paths import (
    callee_units,
    caller_units,
    cleanup_units,
    flow_units,
)
from caudit.retrieval.policy import (
    DEFAULT_POLICY,
    ExpansionPolicy,
    RetrievalVariant,
    UnitClass,
    UnitRole,
)

__all__ = [
    "DEFAULT_POLICY",
    "DEFAULT_TOKENIZER",
    "ClosureResult",
    "ContextUnit",
    "DropReason",
    "DroppedUnit",
    "EvidenceContext",
    "ExpansionPolicy",
    "HeuristicTokenizer",
    "RetrievalVariant",
    "RunLedger",
    "Selection",
    "Tokenizer",
    "UnitClass",
    "UnitFactory",
    "UnitRole",
    "expand",
    "zoom",
]


def expand(
    candidate: Candidate,
    index: Index,
    store: SourceStore,
    policy: ExpansionPolicy = DEFAULT_POLICY,
    budget: TokenBudget | None = None,
    *,
    tokenizer: Tokenizer = DEFAULT_TOKENIZER,
    allowance: int | None = None,
) -> EvidenceContext:
    """Assemble everything one candidate's adjudication may look at.

    ``allowance`` overrides ``budget.per_candidate`` for this candidate, which
    is how a :class:`~caudit.retrieval.budget.RunLedger` hands out the tail of
    a run budget without changing configuration.

    Returns a context in every case. When the primary set alone does not fit,
    the context is empty and carries
    ``review_reason=context_budget_exceeded`` — the candidate is reported as
    needing review rather than adjudicated on a fragment.
    """
    limits = budget or TokenBudget()
    ceiling = limits.per_candidate if allowance is None else max(0, allowance)

    bundle = EvidenceBundle(store)
    factory = UnitFactory(
        store=store,
        bundle=bundle,
        provenance=[
            Provenance(
                producer=Producer.INDEX,
                tool_name="libclang",
                tool_version=index.libclang or "unknown",
                detail=f"retrieval policy v{policy.version}",
            )
        ],
        tokenizer=tokenizer,
    )

    flow = _flow_regions(candidate)
    gaps = _capture(candidate, bundle)
    limitations: list[Limitation] = []
    units: list[ContextUnit] = []

    if policy.variant is RetrievalVariant.FLAT_WINDOW:
        # The ablation control. No index is consulted, on purpose: this is the
        # thing structural retrieval has to beat, and helping it with the very
        # machinery under test would make the comparison meaningless.
        units.extend(_flat_window(candidate, store, factory, policy, limitations))
    else:
        symbol, primary_region = _containing(candidate, index)
        if symbol is not None and primary_region is not None:
            units.extend(
                _from_function(symbol, primary_region, index, factory, policy, flow, limitations)
            )
        elif primary_region is not None:
            # A region the candidate could prove but the index cannot attribute
            # to a function: it is retrieved whole and nothing is expanded
            # around it.
            unit = factory.build(primary_region, role=UnitRole.CONTAINING_FUNCTION)
            if unit is not None:
                units.append(unit)
            limitations.append(_no_expansion(candidate.region))
        else:
            unit = factory.build(candidate.region, role=UnitRole.CANDIDATE_SITE)
            if unit is not None:
                units.append(unit)
            limitations.append(_no_expansion(candidate.region))

        units.extend(
            flow_units(symbol.usr if symbol else None, flow, index=index, factory=factory).units
        )

    # The analyzer's own messages are not retrieval — they arrive with the
    # candidate — so both variants carry them. Withholding them from the
    # control would measure the diagnostic as well as the retrieval.
    units.extend(_analyzer_messages(candidate, factory))

    ordered = _dedupe(units)
    selection = select(ordered, budget=ceiling, max_units=policy.max_units)

    limitations.extend(factory.gaps())
    limitations.extend(
        Limitation(
            kind=LimitationKind.NO_EVIDENCE_EXPANSION,
            detail=detail,
            affects=str(candidate.region.path),
        )
        for detail in gaps
    )
    return EvidenceContext(
        candidate=candidate,
        policy_version=policy.version,
        budget_tokens=ceiling,
        units=list(selection.kept),
        dropped=list(selection.dropped),
        limitations=context_limitations(selection.dropped, limitations),
        total_tokens=selection.total_tokens,
        review_reason=(
            ReviewReason.CONTEXT_BUDGET_EXCEEDED if selection.primaries_exceed_budget else None
        ),
        bundle=bundle,
    )


# --------------------------------------------------------------------- helpers


def _containing(
    candidate: Candidate, index: Index
) -> tuple[IndexSymbol | None, SourceRegion | None]:
    """The function containing the candidate, preferring the compiler's answer.

    The index is asked first because it knows where a body actually begins and
    ends. ``candidate.enclosing_region`` is the fallback for a unit the index
    does not cover — part 07 only sets it when something could prove it — and
    the two are never blended.
    """
    symbol = index.enclosing_function(candidate.region.path, candidate.region.start_line)
    if symbol is not None and symbol.definition is not None:
        return symbol, symbol.definition
    return None, candidate.enclosing_region


def _from_function(
    symbol: IndexSymbol,
    region: SourceRegion,
    index: Index,
    factory: UnitFactory,
    policy: ExpansionPolicy,
    flow: Sequence[SourceRegion],
    limitations: list[Limitation],
) -> list[ContextUnit]:
    """The containing function, its closure, and everything around it."""
    units: list[ContextUnit] = []
    whole = factory.build(
        region,
        role=UnitRole.CONTAINING_FUNCTION,
        symbol=symbol.as_model_symbol(),
        on_dataflow_path=True,
    )
    if whole is not None:
        units.append(whole)

    closure = close_over(symbol, region, index=index, factory=factory, policy=policy, flow=flow)
    units.extend(closure.units)
    if not closure.complete:
        limitations.append(
            Limitation(
                kind=LimitationKind.NO_EVIDENCE_EXPANSION,
                detail=(
                    f"the dependency closure of {symbol.name} is incomplete: "
                    + "; ".join(closure.missing)
                    + ". A definition that is not on the page cannot be read as absent"
                ),
                affects=f"{region.path}::{symbol.name}",
            )
        )

    callers = caller_units(symbol, index=index, factory=factory, policy=policy, flow=flow)
    callees = callee_units(symbol, index=index, factory=factory, policy=policy, flow=flow)
    units.extend(callers.units)
    units.extend(callees.units)
    limitations.extend(callers.limitations)
    limitations.extend(callees.limitations)

    if policy.include_cleanup_paths:
        cleanup = cleanup_units(symbol, region, index=index, factory=factory, flow=flow)
        units.extend(cleanup.units)
        limitations.extend(cleanup.limitations)
    return units


def _flat_window(
    candidate: Candidate,
    store: SourceStore,
    factory: UnitFactory,
    policy: ExpansionPolicy,
    limitations: list[Limitation],
) -> list[ContextUnit]:
    """The control: ``flat_window_lines`` either side of the diagnostic.

    Everything this project argues for is absent by design — no containing
    function, no types, no macros, no callers, no cleanup paths — and the
    window is free to begin and end mid-statement. That is the point: if a
    model does as well on this as on a structural context, parts 06 and 09 are
    complexity nobody is paying for.

    The limitation is not decoration. A downstream reader cannot tell a
    fragment from a whole function by looking at bytes, and part 11 will judge
    a claim against whatever it was shown, so the context says plainly what
    kind of thing it is carrying.
    """
    region = candidate.region
    reach = policy.flat_window_lines
    try:
        lines = store.line_count(region.path)
        start = max(1, region.start_line - reach)
        end = min(lines, region.end_line + reach)
        window = store.make_region(region.path, start, end)
    except (RegionError, OSError) as exc:
        limitations.append(
            Limitation(
                kind=LimitationKind.NO_EVIDENCE_EXPANSION,
                detail=(
                    f"the flat-window control could not read {reach} lines around "
                    f"{region.describe()}: {exc}"
                ),
                affects=str(region.path),
            )
        )
        return []

    limitations.append(
        Limitation(
            kind=LimitationKind.NO_EVIDENCE_EXPANSION,
            detail=(
                f"retrieval variant 'flat_window' (ablation control): lines "
                f"{window.start_line}-{window.end_line} of {window.path} were taken as a "
                f"fixed window around the diagnostic, with no index consulted. The window "
                f"may begin or end inside a function, and no types, macros, callers, "
                f"callees or cleanup paths were retrieved. This is a measurement "
                f"configuration, not a scanning one"
            ),
            affects=str(region.path),
        )
    )
    unit = factory.build(window, role=UnitRole.FLAT_WINDOW, on_dataflow_path=True)
    return [unit] if unit is not None else []


def _flow_regions(candidate: Candidate) -> list[SourceRegion]:
    """The analyzer's reported path, in the order it walked it."""
    return [
        item.region for item in candidate.evidence if item.kind is EvidenceKind.CONTROL_FLOW_STEP
    ]


def _capture(candidate: Candidate, bundle: EvidenceBundle) -> list[str]:
    """Put the candidate's own evidence in the bundle so it stays citable.

    Those items were produced by an analyzer rather than by retrieval, but they
    are part of what the adjudicating model is shown, so a claim must be able
    to cite them and :func:`zoom` must be able to expand them.
    """
    gaps: list[str] = []
    for item in candidate.evidence:
        try:
            bundle.add(item)
        except Exception as exc:
            gaps.append(
                f"the analyzer cited {item.region.describe()}, which could not be read "
                f"at this revision: {exc}"
            )
    return gaps


def _analyzer_messages(candidate: Candidate, factory: UnitFactory) -> list[ContextUnit]:
    """Secondary units: the analyzers' own prose, deduplicated.

    One unit per cited region. Several analyzers reporting the same thing at
    the same place collapse into one unit that says how many there were — the
    only compression this codebase performs, and the reason it is safe is that
    the text is identical and every tool is still listed in the candidate's
    provenance. Distinct messages at one region are joined, never merged into a
    paraphrase of each other.
    """
    entries: list[tuple[SourceRegion, str]] = [
        (candidate.region, candidate.message) for _ in candidate.provenance
    ]
    entries.extend(
        (item.region, candidate.message)
        for item in candidate.evidence
        if item.kind is EvidenceKind.ANALYZER_DIAGNOSTIC
    )

    grouped: dict[tuple[str, int, int, str], tuple[SourceRegion, list[str]]] = {}
    for region, message in entries:
        key = (str(region.path), region.start_line, region.end_line, region.sha256)
        found = grouped.setdefault(key, (region, []))
        found[1].append(message)

    units: list[ContextUnit] = []
    for _key, (region, messages) in sorted(grouped.items()):
        distinct = list(dict.fromkeys(messages))
        unit = factory.build(
            region,
            role=UnitRole.ANALYZER_MESSAGE,
            note="\n".join(distinct),
            occurrences=len(messages),
        )
        if unit is not None:
            units.append(unit)
    return units


def _dedupe(units: Sequence[ContextUnit]) -> list[ContextUnit]:
    """One unit per content address, keeping the strongest role it was given.

    A function that is both the containing function and a callee of itself is
    one region and must cost one region's tokens. Because :func:`sort_units`
    puts the strongest class and relevance first, keeping the first sighting
    keeps the right one.
    """
    best: dict[str, ContextUnit] = {}
    for unit in sort_units(units):
        best.setdefault(unit.evidence_id, unit)
    return sort_units(best.values())


def _no_expansion(region: SourceRegion) -> Limitation:
    return Limitation(
        kind=LimitationKind.NO_EVIDENCE_EXPANSION,
        detail=(
            f"no function containing {region.describe()} is in the index, so no types, "
            "macros, callers, or cleanup paths were retrieved for this candidate and "
            "the cited region is all there is to read"
        ),
        affects=str(region.path),
    )

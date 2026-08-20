"""The assembled bundle, plus the handles that make it reversible.

Everything the spec's invariants can be checked *by construction* is checked
here rather than in the code that builds a context. A validator that rejects a
compressed ``PRIMARY`` unit holds for every caller that ever exists, including
the ones written after this file; an assertion inside :func:`expand` holds only
for :func:`expand`.

Three things are therefore impossible to represent:

* a compressed or paraphrased unit that is not ``SECONDARY``;
* a unit whose class disagrees with its role — the class is a property of the
  role, so "a secondary containing function" cannot be built and then squeezed;
* a context whose ``total_tokens`` is not the sum of the units it holds, or
  which holds one unit in both ``units`` and ``dropped``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.evidence.bundle import EvidenceBundle
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceItem
from caudit.model.finding import Limitation, LimitationKind, ReviewReason
from caudit.model.source import SourceRegion, Symbol
from caudit.retrieval.policy import UnitClass, UnitRole, class_of

__all__ = [
    "ContextUnit",
    "DropReason",
    "DroppedUnit",
    "EvidenceContext",
    "sort_units",
    "zoom",
]


class ContextUnit(BaseModel):
    """One retrieved region, with the reason it is here and what it costs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Content address from part 03. The same region and kind always produce
    #: the same id, which is what lets a unit be deduplicated across roles.
    evidence_id: str = Field(min_length=1)
    unit_class: UnitClass
    role: UnitRole
    region: SourceRegion
    symbol: Symbol | None = None
    relevance: float = Field(ge=0.0, le=1.0)
    token_estimate: int = Field(ge=0)
    #: Call-graph distance for a caller or callee; 0 for roles without one.
    depth: int = Field(default=0, ge=0)
    #: How many identical items this unit stands for. Above 1 the unit has been
    #: compressed, which only a ``SECONDARY`` unit may be.
    occurrences: int = Field(default=1, ge=1)
    #: Prose belonging to a ``SECONDARY`` unit — an analyzer's own message.
    #: Code never appears here: it enters a context as exact bytes through
    #: :attr:`region`, or not at all.
    note: str | None = None

    @model_validator(mode="after")
    def _check_class_matches_role(self) -> Self:
        expected = class_of(self.role)
        if self.unit_class is not expected:
            raise ValueError(
                f"role {self.role} is always {expected}, not {self.unit_class}; the class "
                "is a property of the role so that a unit cannot be reclassified into "
                "one that permits compression"
            )
        return self

    @model_validator(mode="after")
    def _check_only_secondary_is_compressible(self) -> Self:
        if self.unit_class is UnitClass.SECONDARY:
            return self
        if self.occurrences > 1:
            raise ValueError(
                f"a {self.unit_class} unit cannot stand for {self.occurrences} items; "
                "only secondary material may be compressed (AC-09-11)"
            )
        if self.note is not None:
            raise ValueError(
                f"a {self.unit_class} unit cannot carry prose; code enters a context as "
                "exact bytes or not at all"
            )
        return self

    @property
    def is_compressed(self) -> bool:
        return self.occurrences > 1

    @property
    def is_code(self) -> bool:
        return self.unit_class is not UnitClass.SECONDARY

    def collapse(self, count: int) -> ContextUnit:
        """Stand for ``count`` identical items instead of one.

        The only compression this codebase performs, and it is refused on
        anything but secondary material. Refused rather than ignored: a caller
        that thought it was compressing a function should hear about it.
        """
        if self.unit_class is not UnitClass.SECONDARY:
            raise ValueError(
                f"refusing to compress a {self.unit_class} unit ({self.role}); only "
                "secondary material may be compressed (AC-09-11)"
            )
        if count < 1:
            raise ValueError(f"a unit cannot stand for {count} items")
        return self.model_copy(update={"occurrences": count})

    def describe(self) -> str:
        where = f" in {self.symbol.name}" if self.symbol else ""
        repeats = f" x{self.occurrences}" if self.is_compressed else ""
        return f"{self.region.describe()}{where} ({self.role}{repeats})"


class DropReason(StrEnum):
    """Why a unit is not on the page."""

    #: The token budget bound before this unit's turn.
    BUDGET = "budget"
    #: ``max_units`` bound first — breadth, not size.
    MAX_UNITS = "max_units"
    #: The primary set alone exceeded the budget, so nothing was emitted.
    PRIMARY_BUDGET_EXCEEDED = "primary_budget_exceeded"


class DroppedUnit(BaseModel):
    """A unit that did not fit, kept so the omission is visible."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    unit: ContextUnit
    reason: DropReason
    detail: str = Field(min_length=1)

    def as_limitation(self) -> Limitation:
        """The blind spot this drop creates, in the model a finding carries.

        A dropped unit is not diagnostic noise. It becomes a ``Limitation`` on
        every finding derived from this context, which is how a reader learns
        the model was reasoning with less than the whole picture.
        """
        target = self.unit.symbol.name if self.unit.symbol else None
        affects = f"{self.unit.region.path}::{target}" if target else str(self.unit.region.path)
        return Limitation(
            kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
            detail=(
                f"{self.unit.describe()} was retrieved but not included: {self.detail}. "
                "Any claim about this candidate was made without it"
            ),
            affects=affects,
        )


def on_flow_path(region: SourceRegion, flow: Iterable[SourceRegion]) -> bool:
    """True when ``region`` contains a step of the analyzer's reported path.

    The only dataflow signal available before part 10: the analyzer walked
    those lines to reach its conclusion, so a function containing one of them
    is closer to the value in question than a caller two hops away that may
    never touch it.
    """
    return any(
        str(step.path) == str(region.path)
        and region.start_line <= step.start_line
        and step.end_line <= region.end_line
        for step in flow
    )


def sort_units(units: Iterable[ContextUnit]) -> list[ContextUnit]:
    """The one presentation order: class, then relevance, then location.

    Total by construction — ``evidence_id`` is a content address and no two
    distinct units share one — so shuffling the index's iteration order cannot
    change the result (AC-09-12).
    """
    return sorted(
        units,
        key=lambda unit: (
            _CLASS_RANK[unit.unit_class],
            -unit.relevance,
            str(unit.region.path),
            unit.region.start_line,
            unit.region.end_line,
            unit.evidence_id,
        ),
    )


_CLASS_RANK: dict[UnitClass, int] = {
    UnitClass.PRIMARY: 0,
    UnitClass.SUPPORTING: 1,
    UnitClass.SECONDARY: 2,
}


class EvidenceContext(BaseModel):
    """Everything one candidate's adjudication is allowed to look at.

    Carries the :class:`~caudit.evidence.bundle.EvidenceBundle` that captured
    each region's bytes, so :func:`zoom` returns the original for any unit —
    kept, compressed, or dropped — rather than re-reading a file that may have
    changed since. That is the sense in which the spec requires retrieval to be
    reversible.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    candidate: Candidate
    #: Recorded per run: two reports about one revision must be able to say
    #: whether they were assembled by the same policy.
    policy_version: str = Field(min_length=1)
    budget_tokens: int = Field(ge=0)
    units: list[ContextUnit] = Field(default_factory=list)
    dropped: list[DroppedUnit] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)
    total_tokens: int = Field(default=0, ge=0)
    #: Set when this candidate cannot be adjudicated at all. The only value it
    #: currently takes is ``context_budget_exceeded``.
    review_reason: ReviewReason | None = None
    bundle: EvidenceBundle

    @model_validator(mode="after")
    def _check_accounting(self) -> Self:
        counted = sum(unit.token_estimate for unit in self.units)
        if counted != self.total_tokens:
            raise ValueError(f"total_tokens is {self.total_tokens} but the units sum to {counted}")
        if self.total_tokens > self.budget_tokens:
            raise ValueError(
                f"total_tokens {self.total_tokens} exceeds the budget of "
                f"{self.budget_tokens} (AC-09-6)"
            )
        return self

    @model_validator(mode="after")
    def _check_units_and_drops_are_disjoint(self) -> Self:
        kept = {unit.evidence_id for unit in self.units}
        collision = kept & {item.unit.evidence_id for item in self.dropped}
        if collision:
            raise ValueError(
                f"{len(collision)} unit(s) are recorded as both kept and dropped: "
                f"{', '.join(sorted(collision))}"
            )
        return self

    @model_validator(mode="after")
    def _check_primaries_survive(self) -> Self:
        """A primary is dropped only when nothing at all was emitted."""
        if self.review_reason is ReviewReason.CONTEXT_BUDGET_EXCEEDED:
            if self.units:
                raise ValueError(
                    "context_budget_exceeded means no context was emitted, but "
                    f"{len(self.units)} unit(s) are present"
                )
            return self
        dropped_primary = [
            item for item in self.dropped if item.unit.unit_class is UnitClass.PRIMARY
        ]
        if dropped_primary:
            raise ValueError(
                f"{len(dropped_primary)} primary unit(s) were dropped without the "
                "candidate being routed to review; primary units are never dropped "
                "to make room (AC-09-7)"
            )
        return self

    # ---------------------------------------------------------------- reading

    @property
    def is_adjudicable(self) -> bool:
        """False when the context is empty or the budget refused the candidate."""
        return self.review_reason is None and bool(self.units)

    @property
    def primary_units(self) -> list[ContextUnit]:
        return [unit for unit in self.units if unit.unit_class is UnitClass.PRIMARY]

    @property
    def supporting_units(self) -> list[ContextUnit]:
        return [unit for unit in self.units if unit.unit_class is UnitClass.SUPPORTING]

    @property
    def secondary_units(self) -> list[ContextUnit]:
        return [unit for unit in self.units if unit.unit_class is UnitClass.SECONDARY]

    def units_with_role(self, role: UnitRole) -> list[ContextUnit]:
        return [unit for unit in self.units if unit.role is role]

    def unit(self, evidence_id: str) -> ContextUnit | None:
        """A kept or dropped unit by id. Dropped ones are still addressable."""
        for unit in self.units:
            if unit.evidence_id == evidence_id:
                return unit
        for item in self.dropped:
            if item.unit.evidence_id == evidence_id:
                return item.unit
        return None

    def evidence_items(self) -> list[EvidenceItem]:
        """The typed evidence a finding may cite, in presentation order."""
        found = [self.bundle.get(unit.evidence_id) for unit in self.units]
        return [item for item in found if item is not None]

    def evidence_ids(self) -> tuple[str, ...]:
        """Exactly what a model is allowed to cite. Dropped units are not in it."""
        return tuple(unit.evidence_id for unit in self.units)

    def regions(self) -> list[SourceRegion]:
        return [unit.region for unit in self.units]

    def describe(self) -> str:
        if self.review_reason is not None:
            return f"no context: {self.review_reason}"
        return (
            f"{len(self.primary_units)} primary, {len(self.supporting_units)} supporting, "
            f"{len(self.secondary_units)} secondary units in {self.total_tokens}/"
            f"{self.budget_tokens} tokens, {len(self.dropped)} dropped"
        )


def zoom(context: EvidenceContext, evidence_id: str) -> bytes:
    """The exact original bytes behind any unit of ``context``.

    Works for kept, compressed, and dropped units alike: everything retrieved
    was captured in the bundle before selection decided what fits, so a
    compressed summary or an omission can always be expanded back into source.

    Raises ``KeyError`` for an id this context never issued — an invented
    handle cannot be turned into code.
    """
    return context.bundle.zoom(evidence_id)


def context_limitations(
    dropped: Sequence[DroppedUnit], carried: Iterable[Limitation] = ()
) -> list[Limitation]:
    """Every drop as a limitation, plus whatever the index already knew.

    Deduplicated but never reordered away: ``carried`` comes first because a
    blind spot in the index (a unit that did not parse, a macro defined outside
    the tree) explains why the retrieval looks the way it does.
    """
    collected: list[Limitation] = []
    for limitation in [*carried, *(item.as_limitation() for item in dropped)]:
        if limitation not in collected:
            collected.append(limitation)
    return collected

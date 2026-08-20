"""Token accounting and unit-level selection.

The rule this module exists to enforce: **a unit is kept whole or not at all.**
Selection never narrows a region, never summarizes one, and never returns half
a function. When the primaries alone do not fit, it says so and emits nothing,
because a bounds check that fell off the end of a truncated function does not
degrade an answer, it inverts it.

Counting is done through a :class:`Tokenizer`. Part 10 supplies the provider's
own, so the number a budget is spent against is the number that will actually
be sent. Until then :data:`DEFAULT_TOKENIZER` is a deliberately conservative
local estimate — see :class:`HeuristicTokenizer` for what "conservative" is
claimed to mean and what it is not.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol

from caudit.config.loader import TokenBudget
from caudit.errors import RegionError
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.hashing import hash_bytes, hashes_match
from caudit.evidence.store import SourceStore
from caudit.model.evidence import EvidenceItem, Provenance
from caudit.model.finding import Limitation, LimitationKind
from caudit.model.source import SourceRegion, Symbol
from caudit.retrieval.context import ContextUnit, DroppedUnit, DropReason
from caudit.retrieval.policy import UnitClass, UnitRole, class_of, evidence_kind_of, relevance

__all__ = [
    "DEFAULT_TOKENIZER",
    "HeuristicTokenizer",
    "RunLedger",
    "Selection",
    "Tokenizer",
    "UnitFactory",
    "select",
]


class Tokenizer(Protocol):
    """Counts tokens the way the model that will read the text counts them."""

    def count(self, text: str) -> int: ...


@dataclass(frozen=True)
class HeuristicTokenizer:
    """A local estimate for use before a provider tokenizer is available.

    The estimate is ``ceil(len / chars_per_token) + newlines``. Its one
    guarantee is directional: on any tokenizer whose tokens average at least
    ``chars_per_token`` characters — which subword vocabularies do on C and C++
    source, where identifiers, punctuation runs and keywords all merge — this
    over-counts rather than under-counts, so a budget spent against it is never
    overspent against the real one.

    That guarantee is an assumption about the provider, not a proof about it.
    It is asserted against a reference tokenizer in T-09-17 and it is why
    :func:`select` takes a tokenizer rather than calling this directly: when
    part 10 arrives with the real one, nothing here has to change.
    """

    chars_per_token: float = 3.0

    def count(self, text: str) -> int:
        """Tokens in ``text``. Empty text costs nothing."""
        if not text:
            return 0
        # Newlines are charged separately: a tokenizer emits a token for a line
        # break, and code is much more line-broken than the prose these ratios
        # are usually quoted for.
        return math.ceil(len(text) / self.chars_per_token) + text.count("\n")


#: Used when no provider tokenizer has been supplied.
DEFAULT_TOKENIZER: Final = HeuristicTokenizer()


@dataclass
class UnitFactory:
    """Mints costed units, capturing each one's bytes as it goes.

    Every unit is born through here, which puts three things in one place:

    * the region is read at the scanned revision and its hash re-checked, so a
      unit whose file moved under the index never reaches a context;
    * the bytes are captured in the bundle **before** the budget decides
      anything, which is what lets :func:`~caudit.retrieval.context.zoom`
      return the original for a unit that was later dropped;
    * the token estimate is taken from the exact text that will be sent.

    The estimate covers unit content only. Whatever scaffolding part 10 wraps
    around it — headings, instructions, the response schema — is part 10's to
    count, against the same tokenizer.
    """

    store: SourceStore
    bundle: EvidenceBundle
    provenance: list[Provenance]
    tokenizer: Tokenizer = DEFAULT_TOKENIZER
    #: Regions the scanned revision could not supply, with the reason. Read by
    #: ``expand`` to decide whether the dependency closure is complete: a piece
    #: of the closure that could not be read is a gap, not an absence.
    unavailable: list[tuple[SourceRegion, str]] = field(default_factory=list)

    def build(
        self,
        region: SourceRegion,
        *,
        role: UnitRole,
        symbol: Symbol | None = None,
        depth: int = 0,
        on_dataflow_path: bool = False,
        note: str | None = None,
        occurrences: int = 1,
    ) -> ContextUnit | None:
        """One unit, or ``None`` when the region cannot be supplied exactly."""
        data = self._read(region)
        if data is None:
            return None
        item = EvidenceItem.create(
            kind=evidence_kind_of(role),
            region=region,
            provenance=list(self.provenance),
            symbol=symbol,
        )
        self.bundle.add(item)
        # A secondary unit costs what its prose costs; a code unit costs what
        # its bytes cost. Decoding here is for counting only — the bytes the
        # bundle captured are the ones that get quoted.
        text = note if note is not None else self.store.decode_for_display(data)
        return ContextUnit(
            evidence_id=item.evidence_id,
            unit_class=class_of(role),
            role=role,
            region=region,
            symbol=symbol,
            relevance=relevance(role, depth=depth, on_dataflow_path=on_dataflow_path),
            token_estimate=self.tokenizer.count(text),
            depth=depth,
            occurrences=occurrences,
            note=note,
        )

    def _read(self, region: SourceRegion) -> bytes | None:
        try:
            data = self.store.read_region(region)
        except RegionError as exc:
            self.unavailable.append((region, str(exc)))
            return None
        if not hashes_match(region.sha256, hash_bytes(data)):
            self.unavailable.append(
                (
                    region,
                    "the bytes there no longer hash to the value recorded when the "
                    "index was built, so the tree changed under this run",
                )
            )
            return None
        return data

    def gaps(self) -> list[Limitation]:
        """What could not be retrieved, as limitations naming each region."""
        return [
            Limitation(
                kind=LimitationKind.NO_EVIDENCE_EXPANSION,
                detail=f"{region.describe()} could not be retrieved: {reason}",
                affects=str(region.path),
            )
            for region, reason in self.unavailable
        ]


@dataclass(frozen=True)
class Selection:
    """What fits, what does not, and why."""

    kept: tuple[ContextUnit, ...]
    dropped: tuple[DroppedUnit, ...]
    total_tokens: int
    #: True when the primary units alone exceeded the budget. The caller must
    #: emit no context at all in that case (AC-09-8).
    primaries_exceed_budget: bool = False

    def limitations(self) -> list[Limitation]:
        """One limitation per drop, so a reader learns what was not on the page."""
        return [item.as_limitation() for item in self.dropped]


def select(units: Sequence[ContextUnit], *, budget: int, max_units: int) -> Selection:
    """Fit ``units`` into ``budget`` tokens without ever splitting one.

    ``units`` must already be in the order the context will present them —
    :func:`caudit.retrieval.context.sort_units` produces it. Primaries are
    taken first and unconditionally; supporting and secondary units are then
    taken in that same order, and anything that does not fit is dropped whole,
    least relevant first.
    """
    primary = [unit for unit in units if unit.unit_class is UnitClass.PRIMARY]
    optional = [unit for unit in units if unit.unit_class is not UnitClass.PRIMARY]

    primary_tokens = sum(unit.token_estimate for unit in primary)
    if primary_tokens > budget:
        # Nothing is emitted. Not a smaller context: a smaller context is a
        # different question, asked without saying so.
        return Selection(
            kept=(),
            dropped=tuple(
                DroppedUnit(
                    unit=unit,
                    reason=DropReason.PRIMARY_BUDGET_EXCEEDED,
                    detail=(
                        f"the code required to judge this candidate is "
                        f"{primary_tokens} tokens against a budget of {budget}"
                    ),
                )
                for unit in units
            ),
            total_tokens=0,
            primaries_exceed_budget=True,
        )

    kept = list(primary)
    dropped: list[DroppedUnit] = []
    spent = primary_tokens
    # Drops are decided by walking the presentation order forwards and refusing
    # what no longer fits. Because that order is descending relevance, the
    # units refused are the least relevant ones, which is the rule stated in
    # the plan — reached without a second sort that could disagree with the
    # first.
    for unit in optional:
        if len(kept) >= max_units:
            dropped.append(
                DroppedUnit(
                    unit=unit,
                    reason=DropReason.MAX_UNITS,
                    detail=f"the context already holds {max_units} units, the configured cap",
                )
            )
            continue
        if spent + unit.token_estimate > budget:
            dropped.append(
                DroppedUnit(
                    unit=unit,
                    reason=DropReason.BUDGET,
                    detail=(
                        f"{unit.token_estimate} tokens would take the context past "
                        f"the {budget}-token budget, with {budget - spent} left"
                    ),
                )
            )
            continue
        kept.append(unit)
        spent += unit.token_estimate

    return Selection(kept=tuple(kept), dropped=tuple(dropped), total_tokens=spent)


@dataclass
class RunLedger:
    """Cumulative token spend across every candidate in one run.

    The per-candidate budget bounds one question; this bounds the whole run.
    Exhausting it stops further expansion rather than shrinking each remaining
    context to fit — squeezing more candidates through by giving each one less
    code is how a run ends up with many confident answers built on partial
    functions.
    """

    budget: TokenBudget
    spent: int = 0
    #: Candidate ids that were never expanded because the run budget was gone.
    starved: list[str] = field(default_factory=list)

    @property
    def remaining(self) -> int:
        return max(0, self.budget.per_run - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def allowance(self) -> int:
        """Tokens available to the next candidate."""
        return min(self.budget.per_candidate, self.remaining)

    def charge(self, tokens: int) -> int:
        """Record a spend and return the new total."""
        self.spent += max(0, tokens)
        return self.spent

    def starve(self, candidate_id: str) -> Limitation:
        """Record a candidate the run budget could not pay for."""
        self.starved.append(candidate_id)
        return Limitation(
            kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
            detail=(
                f"the run's {self.budget.per_run}-token budget was spent before this "
                f"candidate was expanded, so no code was retrieved for it and nothing "
                f"in this report is a statement about it"
            ),
            affects=candidate_id,
        )

    def describe(self) -> str:
        return f"{self.spent}/{self.budget.per_run} tokens spent, {len(self.starved)} unexpanded"


def total_tokens(units: Iterable[ContextUnit]) -> int:
    """Sum of a unit list's estimates. One definition, used by the validator."""
    return sum(unit.token_estimate for unit in units)

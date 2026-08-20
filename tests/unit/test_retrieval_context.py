"""Part 09 context tests: T-09-13, T-09-14 and the accounting invariants.

Covers AC-09-6, AC-09-10, AC-09-11. The models in ``retrieval.context`` are
where the spec's invariants become unrepresentable states rather than rules
somebody has to remember, so most of these are constructor tests: they assert
that the wrong thing cannot be built, not that the right code avoids building
it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.store import SourceStore
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import ReviewReason
from caudit.retrieval.context import (
    ContextUnit,
    DroppedUnit,
    DropReason,
    EvidenceContext,
    on_flow_path,
    sort_units,
)
from caudit.retrieval.policy import DEFAULT_POLICY, UnitClass, UnitRole
from caudit.retrieval.service import expand, zoom
from tests.conftest import (
    make_candidate,
    make_context_unit,
    make_region,
    retrieval_candidate,
    retrieval_provenance,
    retrieval_world,
)

pytestmark = pytest.mark.needs_libclang


def _three_tools_agreeing() -> list[Provenance]:
    """Three analyzers, one message — the shape that produces a compressed unit."""
    return [
        Provenance(
            producer=Producer.CLANG_TIDY,
            tool_name=f"analyzer-{step}",
            tool_version="18.1.8",
            rule_id="demo.check",
        )
        for step in range(3)
    ]


def _context(root: Path, **overrides: object) -> EvidenceContext:
    bundle = EvidenceBundle(SourceStore(root, revision="x"))
    base: dict[str, object] = {
        "candidate": make_candidate(retrieval_provenance()),
        "policy_version": "1",
        "budget_tokens": 1000,
        "bundle": bundle,
    }
    base.update(overrides)
    return EvidenceContext.model_validate(base)


# ------------------------------------------------------- accounting (AC-09-6)


def test_total_tokens_must_equal_the_units_it_claims_to_sum(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="units sum to 100"):
        _context(
            tmp_path,
            units=[make_context_unit(token_estimate=100)],
            total_tokens=40,
        )


def test_a_context_cannot_exceed_its_own_budget(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="exceeds the budget"):
        _context(
            tmp_path,
            budget_tokens=50,
            units=[make_context_unit(token_estimate=100)],
            total_tokens=100,
        )


def test_a_unit_cannot_be_both_kept_and_dropped(tmp_path: Path) -> None:
    unit = make_context_unit(role=UnitRole.CALLER, token_estimate=10, depth=1)
    with pytest.raises(ValidationError, match="both kept and dropped"):
        _context(
            tmp_path,
            units=[unit],
            total_tokens=10,
            dropped=[DroppedUnit(unit=unit, reason=DropReason.BUDGET, detail="no room")],
        )


def test_a_primary_cannot_be_dropped_to_make_room(tmp_path: Path) -> None:
    """AC-09-7 as a constructor rule, not a convention."""
    primary = make_context_unit(role=UnitRole.CONTAINING_FUNCTION, token_estimate=10)
    with pytest.raises(ValidationError, match="primary unit"):
        _context(
            tmp_path,
            dropped=[DroppedUnit(unit=primary, reason=DropReason.BUDGET, detail="no room")],
        )


def test_a_refused_candidate_carries_no_units(tmp_path: Path) -> None:
    """AC-09-8: "no context emitted" is checked, not merely intended."""
    with pytest.raises(ValidationError, match="no context was emitted"):
        _context(
            tmp_path,
            units=[make_context_unit(token_estimate=10)],
            total_tokens=10,
            review_reason=ReviewReason.CONTEXT_BUDGET_EXCEEDED,
        )


def test_dropping_every_primary_is_allowed_only_alongside_the_review_reason(
    tmp_path: Path,
) -> None:
    primary = make_context_unit(role=UnitRole.CONTAINING_FUNCTION, token_estimate=10)
    context = _context(
        tmp_path,
        dropped=[
            DroppedUnit(unit=primary, reason=DropReason.PRIMARY_BUDGET_EXCEEDED, detail="too large")
        ],
        review_reason=ReviewReason.CONTEXT_BUDGET_EXCEEDED,
    )
    assert not context.is_adjudicable
    assert context.describe() == "no context: context_budget_exceeded"


# ----------------------------------------------------- compression (AC-09-11)


def test_only_a_secondary_unit_may_stand_for_several_items() -> None:
    with pytest.raises(ValidationError, match="only secondary material may be compressed"):
        make_context_unit(role=UnitRole.CONTAINING_FUNCTION, occurrences=4)


def test_only_a_secondary_unit_may_carry_prose() -> None:
    """Code enters a context as exact bytes or not at all (AC-09-11)."""
    with pytest.raises(ValidationError, match="cannot carry prose"):
        make_context_unit(role=UnitRole.CALLER, note="a paraphrase of the function")


def test_a_unit_class_cannot_disagree_with_its_role() -> None:
    """The route a smuggler would take: relabel, then compress."""
    honest = make_context_unit(role=UnitRole.CONTAINING_FUNCTION)
    relabelled = honest.model_dump() | {"unit_class": UnitClass.SECONDARY, "occurrences": 4}
    with pytest.raises(ValidationError, match="is always"):
        ContextUnit.model_validate(relabelled)


# ---------------------------------------------------------------- T-09-14


def test_identical_analyzer_messages_collapse_into_one_secondary_unit(tmp_path: Path) -> None:
    """T-09-14, AC-09-11: five tools, one message, one unit that says five."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    tools = [
        Provenance(
            producer=Producer.CLANG_TIDY,
            tool_name=f"analyzer-{step}",
            tool_version="18.1.8",
            rule_id="demo.check",
        )
        for step in range(5)
    ]
    candidate = retrieval_candidate(
        store, "expansion.c", 120, message="the same sentence, five times", provenance=tools
    )

    context = expand(candidate, index, store)

    secondary = context.secondary_units
    assert len(secondary) == 1
    assert secondary[0].unit_class is UnitClass.SECONDARY
    assert secondary[0].occurrences == 5
    assert secondary[0].is_compressed
    assert secondary[0].note == "the same sentence, five times"
    # Code units are untouched by any of this.
    assert all(not unit.is_compressed for unit in context.units if unit.is_code)
    assert all(unit.note is None for unit in context.units if unit.is_code)


def test_distinct_messages_at_one_region_are_joined_not_merged(tmp_path: Path) -> None:
    """Two tools that disagree are two sentences, never one paraphrase."""
    unit = make_context_unit(
        role=UnitRole.ANALYZER_MESSAGE, note="leak here\nuse after free here", occurrences=2
    )
    assert unit.note is not None
    assert unit.note.split("\n") == ["leak here", "use after free here"]


def test_collapse_refuses_anything_that_is_not_secondary() -> None:
    primary = make_context_unit(role=UnitRole.CONTAINING_FUNCTION)
    with pytest.raises(ValueError, match="refusing to compress"):
        primary.collapse(3)

    secondary = make_context_unit(role=UnitRole.ANALYZER_MESSAGE, note="a message")
    assert secondary.collapse(3).occurrences == 3
    with pytest.raises(ValueError, match="cannot stand for 0 items"):
        secondary.collapse(0)


# ---------------------------------------------------------------- T-09-13


def test_zoom_returns_byte_identical_source_for_kept_compressed_and_dropped(
    tmp_path: Path,
) -> None:
    """T-09-13, AC-09-10: reversibility is the point of the handles."""
    root, index, store = retrieval_world(tmp_path, "expansion")
    # Three tools reporting the same thing, so the context also holds a
    # compressed unit and all three states are covered by one assertion loop.
    candidate = retrieval_candidate(store, "expansion.c", 120, provenance=_three_tools_agreeing())

    # A budget that fits the primaries and forces supporting units out.
    context = expand(candidate, index, store, DEFAULT_POLICY, allowance=1400)

    every = [*context.units, *(item.unit for item in context.dropped)]
    assert context.units, "the primaries must fit for this test to mean anything"
    assert context.dropped, "the budget must actually bind"
    assert any(unit.is_compressed for unit in every), "no compressed unit to check"

    on_disk = (root / "expansion.c").read_bytes()
    for unit in every:
        original = zoom(context, unit.evidence_id)
        assert original == on_disk[unit.region.start_byte : unit.region.end_byte]
    assert len(every) == len(context.units) + len(context.dropped)


def test_zoom_refuses_a_handle_the_context_never_issued(tmp_path: Path) -> None:
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(retrieval_candidate(store, "expansion.c", 120), index, store)
    with pytest.raises(KeyError):
        zoom(context, "ev_deadbeef")


def test_a_dropped_unit_is_still_addressable(tmp_path: Path) -> None:
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(
        retrieval_candidate(store, "expansion.c", 120), index, store, DEFAULT_POLICY, allowance=1400
    )

    dropped = context.dropped[0].unit
    assert context.unit(dropped.evidence_id) is dropped
    # ...but a model may not cite it: the ids it is given are the kept ones.
    assert dropped.evidence_id not in context.evidence_ids()


# --------------------------------------------------------------- ordering


def test_sorting_is_by_class_then_relevance_then_location() -> None:
    units = [
        make_context_unit(role=UnitRole.GLOBAL_DECL, start_line=1, end_line=1),
        make_context_unit(role=UnitRole.ANALYZER_MESSAGE, start_line=2, end_line=2, note="m"),
        make_context_unit(role=UnitRole.CALLER, start_line=3, end_line=4, depth=1),
        make_context_unit(role=UnitRole.CONTAINING_FUNCTION, start_line=5, end_line=9),
        make_context_unit(role=UnitRole.TYPE_DECL, start_line=6, end_line=7),
    ]

    ordered = sort_units(units)

    assert [unit.role for unit in ordered] == [
        UnitRole.CONTAINING_FUNCTION,
        UnitRole.TYPE_DECL,
        UnitRole.CALLER,
        UnitRole.GLOBAL_DECL,
        UnitRole.ANALYZER_MESSAGE,
    ]
    assert sort_units(ordered) == ordered
    assert sort_units(list(reversed(units))) == ordered


def test_on_flow_path_needs_containment_not_overlap() -> None:
    region = make_region("src/a.c", 10, 20)
    assert on_flow_path(region, [make_region("src/a.c", 15, 15)])
    assert not on_flow_path(region, [make_region("src/a.c", 21, 21)])
    assert not on_flow_path(region, [make_region("src/b.c", 15, 15)])


def test_describe_names_the_symbol_and_the_repeat_count() -> None:
    unit: ContextUnit = make_context_unit(
        role=UnitRole.ANALYZER_MESSAGE, start_line=5, end_line=5, note="m", occurrences=3
    )
    assert unit.describe() == "src/main.c:5 (analyzer_message x3)"

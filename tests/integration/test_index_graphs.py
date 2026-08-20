"""Part 06 graph tests: T-06-05 … T-06-08.

The theme is the invariant that unresolved is not absent. Each test here
asserts both halves: the edge that *was* found, and the honest record of what
could not be.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.index.graphs import CallKind
from caudit.model.finding import LimitationKind
from tests.integration.test_index_symbols import build

pytestmark = pytest.mark.needs_libclang


def test_a_call_edge_crosses_translation_units(tmp_path: Path) -> None:
    """T-06-05: `a.c` calls a function whose body is in `b.c`."""
    index = build(tmp_path, "cross_tu")
    caller = index.symbols_named("parse_header")[0]
    callee = index.symbols_named("b_func")[0]

    callees = index.callees_of(caller.usr)
    assert [edge.callee for edge in callees] == [callee.usr]
    assert callees.edges[0].kind is CallKind.DIRECT
    assert str(callees.edges[0].site.path) == "a.c"
    assert index.has_call_edge(caller.usr, callee.usr)

    # And from the other end: the definition in b.c knows its caller in a.c.
    callers = index.callers_of(callee.usr)
    assert [edge.caller for edge in callers] == [caller.usr]
    assert callers.is_complete


def test_a_call_through_a_function_pointer_table_is_an_edge_with_no_callee(
    tmp_path: Path,
) -> None:
    """T-06-06: the edge exists; only its target is unknown."""
    index = build(tmp_path, "indirect")
    dispatch = index.symbols_named("dispatch")[0]

    callees = index.callees_of(dispatch.usr)
    assert callees.edges == ()
    assert len(callees.unresolved) == 1
    assert not callees.is_complete
    unresolved = callees.unresolved[0]
    assert unresolved.callee is None
    assert unresolved.kind is CallKind.FUNCTION_POINTER
    assert str(unresolved.site.path) == "indirect.c"

    recorded = [
        item for item in index.limitations() if item.kind is LimitationKind.UNRESOLVED_INDIRECT_CALL
    ]
    assert len(recorded) == 1
    assert recorded[0].affects == "indirect.c::dispatch"


def test_a_target_of_an_indirect_call_is_never_reported_as_uncalled(
    tmp_path: Path,
) -> None:
    """AC-06-4: `accept_all` sits in the table, so "no callers" is not sayable.

    It has one *direct* caller and the index also holds an unresolved site, so
    the answer carries both. The question "is this function dead?" cannot be
    answered from `edges` alone, which is the point.
    """
    index = build(tmp_path, "indirect")
    accept_all = index.symbols_named("accept_all")[0]
    callers = index.callers_of(accept_all.usr)
    assert [edge.caller for edge in callers] == [index.symbols_named("direct")[0].usr]
    assert not callers.is_complete
    assert "unresolved indirect call site" in callers.describe()


def test_virtual_dispatch_records_every_override_it_can_see(tmp_path: Path) -> None:
    """T-06-07: edges to both overrides, and a limitation about the set."""
    index = build(tmp_path, "cpp", language="c++")
    run = index.symbols_named("run")[0]
    edges = index.callees_of(run.usr).edges
    assert {edge.callee for edge in edges} == {
        "c:@S@Codec@F@decode#I#",
        "c:@S@FastCodec@F@decode#I#",
        "c:@S@SafeCodec@F@decode#I#",
    }
    assert all(edge.kind is CallKind.VIRTUAL for edge in edges)
    # The two override edges are inferred from the hierarchy, not observed at
    # the call site; the one to the base method is what the source wrote.
    assert sum(1 for edge in edges if edge.inferred) == 2

    notes = [
        item for item in index.limitations() if item.kind is LimitationKind.UNRESOLVED_INDIRECT_CALL
    ]
    assert len(notes) == 1
    assert "2 override(s)" in notes[0].detail
    assert "would be missing from that set" in notes[0].detail
    assert notes[0].affects == "virtual.cpp::run"


def test_a_macro_at_a_candidate_site_carries_both_of_its_regions(tmp_path: Path) -> None:
    """T-06-08: the expansion site and the definition site, both citable.

    This is the case the spec calls out by name: a macro that hides a bounds
    check. Reading the call site alone shows `CHECK_LEN(packet->len)`, which
    says nothing about what is being compared.
    """
    index = build(tmp_path, "basic")
    parse_header = index.symbols_named("parse_header")[0]
    assert parse_header.definition is not None

    expansions = index.macros_expanded_in(parse_header.definition)
    by_name = {item.name: item for item in expansions}
    assert "CHECK_LEN" in by_name

    check_len = by_name["CHECK_LEN"]
    assert check_len.expansion.start_line == 15
    assert check_len.definition.start_line == 6
    assert check_len.usr == "c:basic.c@macro@CHECK_LEN"
    assert len(check_len.definition.sha256) == 64

    # The definition's own region is what a reader needs, so it must resolve to
    # the `#define` line and nothing else.
    definition_symbol = index.symbol(check_len.usr)
    assert definition_symbol is not None
    assert definition_symbol.definition == check_len.definition


def test_the_include_graph_records_what_pulled_in_what(tmp_path: Path) -> None:
    index = build(tmp_path, "cross_tu")
    assert [str(path) for path in index.includes("a.c")] == ["b.h"]
    assert index.includes("c.c") == []
    assert index.external_includes("a.c") == []

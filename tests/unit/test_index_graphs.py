"""Part 06 graph unit tests, including T-06-19.

No libclang here: these are about what the data structures let a caller
*conclude*, which is where the "unresolved is not absent" invariant either
holds or quietly stops holding.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from caudit.index.graphs import (
    CallEdge,
    CallGraph,
    CallKind,
    IncludeEdge,
    IncludeGraph,
    MacroExpansion,
    MacroTable,
    ReferenceTable,
    sort_edges,
)
from caudit.model.source import SourceRegion


def region(path: str = "src/a.c", start: int = 1, end: int | None = None) -> SourceRegion:
    return SourceRegion(
        path=PurePosixPath(path),
        start_line=start,
        end_line=end or start,
        start_byte=0,
        end_byte=16,
        sha256="c" * 64,
    )


def edge(caller: str, callee: str | None, line: int = 1) -> CallEdge:
    return CallEdge(
        caller=caller,
        callee=callee,
        site=region(start=line),
        kind=CallKind.DIRECT if callee else CallKind.FUNCTION_POINTER,
    )


def test_unresolved_callers_are_distinguishable_from_no_callers() -> None:
    """T-06-19: the two answers must not read the same.

    `victim` has no recorded caller, and the graph holds an indirect call whose
    target is unknown. "Nothing calls victim" is therefore not a supportable
    claim, and the result says so rather than looking empty.
    """
    graph = CallGraph([edge("c:@F@dispatch", None, line=9)])

    answer = graph.callers_of("c:@F@victim")
    assert answer.edges == ()
    assert not answer.is_complete
    assert len(answer.unresolved) == 1
    assert "unresolved indirect call site" in answer.describe()


def test_the_api_will_not_let_an_empty_answer_be_read_as_absence() -> None:
    """T-06-19, second half: handling the unresolved set is not optional.

    ``CallQuery`` defines neither ``__len__`` nor ``__bool__``, so the two
    idioms that would silently mean "never called" — ``if not callers:`` and
    ``len(callers) == 0`` — cannot be written against it by accident.
    """
    answer = CallGraph([edge("c:@F@dispatch", None)]).callers_of("c:@F@victim")

    assert bool(answer) is True, "an answer object is always truthy"
    with pytest.raises(TypeError):
        len(answer)  # type: ignore[arg-type]
    # The honest forms are both available and both explicit.
    assert answer.edges == ()
    assert answer.is_complete is False


def test_a_complete_answer_says_so() -> None:
    graph = CallGraph([edge("c:@F@main", "c:@F@helper")])
    answer = graph.callers_of("c:@F@helper")
    assert [item.caller for item in answer] == ["c:@F@main"]
    assert answer.is_complete
    assert answer.describe() == "1 callers of c:@F@helper"


def test_callees_walk_to_the_requested_depth() -> None:
    graph = CallGraph(
        [
            edge("c:@F@a", "c:@F@b"),
            edge("c:@F@b", "c:@F@c"),
            edge("c:@F@c", "c:@F@d"),
        ]
    )
    assert [item.callee for item in graph.callees_of("c:@F@a")] == ["c:@F@b"]
    assert [item.callee for item in graph.callees_of("c:@F@a", depth=2)] == ["c:@F@b", "c:@F@c"]
    assert len(graph.callees_of("c:@F@a", depth=9).edges) == 3
    assert graph.callees_of("c:@F@a", depth=0).edges == ()


def test_a_cycle_does_not_walk_forever() -> None:
    graph = CallGraph([edge("c:@F@a", "c:@F@b"), edge("c:@F@b", "c:@F@a")])
    assert len(graph.callees_of("c:@F@a", depth=10).edges) == 2


def test_unresolved_callees_are_reported_only_for_the_walked_nodes() -> None:
    """`callees_of` can be precise where `callers_of` cannot."""
    graph = CallGraph([edge("c:@F@a", None), edge("c:@F@z", None)])
    answer = graph.callees_of("c:@F@a")
    assert len(answer.unresolved) == 1
    assert answer.unresolved[0].caller == "c:@F@a"


def test_edges_have_a_total_order() -> None:
    """Two runs that discover edges in different orders serialize the same."""
    edges = [
        edge("c:@F@b", "c:@F@x", line=2),
        edge("c:@F@a", None, line=5),
        edge("c:@F@a", "c:@F@y", line=1),
    ]
    assert [item.describe() for item in sort_edges(edges)] == [
        item.describe() for item in sort_edges(list(reversed(edges)))
    ]
    assert sort_edges(edges)[0].caller == "c:@F@a"


def test_an_edge_describes_an_unresolved_target_by_what_the_source_wrote() -> None:
    unresolved = CallEdge(
        caller="c:@F@dispatch",
        callee=None,
        site=region(start=9),
        kind=CallKind.FUNCTION_POINTER,
        spelling="handler",
    )
    assert not unresolved.resolved
    assert "<unresolved handler>" in unresolved.describe()


def test_has_edge_is_exact() -> None:
    graph = CallGraph([edge("c:@F@a", "c:@F@b")])
    assert graph.has_edge("c:@F@a", "c:@F@b")
    assert not graph.has_edge("c:@F@b", "c:@F@a")
    assert not graph.has_edge("c:@F@a", "c:@F@missing")


def test_macros_are_found_by_the_region_they_were_expanded_in() -> None:
    table = MacroTable(
        [
            MacroExpansion(
                name="CHECK_LEN",
                usr="c:src/a.c@macro@CHECK_LEN",
                definition=region(start=2),
                expansion=region(start=20),
            ),
            MacroExpansion(
                name="ELSEWHERE",
                usr="c:src/a.c@macro@ELSEWHERE",
                definition=region(start=3),
                expansion=region(start=90),
            ),
        ]
    )
    found = table.expanded_in(region(start=18, end=22))
    assert [item.name for item in found] == ["CHECK_LEN"]
    assert table.expanded_in(region(path="src/other.c", start=20)) == []
    assert [item.name for item in table.named("ELSEWHERE")] == ["ELSEWHERE"]
    assert "expanded at src/a.c:20, defined at src/a.c:2" in found[0].describe()


def test_the_include_graph_separates_the_tree_from_the_toolchain() -> None:
    source = PurePosixPath("src/a.c")
    local = IncludeEdge(includer=source, included="src/a.h", site=region(start=1), in_repo=True)
    system = IncludeEdge(
        includer=source, included="/usr/include/stdio.h", site=region(start=2), in_repo=False
    )
    graph = IncludeGraph([local, system])

    assert graph.includes("src/a.c") == [PurePosixPath("src/a.h")]
    assert graph.external_includes("src/a.c") == ["/usr/include/stdio.h"]
    assert graph.included_by("src/a.h") == [PurePosixPath("src/a.c")]
    # Every entry is hashed, including this one: an include is citable evidence.
    assert local.line == 1
    assert len(local.site.sha256) == 64
    assert local.repo_path == PurePosixPath("src/a.h")
    assert system.repo_path is None


def test_a_reference_table_merges_and_sorts() -> None:
    left = ReferenceTable([("c:@F@f", "c:@S@B")])
    right = ReferenceTable([("c:@F@f", "c:@S@A"), ("c:@F@g", "c:@S@C")])
    left.merge(right)
    assert left.of("c:@F@f") == ["c:@S@A", "c:@S@B"]
    assert left.pairs() == [
        ("c:@F@f", "c:@S@A"),
        ("c:@F@f", "c:@S@B"),
        ("c:@F@g", "c:@S@C"),
    ]
    assert len(left) == 2

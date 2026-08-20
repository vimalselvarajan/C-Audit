"""Citations built to pass v1 and fail v2: T-06-16 … T-06-18.

Each test asserts the *difference* between the two resolvers, not just v2's
verdict. A model that has learned to produce plausible citations produces
exactly these shapes — a name that appears in a comment, an edge that sounds
right, a symbol that reads like it exists — and the value of part 06 is
precisely that they stop resolving.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.evidence.resolver import Citation, ResolutionStatus
from tests.integration.test_index_resolver import resolvers

pytestmark = pytest.mark.needs_libclang


def test_a_symbol_named_only_in_a_comment_no_longer_resolves(tmp_path: Path) -> None:
    """T-06-16: line 7 of `a.c` is a comment mentioning `parse_header`."""
    v1, v2, _index = resolvers(tmp_path)
    citation = Citation(path="a.c", start_line=7, end_line=7, symbol="parse_header")

    assert v1.resolve(citation).status is ResolutionStatus.OK, "v1 matches the text"

    rejected = v2.resolve(citation)
    assert rejected.status is ResolutionStatus.SYMBOL_NOT_FOUND
    assert "not declared or defined at a.c:7" in rejected.detail
    assert "a.c:11-17" in rejected.detail, "the rejection says where it really is"


def test_an_asserted_call_edge_that_does_not_exist_is_rejected(tmp_path: Path) -> None:
    """T-06-17: `parse_header` never calls `never_called_fn`."""
    _v1, v2, _index = resolvers(tmp_path)
    rejected = v2.resolve_call_edge("parse_header", "never_called_fn")

    assert rejected.status is ResolutionStatus.SYMBOL_NOT_FOUND
    assert "no call from parse_header to never_called_fn" in rejected.detail


def test_a_rejected_edge_never_claims_the_call_is_impossible(tmp_path: Path) -> None:
    """The invariant, at the resolver: unresolved is not absent.

    `dispatch` calls through a function-pointer table. The index cannot confirm
    the asserted edge — and must not present that as a denial, because the
    unknown target could be exactly the callee named.
    """
    _v1, v2, _index = resolvers(tmp_path, "indirect")
    rejected = v2.resolve_call_edge("dispatch", "reject_all")

    assert rejected.status is ResolutionStatus.SYMBOL_NOT_FOUND
    assert "indirect call(s) whose target is unknown" in rejected.detail
    assert "unverified rather than disproved" in rejected.detail


def test_a_symbol_that_exists_nowhere_is_rejected_without_an_exception(
    tmp_path: Path,
) -> None:
    """T-06-18: a plausible-looking invention resolves to a verdict, not a crash."""
    v1, v2, _index = resolvers(tmp_path)
    citation = Citation(path="a.c", start_line=11, end_line=17, symbol="parse_header_internal")

    assert v1.resolve(citation).status is ResolutionStatus.SYMBOL_NOT_FOUND
    rejected = v2.resolve(citation)
    assert rejected.status is ResolutionStatus.SYMBOL_NOT_FOUND
    assert "no symbol named 'parse_header_internal'" in rejected.detail


def test_an_edge_naming_an_invented_function_is_rejected(tmp_path: Path) -> None:
    _v1, v2, _index = resolvers(tmp_path)
    for caller, callee in (("parse_header", "made_up_fn"), ("made_up_fn", "b_func")):
        rejected = v2.resolve_call_edge(caller, callee)
        assert rejected.status is ResolutionStatus.SYMBOL_NOT_FOUND
        assert "made_up_fn" in rejected.detail
        assert "not in the index" in rejected.detail


def test_a_symbol_cited_in_a_unit_that_failed_to_parse_is_not_verifiable(
    tmp_path: Path,
) -> None:
    """The quietest fabrication: a citation into a file nothing could read.

    `missing_header.c` is not in the index, so `configured_limit` cannot be
    confirmed to be anywhere — even though the text sits right there on disk
    and v1 is happy to match it.
    """
    v1, v2, _index = resolvers(tmp_path, "broken")
    citation = Citation(
        path="missing_header.c", start_line=6, end_line=9, symbol="configured_limit"
    )

    assert v1.resolve(citation).status is ResolutionStatus.OK
    rejected = v2.resolve(citation)
    assert rejected.status is ResolutionStatus.SYMBOL_NOT_FOUND
    assert "not in the index" in rejected.detail

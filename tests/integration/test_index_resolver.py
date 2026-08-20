"""Resolver v2 against real citations: T-06-15.

The adversarial half — the citations designed to slip past v1 — lives in
``tests/adversarial/test_index_citations.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import Citation, CitationResolver, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.index import Index, IndexResolver, build_index
from caudit.intake import load_scan_plan
from tests.conftest import cpp_fixture, index_config

pytestmark = pytest.mark.needs_libclang


def resolvers(
    tmp_path: Path, name: str = "cross_tu"
) -> tuple[CitationResolver, IndexResolver, Index]:
    """v1 and v2 over the same tree, so the difference is what is asserted."""
    root, database = cpp_fixture(tmp_path, name)
    config = index_config()
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    index = build_index(plan, config)
    store = SourceStore(root, revision=plan.revision)
    bundle = EvidenceBundle(store)
    return CitationResolver(store, bundle), IndexResolver(store, bundle, index), index


def test_a_symbol_cited_at_its_definition_resolves(tmp_path: Path) -> None:
    """T-06-15: `parse_header` at lines 11-17, where the index puts it."""
    _v1, v2, _index = resolvers(tmp_path)
    resolution = v2.resolve(Citation(path="a.c", start_line=11, end_line=17, symbol="parse_header"))
    assert resolution.status is ResolutionStatus.OK
    assert resolution.region is not None
    assert resolution.region.describe() == "a.c:11-17"


def test_a_line_inside_a_body_still_resolves_for_that_function(tmp_path: Path) -> None:
    """The common, legitimate citation: "the bug is at line 16 in parse_header"."""
    _v1, v2, _index = resolvers(tmp_path)
    resolution = v2.resolve(Citation(path="a.c", start_line=16, end_line=16, symbol="parse_header"))
    assert resolution.status is ResolutionStatus.OK


def test_a_declaration_in_a_header_resolves_at_the_header(tmp_path: Path) -> None:
    """A header is never a unit of its own, but it is still indexed."""
    _v1, v2, _index = resolvers(tmp_path)
    resolution = v2.resolve(Citation(path="b.h", start_line=1, end_line=1, symbol="b_func"))
    assert resolution.status is ResolutionStatus.OK


def test_an_asserted_call_edge_that_exists_resolves(tmp_path: Path) -> None:
    _v1, v2, _index = resolvers(tmp_path)
    assert v2.resolve_call_edge("parse_header", "b_func").status is ResolutionStatus.OK
    # Also when the edge rides along with a location.
    located = v2.resolve(
        Citation(
            path="a.c",
            start_line=16,
            end_line=16,
            symbol="parse_header",
            caller="parse_header",
            callee="b_func",
        )
    )
    assert located.status is ResolutionStatus.OK


def test_a_citation_may_name_a_usr_instead_of_a_name(tmp_path: Path) -> None:
    """Names are ambiguous; the USR is the identity, so both are accepted."""
    _v1, v2, index = resolvers(tmp_path)
    caller = index.symbols_named("parse_header")[0]
    callee = index.symbols_named("b_func")[0]
    assert v2.resolve_call_edge(caller.usr, callee.usr).status is ResolutionStatus.OK


def test_the_location_checks_still_run_first(tmp_path: Path) -> None:
    """A symbol that is really there does not excuse a region that is not."""
    _v1, v2, _index = resolvers(tmp_path)
    assert (
        v2.resolve(Citation(path="a.c", start_line=900, end_line=901, symbol="parse_header")).status
        is ResolutionStatus.LINE_OUT_OF_RANGE
    )
    assert (
        v2.resolve(Citation(path="../escape.c", start_line=1, symbol="parse_header")).status
        is ResolutionStatus.OUTSIDE_REPO_ROOT
    )
    stale = v2.resolve(
        Citation(path="a.c", start_line=11, end_line=17, symbol="parse_header", sha256="b" * 64)
    )
    assert stale.status is ResolutionStatus.HASH_MISMATCH


def test_v1_and_v2_agree_when_the_citation_is_honest(tmp_path: Path) -> None:
    """The upgrade must not reject citations that were always fine."""
    v1, v2, _index = resolvers(tmp_path)
    citation = Citation(path="a.c", start_line=11, end_line=17, symbol="parse_header")
    assert v1.resolve(citation).status is v2.resolve(citation).status is ResolutionStatus.OK


def test_only_the_index_backed_resolver_claims_to_verify_edges(tmp_path: Path) -> None:
    """Part 11 asserts this before treating an edge claim as checked."""
    v1, v2, _index = resolvers(tmp_path)
    assert not v1.verifies_call_edges
    assert v2.verifies_call_edges

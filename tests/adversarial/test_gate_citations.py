"""Clause 1: every citation resolves. T-11-01 through T-11-08.

Each test here smuggles one unverifiable claim past the schema and asserts the
gate catches it. The claims are the ones a model can actually make in this
architecture, which is a narrower set than "anything": it cannot write a file
path into a finding, because a location is a handle into a bundle rather than a
string. So a fabricated location arrives as an id that was never issued, a
fabricated function arrives as an asserted call edge, and a fabricated snippet
arrives as a quotation — and those three channels are exactly what is tested.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.evidence.resolver import ResolutionStatus
from caudit.model.adjudication import CallEdgeClaim, Quotation
from caudit.model.evidence import EvidenceItem, EvidenceKind, Producer, Provenance
from caudit.model.finding import ReviewReason
from caudit.model.source import Symbol
from caudit.verify import verify
from tests.conftest import (
    ANALYZERS_THAT_RAN,
    GateWorld,
    gate_world,
    make_adjudication,
    retrieval_provenance,
)


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    return gate_world(
        tmp_path_factory.mktemp("gate-citations"),
        "macro_bounds",
        "macro_bounds.c",
        27,
        message="the copy is not bounded by the destination's declared size",
        cwe=("CWE-787",),
    )


def _verify(world: GateWorld, **overrides: object):  # type: ignore[no-untyped-def]
    return verify(
        make_adjudication(world.context, **overrides),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )


# ------------------------------------------------------------------- T-11-01


def test_an_invented_evidence_id_is_rejected_before_a_file_is_opened(
    world: GateWorld,
) -> None:
    """T-11-01: ``src/ghost.c`` cannot reach the gate as a path — only as a handle.

    A model has no field in which to write a file name. Its only way to point
    at code is an evidence id, so the fabricated-path attack *is* the invented
    id, and it fails before any file is opened.
    """
    outcome = _verify(world, cited_evidence_ids=["ev-src-ghost-c-0000000000000000"])

    assert outcome.accepted is False
    assert outcome.finding is None
    assert ReviewReason.CITATION_UNRESOLVED in outcome.reasons
    assert any("never issued" in line for line in outcome.details)
    # Nothing was looked up: the handle does not name anything in the closed
    # world the model was given, so no resolution was even attempted for it.
    assert not any(
        resolution.citation.evidence_id == "ev-src-ghost-c-0000000000000000"
        for resolution in outcome.resolutions
    )


def test_a_deleted_file_is_reported_as_missing_rather_than_as_a_fabrication(
    tmp_path: Path,
) -> None:
    """The other route to an unresolvable location, and it reads differently.

    A file that existed at analysis time and is gone at verification time is
    not a model inventing anything. The reason has to say so, or a reviewer
    goes looking for a fabrication that never happened.
    """
    world = gate_world(tmp_path, "macro_bounds", "macro_bounds.c", 27, cwe=("CWE-787",))
    (world.root / "macro_bounds.c").unlink()

    outcome = _verify(world)
    assert outcome.accepted is False
    assert ReviewReason.MISSING_FILE in outcome.reasons
    assert any(status.status is ResolutionStatus.MISSING_FILE for status in outcome.resolutions)


# ------------------------------------------------------------------- T-11-02


def test_an_asserted_edge_naming_a_function_that_does_not_exist(world: GateWorld) -> None:
    """T-11-02: ``validate_input()`` is in no index, so the *name* is what failed."""
    outcome = _verify(
        world,
        asserted_call_edges=[CallEdgeClaim(caller="copy_into", callee="validate_input")],
    )

    assert outcome.accepted is False
    assert ReviewReason.SYMBOL_UNRESOLVED in outcome.reasons
    assert any("validate_input" in line for line in outcome.details)
    # Not reported as a missing edge: the edge was never the problem.
    assert ReviewReason.CALL_EDGE_UNRESOLVED not in outcome.reasons


# --------------------------------------------------------- T-11-03 and T-11-04


def test_a_line_past_the_end_of_a_real_file_never_resolves(world: GateWorld) -> None:
    """T-11-03: the file is real, the line is not, and ``ok`` is not available.

    Reported as ``citation_unresolved`` rather than ``hash_mismatch``: nothing
    changed, the citation simply does not name anything, and sending a reader
    to look for an edit would waste the trip.
    """
    ghost_line = world.context.candidate.region.model_copy(
        update={"start_line": 9999, "end_line": 9999}
    )
    context = world.context.model_copy(
        update={"candidate": world.context.candidate.model_copy(update={"region": ghost_line})}
    )
    outcome = verify(
        make_adjudication(context),
        context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.CITATION_UNRESOLVED in outcome.reasons
    assert any(
        resolution.status is ResolutionStatus.LINE_OUT_OF_RANGE
        for resolution in outcome.resolutions
    )


def test_a_real_symbol_cited_forty_lines_from_where_it_lives(tmp_path: Path) -> None:
    """T-11-04: the index places ``long_walk`` elsewhere, so the claim is false.

    This is the failure part 06's resolver exists for. Version 1 asks whether
    the identifier appears in those bytes, which a comment satisfies; version 2
    asks whether the index puts the symbol *at* the region, and it does not.
    """
    world = gate_world(tmp_path, "expansion", "expansion.c", 44, cwe=("CWE-190",))
    displaced = _displaced_symbol_item(world, symbol_name="long_walk", start=29, end=32)
    context = _with_extra_unit(world, displaced)

    outcome = verify(
        make_adjudication(context, cited_evidence_ids=[displaced.evidence_id], cwe="CWE-190"),
        context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.SYMBOL_UNRESOLVED in outcome.reasons
    assert any(
        "long_walk" in line and "not declared or defined" in line for line in outcome.details
    )


def _displaced_symbol_item(
    world: GateWorld, *, symbol_name: str, start: int, end: int
) -> EvidenceItem:
    """An evidence item claiming ``symbol_name`` at a region it does not occupy."""
    region = world.store.make_region("expansion.c", start, end)
    item = EvidenceItem.create(
        kind=EvidenceKind.PRIMARY_CODE,
        region=region,
        provenance=retrieval_provenance(),
        symbol=Symbol(name=symbol_name, kind="function"),
    )
    world.context.bundle.add(item)
    return item


def _with_extra_unit(world: GateWorld, item: EvidenceItem):  # type: ignore[no-untyped-def]
    """Issue one more unit into a context, bypassing the token accounting.

    ``model_copy`` deliberately does not re-validate: representing a state the
    builders refuse to build is the whole point of an adversarial fixture.
    """
    from caudit.retrieval.context import ContextUnit
    from caudit.retrieval.policy import UnitClass, UnitRole

    unit = ContextUnit(
        evidence_id=item.evidence_id,
        unit_class=UnitClass.PRIMARY,
        role=UnitRole.CONTAINING_FUNCTION,
        region=item.region,
        symbol=item.symbol,
        relevance=1.0,
        token_estimate=0,
    )
    return world.context.model_copy(update={"units": [*world.context.units, unit]})


# ------------------------------------------------------------------- T-11-05


def test_provenance_naming_an_analyzer_that_never_ran(tmp_path: Path) -> None:
    """T-11-05: the candidate says ``infer`` produced this; no infer ran."""
    world = gate_world(
        tmp_path,
        "macro_bounds",
        "macro_bounds.c",
        27,
        cwe=("CWE-787",),
        provenance=[
            Provenance(
                producer=Producer.CSA,
                tool_name="infer",
                tool_version="1.2.0",
                rule_id="BUFFER_OVERRUN_L1",
            )
        ],
    )
    outcome = verify(
        make_adjudication(world.context),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.SCHEMA_VIOLATION in outcome.reasons
    assert any("infer" in line and "did not run" in line for line in outcome.details)


def test_an_unsupplied_analyzer_set_is_recorded_rather_than_skipped(
    world: GateWorld,
) -> None:
    """A check that quietly does not run is indistinguishable from one that passed."""
    outcome = verify(make_adjudication(world.context), world.context, world.index, world.store)
    assert outcome.accepted is True
    assert outcome.finding is not None
    kinds = {limitation.kind for limitation in outcome.finding.limitations}
    assert "provenance_unchecked" in {str(kind) for kind in kinds}


# --------------------------------------------------------- T-11-06 and T-11-07


def test_a_quoted_snippet_with_one_added_character(world: GateWorld) -> None:
    """T-11-06: an exclamation mark reverses a condition; the hashes disagree."""
    identifier = world.evidence(0)
    outcome = _verify(
        world,
        quoted_evidence=[
            Quotation(evidence_id=identifier, text="frame->buf[index] = src[index];!")
        ],
    )

    assert outcome.accepted is False
    assert ReviewReason.HASH_MISMATCH in outcome.reasons
    detail = next(line for line in outcome.details if "hash_mismatch" in line)
    # Both hashes, so a reviewer can pull the region and see the difference.
    assert "quotation" in detail and "region" in detail


def test_a_quotation_differing_only_in_whitespace_is_still_a_mismatch(
    world: GateWorld,
) -> None:
    """T-11-07: exact bytes, by design.

    Hashes are over exact bytes everywhere else in this codebase, and a
    quotation is not the place to start being lenient — a comparison that
    forgives a dropped space forgives a dropped operator by the same rule.
    """
    identifier = world.evidence(0)
    outcome = _verify(
        world,
        quoted_evidence=[
            Quotation(evidence_id=identifier, text="frame->buf[index]  =  src[index];")
        ],
    )

    assert outcome.accepted is False
    assert ReviewReason.HASH_MISMATCH in outcome.reasons


def test_an_exact_quotation_is_accepted(world: GateWorld) -> None:
    """The check has to be passable, or it is only a way to reject everything."""
    outcome = _verify(
        world,
        quoted_evidence=[
            Quotation(evidence_id=world.evidence(0), text="frame->buf[index] = src[index];")
        ],
    )
    assert outcome.accepted is True
    assert ReviewReason.HASH_MISMATCH not in outcome.reasons


def test_a_quotation_may_only_quote_what_the_answer_cites(world: GateWorld) -> None:
    """Refused at construction: quoting from nowhere is an incoherent object."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="quote only from what you cite"):
        make_adjudication(
            world.context,
            cited_evidence_ids=[world.evidence(0)],
            quoted_evidence=[Quotation(evidence_id=world.evidence(1), text="anything")],
        )


# ------------------------------------------------------------------- T-11-08


def test_an_asserted_edge_the_call_graph_does_not_record(tmp_path: Path) -> None:
    """T-11-08: ``caller_c`` and ``helper_one`` are both real; the call is not."""
    world = gate_world(tmp_path, "expansion", "expansion.c", 44, cwe=("CWE-190",))
    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-190",
            asserted_call_edges=[CallEdgeClaim(caller="caller_c", callee="helper_one")],
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.CALL_EDGE_UNRESOLVED in outcome.reasons
    detail = next(line for line in outcome.details if "call_edge_unresolved" in line)
    # "The index records no such edge" is not "no such call exists", and the
    # rejection has to keep the difference.
    assert "records no call" in detail


def test_an_edge_the_graph_does_record_resolves(tmp_path: Path) -> None:
    world = gate_world(tmp_path, "expansion", "expansion.c", 44, cwe=("CWE-190",))
    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-190",
            asserted_call_edges=[CallEdgeClaim(caller="caller_a", callee="long_walk")],
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert outcome.accepted is True
    assert ReviewReason.CALL_EDGE_UNRESOLVED not in outcome.reasons


def test_a_resolver_with_no_call_graph_reports_unverified_not_verified(
    world: GateWorld,
) -> None:
    """Part 03's resolver cannot check an edge, so it does not get to pass one."""
    from caudit.evidence.resolver import CitationResolver
    from caudit.verify.citations import citations_for, edge_failures, resolve

    adjudication = make_adjudication(
        world.context,
        asserted_call_edges=[CallEdgeClaim(caller="caller_a", callee="long_walk")],
    )
    resolver = CitationResolver(world.store, world.context.bundle)
    assert resolver.verifies_call_edges is False

    resolutions = resolve(citations_for(adjudication, world.context), resolver)
    failures = edge_failures(resolutions, resolver, world.index)
    assert [failure.reason for failure in failures] == [ReviewReason.CALL_EDGE_UNRESOLVED]
    assert "an unverified edge is not a verified one" in failures[0].detail


# ------------------------------------------------------------- the happy path


def test_a_fully_valid_adjudication_resolves_everything(world: GateWorld) -> None:
    outcome = _verify(world)
    assert outcome.accepted is True
    assert outcome.reasons == []
    assert outcome.resolution_rate == 1.0
    assert all(resolution.ok for resolution in outcome.resolutions)


def test_the_candidate_location_is_always_checked_even_when_uncited(
    world: GateWorld,
) -> None:
    """A report whose location does not resolve is wrong where a reader looks first."""
    labels = {resolution.citation.label for resolution in _verify(world).resolutions}
    assert "candidate_location" in labels


def test_configuration_is_not_consulted_by_the_gate() -> None:
    """The gate takes four objects and no ``Config``; there is no knob to loosen.

    Asserted on the signature rather than by behaviour: the strongest form of
    "this cannot be configured off" is that there is nowhere to put the switch.
    """
    import inspect

    parameters = inspect.signature(verify).parameters
    assert "config" not in parameters
    assert Config not in {parameter.annotation for parameter in parameters.values()}

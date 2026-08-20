"""The gate's own guarantees: T-11-13, 16, 17, 19, 20, 21, 22.

Where the adversarial suite attacks one clause at a time, these tests are about
properties of the whole component — that it is deterministic, that it touches
no network, that no input can produce a confirmed finding with an unresolved
citation, and that confidence is computed rather than believed.
"""

from __future__ import annotations

import inspect
import random
import socket
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from caudit.model.adjudication import CallEdgeClaim
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Reachability,
    ReviewReason,
)
from caudit.retrieval.policy import UnitRole
from caudit.verify import GateOutcome, ReviewItem, verify
from caudit.verify.gate import _DOWNGRADE_ONLY
from tests.conftest import ANALYZERS_THAT_RAN, GateWorld, gate_world, make_adjudication


@pytest.fixture(scope="module")
def bounds(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    return gate_world(
        tmp_path_factory.mktemp("verify-bounds"),
        "macro_bounds",
        "macro_bounds.c",
        27,
        message="the copy is not bounded by the destination's declared size",
        cwe=("CWE-787",),
    )


@pytest.fixture(scope="module")
def flow(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    return gate_world(
        tmp_path_factory.mktemp("verify-flow"),
        "expansion",
        "expansion.c",
        248,
        message="the offset may exceed the string's length",
        cwe=("CWE-125",),
        flow=(258, 253, 248),
    )


def _verify(world: GateWorld, **overrides: object) -> GateOutcome:
    return verify(
        make_adjudication(world.context, **overrides),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )


# ------------------------------------------------------------------- T-11-13


def test_a_genuine_control_flow_path_keeps_demonstrated_reachability(
    flow: GateWorld,
) -> None:
    """T-11-13: the analyzer walked three functions, and the citations show it.

    The ceiling has to be reachable or the rule is just a cap that always
    binds, and a claim nobody can ever make is not a claim.
    """
    flow_units = flow.ids_with_role(UnitRole.FLOW_FUNCTION)
    outcome = verify(
        make_adjudication(
            flow.context,
            cited_evidence_ids=[flow.evidence(0), *flow_units],
            cwe="CWE-125",
            cwe_rationale="The offset is read past the end of the string.",
            reachability=Reachability.DEMONSTRATED,
        ),
        flow.context,
        flow.index,
        flow.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is True
    assert outcome.finding is not None
    assert outcome.finding.reachability is Reachability.DEMONSTRATED
    assert outcome.downgrades == []


def test_a_resolved_call_edge_is_reachability_evidence(bounds: GateWorld) -> None:
    """The compiler's own answer about whether one function reaches another."""
    world_outcome = _verify(bounds, reachability=Reachability.DEMONSTRATED)
    assert world_outcome.finding is not None
    assert world_outcome.finding.reachability is Reachability.ARGUED

    with_edge = _verify(
        bounds,
        reachability=Reachability.DEMONSTRATED,
        exploitability=Exploitability.PLAUSIBLE,
        asserted_call_edges=[CallEdgeClaim(caller="copy_into", callee="copy_into")],
    )
    # The self-edge does not exist, so this still downgrades — the point is
    # that an *asserted* edge is not evidence until the index agrees.
    assert ReviewReason.CALL_EDGE_UNRESOLVED in with_edge.reasons


def test_an_edge_the_index_confirms_raises_both_ceilings(flow: GateWorld) -> None:
    outcome = verify(
        make_adjudication(
            flow.context,
            cwe="CWE-125",
            cwe_rationale="The offset is read past the end of the string.",
            reachability=Reachability.DEMONSTRATED,
            exploitability=Exploitability.DEMONSTRATED,
            asserted_call_edges=[CallEdgeClaim(caller="stage_one", callee="stage_two")],
        ),
        flow.context,
        flow.index,
        flow.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert outcome.accepted is True
    assert outcome.finding is not None
    assert outcome.finding.reachability is Reachability.DEMONSTRATED
    assert outcome.finding.exploitability is Exploitability.DEMONSTRATED


# --------------------------------------------------------- T-11-16 and T-11-17


def test_a_fully_valid_adjudication_is_confirmed_with_computed_confidence(
    bounds: GateWorld,
) -> None:
    """T-11-16: everything resolves, so the finding is high-confidence."""
    outcome = _verify(bounds)

    assert outcome.accepted is True
    assert outcome.review_item is None
    assert outcome.finding is not None
    assert outcome.finding.confidence is Confidence.HIGH
    assert outcome.finding.confidence_reason is ReviewReason.ALL_CITATIONS_RESOLVED
    assert outcome.resolution_rate == 1.0


def test_confidence_is_computed_and_never_read_from_the_self_report(
    bounds: GateWorld,
) -> None:
    """T-11-17: two citations fail while the model reports ``high``.

    How sure a model says it is, is not evidence about anything. The two
    directions are both tested: a confident answer that fails, and a
    self-doubting answer that holds.
    """
    outcome = _verify(
        bounds,
        cited_evidence_ids=["ev-0000000000000000", "ev-1111111111111111"],
        confidence_self_report=Confidence.HIGH,
    )

    assert outcome.accepted is False
    assert outcome.review_item is not None
    assert outcome.review_item.finding.confidence is Confidence.REVIEW_REQUIRED
    assert outcome.review_item.finding.confidence_reason is ReviewReason.CITATION_UNRESOLVED


def test_a_self_doubting_answer_whose_citations_hold_is_still_confirmed(
    bounds: GateWorld,
) -> None:
    outcome = _verify(bounds, confidence_self_report=Confidence.MEDIUM)
    assert outcome.accepted is True
    assert outcome.finding is not None
    assert outcome.finding.confidence is Confidence.HIGH


def test_the_self_report_is_not_copied_onto_the_finding(bounds: GateWorld) -> None:
    """Structural: the finding has no field that could carry it."""
    assert "confidence_self_report" not in _verify(bounds).finding.model_dump()  # type: ignore[union-attr]


# ------------------------------------------------------------------- T-11-19


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    fabricated=st.lists(
        st.text(alphabet="0123456789abcdef", min_size=8, max_size=16).map(lambda s: f"ev-{s}"),
        min_size=0,
        max_size=3,
        unique=True,
    ),
    real_count=st.integers(min_value=0, max_value=2),
    reachability=st.sampled_from(list(Reachability)),
    exploitability=st.sampled_from(list(Exploitability)),
)
def test_no_confirmed_finding_ever_has_an_unresolved_citation(
    bounds: GateWorld,
    fabricated: list[str],
    real_count: int,
    reachability: Reachability,
    exploitability: Exploitability,
) -> None:
    """T-11-19: the property the whole product claim rests on.

    Generated over the two things a model controls that can break clause 1 —
    which ids it cites and how strongly it claims — because those are the
    inputs an adversary actually has. Whatever comes out, an accepted outcome
    has no failed resolution in it and no blocking reason on it.
    """
    issued = list(bounds.context.evidence_ids()[:real_count])
    cited = [*issued, *(name for name in fabricated if name not in issued)]
    if not cited:
        cited = [bounds.evidence(0)]

    outcome = _verify(
        bounds,
        cited_evidence_ids=cited,
        reachability=reachability,
        exploitability=exploitability,
    )

    if outcome.accepted:
        assert outcome.finding is not None
        assert all(resolution.ok for resolution in outcome.resolutions)
        assert not [
            reason
            for reason in outcome.reasons
            if reason not in _DOWNGRADE_ONLY and reason is not ReviewReason.ALL_CITATIONS_RESOLVED
        ]
        assert outcome.finding.is_confirmed
    else:
        assert outcome.review_item is not None
        assert outcome.review_item.finding.is_confirmed is False


# ------------------------------------------------------------------- T-11-20


def test_no_output_type_can_express_a_merged_count() -> None:
    """T-11-20: the separation is not a convention this package follows.

    Asserted over the field names *and* the properties, because either one
    could grow a ``total`` and the report would be wrong in the one way the
    spec calls a hard gate.
    """
    forbidden = ("total", "count", "all_findings", "sum")
    for model in (GateOutcome, ReviewItem):
        names = set(model.model_fields)
        names |= {
            name
            for name, value in vars(model).items()
            if isinstance(value, property) and not name.startswith("_")
        }
        offenders = [name for name in names if any(word in name.lower() for word in forbidden)]
        assert offenders == [], f"{model.__name__} exposes {offenders}"


def test_a_refused_outcome_always_carries_its_item(bounds: GateWorld) -> None:
    """ "Nothing is discarded" as a validator, not a habit."""
    with pytest.raises(ValueError, match="carries a review item and no finding"):
        GateOutcome(accepted=False)
    with pytest.raises(ValueError, match="carries a finding and no review item"):
        GateOutcome(accepted=True)


def test_a_review_item_cannot_hold_a_confirmed_finding(bounds: GateWorld) -> None:
    confirmed = _verify(bounds).finding
    assert confirmed is not None
    with pytest.raises(ValueError, match="counted as a confirmed vulnerability"):
        ReviewItem(finding=confirmed, reasons=[ReviewReason.HASH_MISMATCH])


def test_an_accepted_outcome_cannot_carry_a_blocking_reason(bounds: GateWorld) -> None:
    """Belt and braces over the acceptance rule, checked by the type."""
    confirmed = _verify(bounds).finding
    with pytest.raises(ValueError, match="accepted with 1 blocking reason"):
        GateOutcome(accepted=True, finding=confirmed, reasons=[ReviewReason.CITATION_UNRESOLVED])


def test_a_downgrade_reason_does_not_block_acceptance(bounds: GateWorld) -> None:
    """The one exception, and it is a named constant rather than a special case."""
    assert {ReviewReason.IMPACT_EXCEEDS_EVIDENCE} == _DOWNGRADE_ONLY
    outcome = _verify(bounds, reachability=Reachability.DEMONSTRATED)
    assert outcome.accepted is True
    assert outcome.reasons == [ReviewReason.IMPACT_EXCEEDS_EVIDENCE]


# ------------------------------------------------------------------- T-11-21


def test_the_gate_completes_with_every_socket_disabled(
    bounds: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-11-21: a gate that could ask a model whether its own output was good.

    Not asserted by counting calls afterwards — the socket module is made to
    raise, so an attempt fails at the point it happens with a stack that names
    it.
    """

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the verification gate opened a connection")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    first = _verify(bounds)
    second = _verify(bounds)

    assert first.accepted is True
    assert first.model_dump() == second.model_dump()


def test_the_gate_takes_no_provider_and_no_consent() -> None:
    """The strongest form of "model-free": there is nowhere to pass a model."""
    parameters = set(inspect.signature(verify).parameters)
    assert not parameters & {"provider", "consent", "llm", "account", "cache"}


# ------------------------------------------------------------------- T-11-22


def test_fifty_runs_with_shuffled_citations_agree_exactly(bounds: GateWorld) -> None:
    """T-11-22: same outcome, same reasons, in the same order, every time.

    Shuffling the citation order is the interesting perturbation: it is the one
    thing about an answer that carries no meaning, so any effect it has on the
    output is an ordering bug rather than a decision.
    """
    issued = list(bounds.context.evidence_ids()[:3])
    baseline = _verify(
        bounds,
        cited_evidence_ids=issued,
        reachability=Reachability.DEMONSTRATED,
        cwe="CWE-416",
    )
    rng = random.Random(20260812)

    for _ in range(50):
        shuffled = issued[:]
        rng.shuffle(shuffled)
        outcome = _verify(
            bounds,
            cited_evidence_ids=shuffled,
            reachability=Reachability.DEMONSTRATED,
            cwe="CWE-416",
        )
        assert outcome.accepted == baseline.accepted
        assert outcome.reasons == baseline.reasons
        assert outcome.details == baseline.details
        assert [item.status for item in outcome.resolutions] == [
            item.status for item in baseline.resolutions
        ]


def test_two_runs_produce_byte_identical_serialized_outcomes(bounds: GateWorld) -> None:
    """What a report is rendered from, compared the way a report is compared."""
    first = _verify(bounds, reachability=Reachability.DEMONSTRATED)
    second = _verify(bounds, reachability=Reachability.DEMONSTRATED)
    assert first.model_dump_json() == second.model_dump_json()


def test_the_gate_reads_no_clock(bounds: GateWorld, monkeypatch: pytest.MonkeyPatch) -> None:
    """A timestamp anywhere in the outcome would break the comparison above."""
    import time

    def refuse() -> float:
        raise AssertionError("the verification gate read the clock")

    monkeypatch.setattr(time, "time", refuse)
    monkeypatch.setattr(time, "monotonic", refuse)
    assert _verify(bounds).accepted is True


# ------------------------------------------------------------- the audit trail


def test_every_claim_the_gate_checked_is_in_the_trail(bounds: GateWorld) -> None:
    outcome = _verify(
        bounds,
        cited_evidence_ids=list(bounds.context.evidence_ids()[:3]),
        asserted_call_edges=[CallEdgeClaim(caller="caller_a", callee="long_walk")],
    )
    labels = [resolution.citation.label for resolution in outcome.resolutions]
    assert labels.count("candidate_location") == 1
    assert labels.count("cited_evidence") == 3
    assert labels.count("asserted_call_edge") == 1


def test_the_resolution_rate_is_vacuously_complete_with_nothing_to_check(
    bounds: GateWorld,
) -> None:
    assert GateOutcome(accepted=True, finding=_verify(bounds).finding).resolution_rate == 1.0


def test_the_finding_carries_the_contexts_own_limitations(tmp_path: Path) -> None:
    """Part 11 does not get to drop what part 09 recorded about this candidate."""
    world = gate_world(
        tmp_path, "indirect", "indirect.c", 24, cwe=("CWE-476",), message="may be null"
    )
    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-476",
            cwe_rationale="The table entry is dereferenced without a null check.",
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    finding = outcome.finding or (outcome.review_item.finding if outcome.review_item else None)
    assert finding is not None
    for limitation in world.context.limitations:
        assert limitation in finding.limitations


def test_a_model_provenance_record_is_appended_not_substituted(bounds: GateWorld) -> None:
    """The analyzer's provenance is what part 04 measures bias with; it stays."""
    from caudit.model.evidence import Producer, Provenance

    record = Provenance(
        producer=Producer.LLM, tool_name="gemini-flash-latest", tool_version="2026-08"
    )
    outcome = verify(
        make_adjudication(bounds.context),
        bounds.context,
        bounds.index,
        bounds.store,
        analyzers=ANALYZERS_THAT_RAN,
        model_provenance=record,
    )
    assert outcome.finding is not None
    assert outcome.finding.provenance[:-1] == list(bounds.context.candidate.provenance)
    assert outcome.finding.provenance[-1] == record


def test_a_review_item_whose_reasons_omit_its_own_finding_is_refused(
    bounds: GateWorld,
) -> None:
    """The report and the audit trail cannot be allowed to disagree."""
    item = _verify(bounds, cited_evidence_ids=["ev-0000000000000000"]).review_item
    assert item is not None
    with pytest.raises(ValueError, match="not among the reasons the gate recorded"):
        ReviewItem(finding=item.finding, reasons=[ReviewReason.OUT_OF_SCOPE_FAMILY])


def test_a_dropped_unit_alone_contradicts_an_empty_assumption_list(
    bounds: GateWorld,
) -> None:
    """The two contradictions are independent, and either one is enough.

    ``indirect`` covers the limitations half. This covers the drops half, on a
    context that records no limitations at all, so neither test can pass on the
    strength of the other.
    """
    from caudit.retrieval.context import DroppedUnit, DropReason

    assert bounds.context.limitations == []
    dropped = DroppedUnit(
        unit=bounds.context.units[-1], reason=DropReason.MAX_UNITS, detail="breadth cap"
    )
    context = bounds.context.model_copy(update={"dropped": [dropped]})

    outcome = verify(
        make_adjudication(context, unresolved_assumptions=[]),
        context,
        bounds.index,
        bounds.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert ReviewReason.ASSUMPTIONS_UNSTATED in outcome.reasons
    detail = next(line for line in outcome.details if "assumptions_unstated" in line)
    assert "1 retrieved unit(s) did not fit" in detail
    assert "blind spot" not in detail


def test_an_empty_assumption_list_stands_when_nothing_contradicts_it(
    bounds: GateWorld,
) -> None:
    """ "There are none" is a claim, and on a clean context it is a true one.

    The clause is a contradiction check, not a requirement to write something.
    A gate that demanded an assumption from every answer would teach a model to
    invent one.
    """
    assert bounds.context.dropped == []
    assert bounds.context.limitations == []
    outcome = _verify(bounds, unresolved_assumptions=[])
    assert outcome.accepted is True
    assert ReviewReason.ASSUMPTIONS_UNSTATED not in outcome.reasons


def test_a_fabricated_usr_is_reported_as_a_fabricated_name(flow: GateWorld) -> None:
    """A USR is checked by identity, and an invented one identifies nothing."""
    outcome = verify(
        make_adjudication(
            flow.context,
            cwe="CWE-125",
            cwe_rationale="The offset is read past the end of the string.",
            asserted_call_edges=[CallEdgeClaim(caller="stage_one", callee="c:@F@validate_input")],
        ),
        flow.context,
        flow.index,
        flow.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert outcome.accepted is False
    assert ReviewReason.SYMBOL_UNRESOLVED in outcome.reasons
    assert any("validate_input" in line for line in outcome.details)


def test_an_edge_asserted_by_usr_resolves_by_identity(flow: GateWorld) -> None:
    """A USR is how the index names a symbol; the gate accepts the same names."""
    symbol = flow.index.symbols_named("stage_two")[0]
    outcome = verify(
        make_adjudication(
            flow.context,
            cwe="CWE-125",
            cwe_rationale="The offset is read past the end of the string.",
            asserted_call_edges=[CallEdgeClaim(caller="stage_one", callee=symbol.usr)],
        ),
        flow.context,
        flow.index,
        flow.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert outcome.accepted is True


def test_a_quotation_of_a_cited_but_unissued_id_is_a_citation_failure(
    bounds: GateWorld,
) -> None:
    """Coherent as an object, unresolvable as a claim — and told apart from a mismatch.

    Part 10's validator only requires a quotation to name something the answer
    cited. Whether that id was ever *issued* is a question about this run, and
    the answer here is "no bytes to compare against", not "the bytes differ".
    """
    from caudit.model.adjudication import Quotation

    outcome = _verify(
        bounds,
        cited_evidence_ids=["ev-0000000000000000"],
        quoted_evidence=[Quotation(evidence_id="ev-0000000000000000", text="anything")],
    )
    assert outcome.accepted is False
    assert ReviewReason.HASH_MISMATCH not in outcome.reasons
    assert any("quotes evidence id" in line for line in outcome.details)


def test_a_model_provenance_record_is_not_held_to_the_analyzer_set(
    bounds: GateWorld,
) -> None:
    """Holding it to that set would reject every finding a model touched."""
    from caudit.model.evidence import Producer, Provenance

    outcome = verify(
        make_adjudication(bounds.context),
        bounds.context,
        bounds.index,
        bounds.store,
        analyzers=ANALYZERS_THAT_RAN,
        model_provenance=Provenance(
            producer=Producer.LLM, tool_name="a-model-that-is-not-an-analyzer", tool_version="1"
        ),
    )
    assert outcome.accepted is True

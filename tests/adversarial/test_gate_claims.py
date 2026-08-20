"""Clauses 2, 3 and 4: the weakness, the strength of the claim, the gaps.

T-11-09 through T-11-15, plus T-11-18 and T-11-23.

Clause 3 is the only place in the gate where a failed check keeps the finding,
so most of what these tests pin down is the *shape* of a downgrade: which value
survives, that a cautious claim is never raised to meet the evidence, and that
the weakening reaches the page rather than being applied silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Impact,
    ImpactKind,
    LimitationKind,
    Reachability,
    ReviewReason,
    Severity,
)
from caudit.retrieval.policy import UnitRole
from caudit.verify import verify
from tests.conftest import ANALYZERS_THAT_RAN, GateWorld, gate_world, make_adjudication


@pytest.fixture(scope="module")
def bounds(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    """A copy under a macro guard: a write, a buffer, and no release anywhere."""
    return gate_world(
        tmp_path_factory.mktemp("gate-bounds"),
        "macro_bounds",
        "macro_bounds.c",
        27,
        message="the copy is not bounded by the destination's declared size",
        cwe=("CWE-787",),
    )


@pytest.fixture(scope="module")
def flow(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    """A source-to-sink path the analyzer itself walked, across three functions."""
    return gate_world(
        tmp_path_factory.mktemp("gate-flow"),
        "expansion",
        "expansion.c",
        248,
        message="the offset may exceed the string's length",
        cwe=("CWE-125",),
        flow=(258, 253, 248),
    )


def _verify(world: GateWorld, **overrides: object):  # type: ignore[no-untyped-def]
    return verify(
        make_adjudication(world.context, **overrides),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )


# --------------------------------------------------------- T-11-09 and T-11-10


def test_a_use_after_free_argued_from_evidence_with_no_release_site(
    bounds: GateWorld,
) -> None:
    """T-11-09: CWE-416 is an argument about what happens after a release."""
    outcome = _verify(bounds, cwe="CWE-416", cwe_rationale="The buffer is reused after release.")

    assert outcome.accepted is False
    assert ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE in outcome.reasons
    detail = next(line for line in outcome.details if "evidence_does_not_support_cwe" in line)
    assert "a release site" in detail
    # The rejection says the check is lexical, so a reader can tell "not cited"
    # from "written in a form this does not recognise".
    assert "lexical" in detail


def test_an_out_of_bounds_write_argued_from_a_declaration_alone(bounds: GateWorld) -> None:
    """T-11-10: CWE-787 needs the write, not only the buffer it would overflow."""
    declarations = bounds.ids_with_role(UnitRole.TYPE_DECL, UnitRole.MACRO_DEF)
    outcome = _verify(bounds, cited_evidence_ids=declarations)
    assert outcome.accepted is False
    assert ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE in outcome.reasons
    assert any("a write into memory" in line for line in outcome.details)


def test_the_same_evidence_supports_the_read_variant(bounds: GateWorld) -> None:
    """The split between write and read variants is real, not decoration.

    ``CWE-125`` asks for an access and the declarations contain a subscript;
    ``CWE-787`` asks for a write and they do not. A family-wide rule would
    accept both or reject both.
    """
    outcome = _verify(
        bounds,
        cited_evidence_ids=bounds.ids_with_role(UnitRole.TYPE_DECL),
        cwe="CWE-125",
        cwe_rationale="The index is read past the end of the declared buffer.",
    )
    assert ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE not in outcome.reasons


def test_a_precondition_check_is_never_run_on_evidence_that_did_not_resolve(
    bounds: GateWorld,
) -> None:
    """One fault, one reason.

    With nothing citable, "the evidence does not support the weakness" is a
    statement about an argument that does not exist, and reporting it beside
    ``citation_unresolved`` would charge the reviewer twice for one mistake.
    """
    outcome = _verify(bounds, cited_evidence_ids=["ev-0000000000000000"])
    assert ReviewReason.CITATION_UNRESOLVED in outcome.reasons
    assert ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE not in outcome.reasons


# --------------------------------------------------------- T-11-11 and T-11-12


def test_demonstrated_reachability_with_no_control_flow_evidence_is_downgraded(
    bounds: GateWorld,
) -> None:
    """T-11-11: the finding survives at the lower claim, and says that it did."""
    outcome = _verify(bounds, reachability=Reachability.DEMONSTRATED)

    assert outcome.accepted is True, "a downgrade keeps the finding"
    assert outcome.finding is not None
    assert outcome.finding.reachability is Reachability.ARGUED
    assert ReviewReason.IMPACT_EXCEEDS_EVIDENCE in outcome.reasons

    # Recorded twice: as a reason on the outcome, and as a limitation on the
    # finding, which is what carries it to the page.
    downgraded = [
        limitation
        for limitation in outcome.finding.limitations
        if limitation.kind is LimitationKind.CLAIM_DOWNGRADED
    ]
    assert len(downgraded) == 1
    assert "proposed as demonstrated" in downgraded[0].detail
    assert "reported as argued" in downgraded[0].detail


def test_demonstrated_exploitability_from_a_local_buffer_alone_is_downgraded(
    bounds: GateWorld,
) -> None:
    """T-11-12: nothing upstream was cited, so nothing shows attacker influence."""
    outcome = _verify(bounds, exploitability=Exploitability.DEMONSTRATED)

    assert outcome.accepted is True
    assert outcome.finding is not None
    assert outcome.finding.exploitability is Exploitability.UNLIKELY
    assert ReviewReason.IMPACT_EXCEEDS_EVIDENCE in outcome.reasons
    assert any("attacker influences" in line for line in outcome.details)


def test_a_downgrade_lowers_confidence_without_rejecting_the_finding(
    bounds: GateWorld,
) -> None:
    """Something in it was weakened, so ``high`` would report the refused claim."""
    outcome = _verify(bounds, reachability=Reachability.DEMONSTRATED)
    assert outcome.finding is not None
    assert outcome.finding.confidence is Confidence.MEDIUM
    assert outcome.finding.is_confirmed is True


def test_a_cautious_claim_is_never_raised_to_meet_the_evidence(flow: GateWorld) -> None:
    """The rule is a ceiling, not a correction.

    This context supports ``demonstrated``. A model that says ``unknown``
    anyway is being conservative, and a gate that "fixed" that would be
    inventing a claim nobody made.
    """
    outcome = verify(
        make_adjudication(
            flow.context,
            cwe="CWE-125",
            cwe_rationale="The offset is read past the end of the string.",
            reachability=Reachability.UNKNOWN,
            exploitability=Exploitability.UNKNOWN,
        ),
        flow.context,
        flow.index,
        flow.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert outcome.finding is not None
    assert outcome.finding.reachability is Reachability.UNKNOWN
    assert outcome.finding.exploitability is Exploitability.UNKNOWN
    assert outcome.downgrades == []


# --------------------------------------------------------- T-11-14 and T-11-15


def test_no_assumptions_while_the_budget_dropped_units(tmp_path: Path) -> None:
    """T-11-14: an empty list is a claim, and this run contradicts it."""
    config = Config.model_validate({"token_budget": {"per_candidate": 1500}})
    world = gate_world(tmp_path, "expansion", "expansion.c", 44, config=config, cwe=("CWE-190",))
    assert len(world.context.dropped) == 3

    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-190",
            cwe_rationale="The running total wraps at the width it is accumulated in.",
            unresolved_assumptions=[],
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.ASSUMPTIONS_UNSTATED in outcome.reasons
    assert any("3 retrieved unit(s) did not fit" in line for line in outcome.details)


def test_no_assumptions_while_the_index_recorded_an_indirect_call(tmp_path: Path) -> None:
    """T-11-15: the caller set was incomplete and the answer said nothing was."""
    world = gate_world(
        tmp_path,
        "indirect",
        "indirect.c",
        24,
        cwe=("CWE-476",),
        message="the selected handler may be null",
    )
    assert any(
        limitation.kind is LimitationKind.UNRESOLVED_INDIRECT_CALL
        for limitation in world.context.limitations
    )

    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-476",
            cwe_rationale="The table entry is dereferenced without a null check.",
            unresolved_assumptions=[],
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.ASSUMPTIONS_UNSTATED in outcome.reasons
    assert any("unresolved_indirect_call" in line for line in outcome.details)


def test_stating_any_assumption_satisfies_the_clause(tmp_path: Path) -> None:
    """Judging *which* assumptions were named would be judging the answer.

    A deterministic gate can check that a claim of "none" is contradicted. It
    cannot check that the assumptions someone did state are the right ones, and
    pretending otherwise would put an opinion in a component whose whole value
    is that it has none.
    """
    world = gate_world(
        tmp_path, "indirect", "indirect.c", 24, cwe=("CWE-476",), message="may be null"
    )
    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-476",
            cwe_rationale="The table entry is dereferenced without a null check.",
            unresolved_assumptions=["something unrelated to the indirect call"],
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert ReviewReason.ASSUMPTIONS_UNSTATED not in outcome.reasons


# ------------------------------------------------------------------- T-11-18


def test_three_independent_faults_are_all_reported(tmp_path: Path) -> None:
    """T-11-18: a bad hash, a bad CWE, and no assumptions, all in one answer.

    Reporting only the first would send the reviewer back three times. The
    ``indirect`` fixture is used because it is the one that comes with a
    genuine gap — an unresolved indirect call — for the empty assumption list
    to contradict.
    """
    from caudit.model.adjudication import Quotation

    world = gate_world(
        tmp_path, "indirect", "indirect.c", 24, cwe=("CWE-476",), message="may be null"
    )
    outcome = verify(
        make_adjudication(
            world.context,
            cwe="CWE-664",
            cwe_rationale="Improper control of a resource through its lifetime.",
            unresolved_assumptions=[],
            quoted_evidence=[
                Quotation(
                    evidence_id=world.evidence(0),
                    text="return handlers[which & 2](value);",
                )
            ],
        ),
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )

    assert outcome.accepted is False
    assert ReviewReason.HASH_MISMATCH in outcome.reasons
    assert ReviewReason.CWE_MAPPING_REJECTED in outcome.reasons
    assert ReviewReason.ASSUMPTIONS_UNSTATED in outcome.reasons
    assert len(outcome.details) >= 3
    # The item carries them all, not just the one on the finding.
    assert outcome.review_item is not None
    assert set(outcome.review_item.reasons) >= {
        ReviewReason.HASH_MISMATCH,
        ReviewReason.CWE_MAPPING_REJECTED,
        ReviewReason.ASSUMPTIONS_UNSTATED,
    }
    # The finding carries the most severe one; the rest are not lost.
    assert outcome.review_item.finding.confidence_reason is ReviewReason.HASH_MISMATCH


def test_a_quotation_may_be_one_line_out_of_a_whole_function(bounds: GateWorld) -> None:
    """Containment, not equality — a region is a function and a quote is a line."""
    from caudit.model.adjudication import Quotation

    outcome = _verify(
        bounds,
        quoted_evidence=[
            Quotation(evidence_id=bounds.evidence(0), text="frame->buf[index] = src[index]")
        ],
    )
    assert outcome.accepted is True


def test_a_prohibited_mapping_names_the_entries_to_use_instead(bounds: GateWorld) -> None:
    """A rejection a reader cannot act on is a rejection they will argue with."""
    outcome = _verify(
        bounds,
        cwe="CWE-664",
        cwe_rationale="A buffer overflow write past the end of the destination.",
    )
    detail = next(line for line in outcome.details if "cwe_mapping_rejected" in line)
    assert "Class or Pillar" in detail
    assert "CWE-787" in detail


# ------------------------------------------------------------------- T-11-23


def test_an_out_of_scope_family_is_kept_in_review_rather_than_dropped(
    bounds: GateWorld,
) -> None:
    """T-11-23: an over-strict allowlist must not silently suppress a defect."""
    outcome = _verify(
        bounds,
        cwe="CWE-327",
        cwe_rationale="A broken cryptographic algorithm is in use here.",
    )

    assert outcome.accepted is False
    assert ReviewReason.OUT_OF_SCOPE_FAMILY in outcome.reasons
    assert outcome.review_item is not None

    # Kept, not dropped: the item still describes the candidate, at its
    # location, with the analyzer's own classification standing in.
    finding = outcome.review_item.finding
    assert finding.location == bounds.context.candidate.region
    assert finding.cwe == "CWE-787"
    assert "CWE-327" in finding.cwe_rationale
    assert "cannot carry" in finding.cwe_rationale


def test_a_discouraged_mapping_needs_a_rationale(bounds: GateWorld) -> None:
    outcome = _verify(bounds, cwe="CWE-119", cwe_rationale="   ")
    assert outcome.accepted is False
    assert ReviewReason.CWE_MAPPING_REJECTED in outcome.reasons
    assert any("discouraged" in line for line in outcome.details)


def test_a_confirmation_naming_no_weakness_is_refused_at_construction(
    bounds: GateWorld,
) -> None:
    """Part 10 already refuses this shape; part 11 never sees it.

    Recorded here because the gate's ``cwe is None`` branch is what handles a
    *rejection*, and it would be easy to read that branch as the place a
    confirmation with no CWE is caught. It is not — the object cannot exist.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="must say which weakness"):
        make_adjudication(bounds.context, cwe=None)


# ------------------------------------------------- the model's own two verdicts


def test_a_model_rejection_keeps_the_candidate_in_the_report(bounds: GateWorld) -> None:
    """Deleting an analyzer's diagnostic on a model's word is the failure to avoid."""
    outcome = _verify(
        bounds,
        verdict="rejected",
        cwe=None,
        cwe_rationale="The macro guard bounds len before the loop; the analyzer missed it.",
    )

    assert outcome.accepted is False
    assert outcome.reasons == [ReviewReason.MODEL_REJECTED]
    assert outcome.review_item is not None
    assert outcome.review_item.finding.confidence_reason is ReviewReason.MODEL_REJECTED
    # The model's argument travels with it, so a human can confirm the dismissal.
    assert "macro guard" in outcome.details[0]


def test_a_model_that_could_not_tell_is_not_a_model_that_disagreed(
    bounds: GateWorld,
) -> None:
    """Two answers, two reasons. Merging them would lose which one was given."""
    outcome = _verify(
        bounds,
        verdict="review_required",
        confidence_self_report=Confidence.REVIEW_REQUIRED,
        unresolved_assumptions=["the caller's len is not shown"],
    )

    assert outcome.accepted is False
    assert outcome.reasons == [ReviewReason.MODEL_INCONCLUSIVE]
    assert "the caller's len is not shown" in outcome.details[0]


def test_a_rejection_with_a_fabricated_citation_reports_both(bounds: GateWorld) -> None:
    """A rejection is still an answer, and its evidence is still checked."""
    outcome = _verify(
        bounds,
        verdict="rejected",
        cwe=None,
        cwe_rationale="The guard is present.",
        cited_evidence_ids=["ev-0000000000000000"],
    )
    assert {ReviewReason.CITATION_UNRESOLVED, ReviewReason.MODEL_REJECTED} <= set(outcome.reasons)


def test_the_impact_reported_is_the_one_the_model_argued(bounds: GateWorld) -> None:
    """Impact is not recomputed here. Only reachability and exploitability are.

    They are three separate fields and the gate weakens two of them on
    evidence; inferring the third from either would be the exact conflation the
    schema exists to prevent.
    """
    impact = Impact(
        kind=ImpactKind.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        description="Control of the return address.",
        evidence_supports="The cited copy overruns a stack buffer.",
    )
    outcome = _verify(bounds, impact=impact, reachability=Reachability.DEMONSTRATED)
    assert outcome.finding is not None
    assert outcome.finding.impact == impact
    assert outcome.finding.reachability is Reachability.ARGUED

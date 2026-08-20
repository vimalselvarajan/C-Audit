"""Part 10 into part 11, offline: the Milestone 2 path end to end.

The unit and adversarial suites hand the gate an ``Adjudication`` built in the
test. This one takes the object that actually comes back from a provider — via
a committed cassette, through the real retry loop and the real
``model_validate_json`` — and puts it through the gate. What that adds is the
seam: the two parts agree about evidence ids, about which reasons mean what,
and about the fact that an outcome carrying a reason instead of a proposal
never reaches the gate at all.

Still no socket and no key. Part 10's cassettes are the whole model here.
"""

from __future__ import annotations

import pytest

from caudit.config.loader import Config
from caudit.llm.service import RunAccount, Verdict, adjudicate
from caudit.model.finding import Confidence, ReviewReason
from caudit.report.sections import build_sections
from caudit.verify import verify
from tests.conftest import (
    ANALYZERS_THAT_RAN,
    GateWorld,
    cassette_provider,
    demo_coverage,
    gate_world,
    granted_consent,
    no_sleep,
)


def _config() -> Config:
    return Config.model_validate({"llm": {"triage_enabled": False, "cache_enabled": False}})


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    return gate_world(
        tmp_path_factory.mktemp("verify-pipeline"),
        "macro_bounds",
        "macro_bounds.c",
        27,
        message="the copy is not bounded by the destination's declared size",
        cwe=("CWE-787",),
    )


def _adjudicate(world: GateWorld, cassette: str):  # type: ignore[no-untyped-def]
    config = _config()
    provider, _ = cassette_provider(cassette, evidence_ids=world.context.evidence_ids())
    return adjudicate(
        world.context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )


def test_a_recorded_confirmation_survives_the_gate(world: GateWorld) -> None:
    """The happy path, with a real provider answer rather than a hand-built one."""
    outcome = _adjudicate(world, "adjudication-confirmed")
    assert outcome.adjudication is not None
    assert outcome.adjudication.verdict is Verdict.CONFIRMED

    gated = verify(
        outcome.adjudication,
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert gated.accepted is True
    assert gated.finding is not None
    assert gated.finding.confidence is Confidence.HIGH
    assert gated.resolution_rate == 1.0


def test_a_recorded_rejection_stays_in_the_report(world: GateWorld) -> None:
    outcome = _adjudicate(world, "adjudication-rejected")
    assert outcome.adjudication is not None
    assert outcome.adjudication.verdict is Verdict.REJECTED

    gated = verify(
        outcome.adjudication,
        world.context,
        world.index,
        world.store,
        analyzers=ANALYZERS_THAT_RAN,
    )
    assert gated.accepted is False
    assert gated.review_item is not None
    assert gated.review_item.finding.confidence_reason is ReviewReason.MODEL_REJECTED


def test_an_outcome_with_no_proposal_never_reaches_the_gate(world: GateWorld) -> None:
    """Part 10's refusals are already reasons; there is nothing left to verify.

    Asserted as a property of the two types rather than by convention: the
    gate's first argument is an ``Adjudication``, and a refused outcome does not
    have one to give it.
    """
    outcome = _adjudicate(world, "adjudication-prose")
    assert outcome.adjudication is None
    assert outcome.review_reason is ReviewReason.SCHEMA_INVALID_RESPONSE


@pytest.fixture(scope="module")
def second(tmp_path_factory: pytest.TempPathFactory) -> GateWorld:
    """A second candidate, so a report can hold one of each.

    It has to be a different candidate rather than a second verdict on the
    same one: ``finding_id`` addresses the defect, not the run, so two
    adjudications of one candidate collide by design.
    """
    return gate_world(
        tmp_path_factory.mktemp("verify-pipeline-2"),
        "macro_bounds",
        "macro_bounds.c",
        29,
        message="the recorded length is not the length that was copied",
        cwe=("CWE-787",),
    )


def test_a_gated_finding_renders_into_the_report_sections(
    world: GateWorld, second: GateWorld
) -> None:
    """Part 11's output is what part 08 already knows how to render.

    This is the join part 12 will make, checked here so the two halves cannot
    drift apart before it does: a confirmed finding lands in ``confirmed``, a
    review item lands in ``needs_review``, and the two counts stay apart.
    """
    from caudit.evidence.resolver import CitationResolver

    confirmed = _adjudicate(world, "adjudication-confirmed").adjudication
    rejected = _adjudicate(second, "adjudication-rejected").adjudication
    assert confirmed is not None and rejected is not None

    accepted = verify(
        confirmed, world.context, world.index, world.store, analyzers=ANALYZERS_THAT_RAN
    )
    refused = verify(
        rejected, second.context, second.index, second.store, analyzers=ANALYZERS_THAT_RAN
    )
    assert accepted.finding is not None
    assert refused.review_item is not None

    sections = build_sections(
        [accepted.finding, refused.review_item.finding],
        resolver=CitationResolver(world.store, world.context.bundle),
        coverage=demo_coverage(),
    )
    assert sections.confirmed_count == 1
    assert sections.review_count == 1
    assert sections.confirmed[0].finding_id != sections.needs_review[0].finding_id
    # Part 08's own gate re-resolves what part 11 already resolved, and agrees.
    assert sections.unresolved == {}


def test_every_id_part_10_issued_is_an_id_part_11_accepts(world: GateWorld) -> None:
    """The seam itself: one notion of "what may be cited", not two.

    Part 10 checks the ids against the assembled prompt; part 11 checks them
    against the context. If those two ever disagreed, an answer could pass the
    cheap check and fail the authoritative one for no reason a user could act
    on.
    """
    config = _config()
    provider, _ = cassette_provider(
        "adjudication-confirmed", evidence_ids=world.context.evidence_ids()
    )
    adjudicate(
        world.context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )
    issued_to_the_prompt = set(provider.requests[0].prompt.evidence_ids)
    assert issued_to_the_prompt == set(world.context.evidence_ids())

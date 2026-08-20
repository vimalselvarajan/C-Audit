"""The whole part 10 path, end to end, offline.

Retrieval assembles a context from a real index, the tiers are routed by the
one truth table, and every answer arrives from a committed cassette. What these
tests cover that the unit tests do not is the *sequencing*: which tier is asked,
in what order, and what happens to the record of an exchange that was overtaken
by a later one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.llm.service import (
    AdjudicationOutcome,
    AttemptOutcome,
    CassetteProvider,
    RunAccount,
    Tier,
    TriageResult,
    Verdict,
    adjudicate,
    response_cache,
)
from caudit.model.finding import ReviewReason
from caudit.retrieval.context import EvidenceContext
from tests.conftest import (
    cassette_provider,
    granted_consent,
    no_sleep,
    retrieval_context,
)


def _config(**llm: object) -> Config:
    settings: dict[str, object] = {"triage_enabled": True, "cache_enabled": False}
    settings.update(llm)
    return Config.model_validate({"llm": settings})


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> EvidenceContext:
    return retrieval_context(
        tmp_path_factory.mktemp("pipeline"), "macro_bounds", "macro_bounds.c", 27
    )


def _adjudicate(
    context: EvidenceContext,
    cassette: str,
    config: Config,
    *,
    triage: TriageResult | None = None,
) -> tuple[AdjudicationOutcome, CassetteProvider, RunAccount]:
    provider, _ = cassette_provider(cassette, evidence_ids=context.evidence_ids())
    account = RunAccount(config=config)
    outcome = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        triage=triage,
        sleeper=no_sleep,
    )
    return outcome, provider, account


def test_triage_runs_first_and_the_adjudication_tier_answers(
    context: EvidenceContext,
) -> None:
    """The cheap tier is asked before the expensive one, and it shapes the route."""
    outcome, provider, account = _adjudicate(context, "triage-then-confirmed", _config())

    assert [request.tier for request in provider.requests] == [
        Tier.TRIAGE,
        Tier.ADJUDICATION,
    ]
    assert outcome.accepted
    assert outcome.tier is Tier.ADJUDICATION
    # Both tiers are billed, each against its own model id.
    assert account.accounts[Tier.TRIAGE].calls == 1
    assert account.accounts[Tier.ADJUDICATION].calls == 1
    assert account.accounts[Tier.ESCALATION].calls == 0


def test_an_ambiguous_high_impact_triage_goes_straight_to_escalation(
    context: EvidenceContext,
) -> None:
    """The escalation cell of the table, reached through the real pipeline."""
    outcome, provider, account = _adjudicate(
        context, "triage-ambiguous-high-then-review", _config()
    )

    assert [request.tier for request in provider.requests] == [
        Tier.TRIAGE,
        Tier.ESCALATION,
    ]
    assert outcome.tier is Tier.ESCALATION
    assert account.accounts[Tier.ADJUDICATION].calls == 0
    assert outcome.accepted


def test_a_triage_dismissal_leaves_the_candidate_in_the_report(
    context: EvidenceContext,
) -> None:
    """Triage decides which tier answers. It never removes a candidate."""
    outcome, provider, _account = _adjudicate(context, "triage-dismisses", _config())

    assert [request.tier for request in provider.requests] == [Tier.TRIAGE]
    assert outcome.tier is Tier.TRIAGE
    assert outcome.answered
    assert outcome.adjudication is None
    # analyzer_only is not a blocking reason: the analyzer's claim stands and
    # part 11 is still free to promote or route it.
    assert outcome.review_reason is ReviewReason.ANALYZER_ONLY
    detail = " ".join(item.detail for item in outcome.limitations)
    assert "not worth full adjudication" in detail
    assert "never what is reported" in detail


def test_an_ambiguous_high_impact_verdict_escalates_after_adjudication(
    context: EvidenceContext,
) -> None:
    """The adjudication answer re-enters the same table and is overtaken."""
    config = _config(triage_enabled=False)
    outcome, provider, account = _adjudicate(context, "adjudication-review-required-high", config)

    assert [request.tier for request in provider.requests] == [
        Tier.ADJUDICATION,
        Tier.ESCALATION,
    ]
    assert outcome.tier is Tier.ESCALATION
    assert outcome.adjudication is not None
    assert outcome.adjudication.verdict is Verdict.CONFIRMED

    # The overtaken exchange is kept: a run that asked twice is a different run
    # from one that asked once, and the accounting has to say so.
    assert len(outcome.attempts) == 2
    assert [attempt.tier for attempt in outcome.attempts] == [
        Tier.ADJUDICATION,
        Tier.ESCALATION,
    ]
    assert account.accounts[Tier.ADJUDICATION].calls == 1
    assert account.accounts[Tier.ESCALATION].calls == 1


def test_disabling_escalation_keeps_the_first_answer(context: EvidenceContext) -> None:
    config = _config(triage_enabled=False, allow_escalation=False)
    outcome, provider, _account = _adjudicate(context, "adjudication-review-required-high", config)

    assert [request.tier for request in provider.requests] == [Tier.ADJUDICATION]
    assert outcome.tier is Tier.ADJUDICATION
    assert outcome.adjudication is not None
    assert outcome.adjudication.verdict is Verdict.REVIEW_REQUIRED


def test_a_triage_failure_falls_through_to_adjudication(
    context: EvidenceContext,
) -> None:
    """A tier that will not answer must not stop the run or raise the stakes."""
    outcome, provider, account = _adjudicate(
        context, "triage-unanswerable-then-confirmed", _config()
    )
    # Three prose answers exhaust the triage attempts. Routing then uses the
    # assumed result, which is "adjudicate, ambiguous, impact unassessed".
    assert [request.tier for request in provider.requests] == [
        Tier.TRIAGE,
        Tier.TRIAGE,
        Tier.TRIAGE,
        Tier.ADJUDICATION,
    ]
    assert outcome.tier is Tier.ADJUDICATION
    assert outcome.accepted
    assert account.accounts[Tier.ESCALATION].calls == 0, (
        "a tier that would not answer must not raise the stakes"
    )


def test_a_supplied_triage_result_skips_the_cheap_tier(
    context: EvidenceContext,
) -> None:
    """Part 12 will batch triage; the entry point already accepts its answer."""
    from caudit.model.adjudication import TriageDisposition, TriageResult
    from caudit.model.finding import Impact, ImpactKind, Severity

    config = _config()
    supplied = TriageResult(
        disposition=TriageDisposition.ADJUDICATE,
        ambiguous=False,
        impact=Impact(
            kind=ImpactKind.MEMORY_CORRUPTION,
            severity=Severity.HIGH,
            description="d",
            evidence_supports="e",
        ),
        rationale="decided elsewhere",
    )
    outcome, provider, account = _adjudicate(
        context, "adjudication-confirmed", config, triage=supplied
    )
    assert [request.tier for request in provider.requests] == [Tier.ADJUDICATION]
    assert account.accounts[Tier.TRIAGE].calls == 0
    assert outcome.accepted


def test_the_escalation_prompt_is_assembled_from_the_escalation_template(
    context: EvidenceContext,
) -> None:
    config = _config(triage_enabled=False)
    _outcome, provider, _account = _adjudicate(context, "adjudication-review-required-high", config)
    escalation = provider.requests[-1].prompt
    assert escalation.tier is Tier.ESCALATION
    assert "second opinion" in escalation.text
    assert "Do not raise a claim to match the stakes" in escalation.text


def test_two_tiers_cache_separately(context: EvidenceContext, tmp_path: Path) -> None:
    """Different tier, different model id, different key. Nothing is shared."""
    config = Config.model_validate(
        {
            "llm": {
                "triage_enabled": True,
                "cache_enabled": True,
                "cache_dir": str(tmp_path / "cache"),
            }
        }
    )
    cache = response_cache(config)
    provider, _ = cassette_provider("triage-then-confirmed", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=cache,
        sleeper=no_sleep,
    )
    assert cache.writes == 2
    assert len(list((tmp_path / "cache").glob("*.json"))) == 2

    replayed = adjudicate(
        context,
        config=config,
        provider=cassette_provider("triage-then-confirmed", evidence_ids=context.evidence_ids())[0],
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=response_cache(config),
        sleeper=no_sleep,
    )
    assert replayed.from_cache
    assert [attempt.outcome for attempt in replayed.attempts] == [
        AttemptOutcome.CACHED,
        AttemptOutcome.CACHED,
    ]


def test_every_limitation_the_context_carried_reaches_the_outcome(
    context: EvidenceContext,
) -> None:
    """Part 11 needs the retrieval blind spots, not only the adjudication ones."""
    outcome, _provider, _account = _adjudicate(
        context, "adjudication-confirmed", _config(triage_enabled=False)
    )
    for limitation in context.limitations:
        assert limitation in outcome.limitations

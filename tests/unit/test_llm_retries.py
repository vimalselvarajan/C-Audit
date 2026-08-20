"""Structured output and failure handling: T-10-04, T-10-05, T-10-17..T-10-20."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.llm.service import (
    AdjudicationOutcome,
    AttemptOutcome,
    CassetteProvider,
    RunAccount,
    Tier,
    adjudicate,
)
from caudit.model.adjudication import Adjudication, Verdict
from caudit.model.finding import Confidence, ReviewReason
from caudit.retrieval.context import EvidenceContext
from tests.conftest import (
    RecordingSleeper,
    RefusingProvider,
    cassette_provider,
    granted_consent,
    llm_config,
    no_sleep,
    retrieval_context,
)


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> EvidenceContext:
    return retrieval_context(
        tmp_path_factory.mktemp("retries"), "macro_bounds", "macro_bounds.c", 27
    )


def _run(
    context: EvidenceContext,
    cassette: str,
    *,
    config: Config | None = None,
    sleeper: Callable[[float], None] = no_sleep,
) -> tuple[AdjudicationOutcome, CassetteProvider, RunAccount]:
    effective = config if config is not None else llm_config()
    provider, _ = cassette_provider(cassette, evidence_ids=context.evidence_ids())
    account = RunAccount(config=effective)
    outcome = adjudicate(
        context,
        config=effective,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=sleeper,
    )
    return outcome, provider, account


# --------------------------------------------------------------------- T-10-04


def test_two_malformed_answers_are_retried_and_the_third_is_accepted(
    context: EvidenceContext,
) -> None:
    """T-10-04: two retries, then success; the call count is exactly 3."""
    outcome, provider, _ = _run(context, "adjudication-malformed-twice")

    assert outcome.accepted
    assert provider.calls == 3
    assert [attempt.outcome for attempt in outcome.attempts] == [
        AttemptOutcome.SCHEMA_INVALID,
        AttemptOutcome.SCHEMA_INVALID,
        AttemptOutcome.ACCEPTED,
    ]


def test_the_validation_error_is_fed_back_to_the_next_attempt(
    context: EvidenceContext,
) -> None:
    """A retry that asked the same question in the same words would be a waste."""
    _outcome, provider, _ = _run(context, "adjudication-malformed-twice")

    first, second, third = provider.requests
    assert first.correction is None
    assert second.correction is not None
    assert "did not satisfy the schema" in second.correction
    assert second.correction in second.body()
    # Each retry carries the error from the answer immediately before it.
    assert third.correction != second.correction


def test_the_number_of_attempts_follows_configuration(context: EvidenceContext) -> None:
    outcome, provider, _ = _run(
        context, "adjudication-malformed-always", config=llm_config(max_attempts=2)
    )
    assert provider.calls == 2
    assert outcome.review_reason is ReviewReason.SCHEMA_INVALID_RESPONSE


# --------------------------------------------------------------------- T-10-05


def test_never_valid_becomes_review_required_with_no_partial_finding(
    context: EvidenceContext,
) -> None:
    """T-10-05."""
    outcome, provider, _ = _run(context, "adjudication-malformed-always")

    assert provider.calls == 3
    assert outcome.adjudication is None
    assert outcome.review_reason is ReviewReason.SCHEMA_INVALID_RESPONSE
    assert not outcome.accepted
    assert all(attempt.outcome is AttemptOutcome.SCHEMA_INVALID for attempt in outcome.attempts)


def test_a_blocking_reason_can_never_be_a_confident_finding() -> None:
    """The reason part 10 records is one part 08's model refuses to confirm."""
    from caudit.model.finding import BLOCKING_REVIEW_REASONS

    for reason in (
        ReviewReason.SCHEMA_INVALID_RESPONSE,
        ReviewReason.PROVIDER_UNAVAILABLE,
        ReviewReason.CITATION_UNRESOLVED,
        ReviewReason.RUN_BUDGET_EXHAUSTED,
    ):
        assert reason in BLOCKING_REVIEW_REASONS


# --------------------------------------------------------------------- T-10-17


def test_a_response_missing_unresolved_assumptions_is_not_accepted(
    context: EvidenceContext,
) -> None:
    """T-10-17: every other field is present, and that is not enough."""
    outcome, provider, _ = _run(context, "adjudication-missing-assumptions")

    assert outcome.adjudication is None
    assert outcome.review_reason is ReviewReason.SCHEMA_INVALID_RESPONSE
    assert provider.calls == 3
    assert "unresolved_assumptions" in (outcome.attempts[0].detail or "")


def test_unresolved_assumptions_is_required_by_the_response_schema() -> None:
    """T-10-17: the provider is told it is required, not only the validator."""
    from caudit.llm.service import adjudication_response_schema

    schema = adjudication_response_schema()
    assert "unresolved_assumptions" in schema["required"]
    assert "unresolved_assumptions" in schema["properties"]


# --------------------------------------------------------------------- T-10-18


def test_an_explicitly_empty_assumptions_list_is_accepted(
    context: EvidenceContext,
) -> None:
    """T-10-18: present-and-empty is a claim; absent is a silence."""
    outcome, provider, _ = _run(context, "adjudication-empty-assumptions")

    assert outcome.accepted
    assert provider.calls == 1
    assert outcome.adjudication is not None
    assert outcome.adjudication.unresolved_assumptions == []


def test_the_prompt_asks_for_the_field_even_when_there_is_nothing_to_say(
    context: EvidenceContext,
) -> None:
    """The distinction only holds if the instructions state it."""
    _outcome, provider, _ = _run(context, "adjudication-empty-assumptions")
    body = provider.requests[0].prompt.text
    assert "`unresolved_assumptions` is never omitted" in body
    assert "empty array" in body


# --------------------------------------------------------------------- T-10-19


def test_a_rate_limit_is_retried_with_backoff_and_recorded(
    context: EvidenceContext,
) -> None:
    """T-10-19: the 429 is survived, the wait happened, and both show in the trace."""
    sleeper = RecordingSleeper()
    outcome, provider, _ = _run(context, "provider-rate-limited-then-ok", sleeper=sleeper)

    assert outcome.accepted
    assert provider.calls == 2
    assert [attempt.outcome for attempt in outcome.attempts] == [
        AttemptOutcome.TRANSPORT_ERROR,
        AttemptOutcome.ACCEPTED,
    ]
    assert sleeper.delays == [pytest.approx(1.0)]
    assert "429" in outcome.attempts[0].detail


def test_backoff_grows_by_the_configured_multiplier(context: EvidenceContext) -> None:
    sleeper = RecordingSleeper()
    _outcome, _provider, _account = _run(
        context,
        "provider-timeout",
        config=llm_config(backoff_seconds=0.5, backoff_multiplier=3.0),
        sleeper=sleeper,
    )
    # Three transport attempts means two waits: none before the first.
    assert sleeper.delays == [pytest.approx(0.5), pytest.approx(1.5)]


# --------------------------------------------------------------------- T-10-20


def test_repeated_timeouts_end_as_provider_unavailable_and_the_run_completes(
    context: EvidenceContext,
) -> None:
    """T-10-20."""
    outcome, provider, _ = _run(context, "provider-timeout")

    assert provider.calls == 3
    assert outcome.adjudication is None
    assert outcome.review_reason is ReviewReason.PROVIDER_UNAVAILABLE
    assert all(attempt.outcome is AttemptOutcome.TRANSPORT_ERROR for attempt in outcome.attempts)


def test_a_refusal_is_not_retried(context: EvidenceContext) -> None:
    """A bad key or a bad model id fails the same way every time."""
    outcome, provider, _ = _run(context, "provider-refused")

    assert provider.calls == 1
    assert outcome.review_reason is ReviewReason.PROVIDER_UNAVAILABLE
    assert outcome.attempts[-1].outcome is AttemptOutcome.REFUSED


def test_the_transport_failure_never_produces_a_partial_proposal(
    context: EvidenceContext,
) -> None:
    outcome, _provider, _ = _run(context, "provider-timeout")
    assert outcome.adjudication is None
    assert outcome.usage.input_tokens == 0
    assert outcome.usage.output_tokens == 0


# ----------------------------------------------------------- model invariants


def test_a_confirmation_citing_nothing_is_not_representable() -> None:
    """A confirmed verdict with no citation is an assertion, not an argument."""
    payload = {
        "verdict": "confirmed",
        "cited_evidence_ids": [],
        "cwe": "CWE-787",
        "cwe_rationale": "because",
        "trigger_conditions": [],
        "impact": {
            "kind": "memory_corruption",
            "severity": "high",
            "description": "d",
            "evidence_supports": "e",
        },
        "reachability": "argued",
        "exploitability": "unknown",
        "remediation": {"strategy": "s", "rationale": "r"},
        "maintainability_impact": {
            "ownership": "o",
            "complexity": "c",
            "coupling": "k",
            "regression_risk": "g",
        },
        "unresolved_assumptions": [],
        "confidence_self_report": "high",
    }
    with pytest.raises(ValueError, match="assertion, not an"):
        Adjudication.model_validate(payload)

    with pytest.raises(ValueError, match="which weakness"):
        Adjudication.model_validate(payload | {"cited_evidence_ids": ["ev-1"], "cwe": None})

    with pytest.raises(ValueError, match="contradicts"):
        Adjudication.model_validate(
            payload
            | {
                "cited_evidence_ids": ["ev-1"],
                "confidence_self_report": Confidence.REVIEW_REQUIRED,
            }
        )


def test_a_rejection_may_cite_nothing_and_name_no_weakness(
    context: EvidenceContext,
) -> None:
    """The analyzer being wrong is an answer, and it needs no CWE."""
    outcome, _provider, _ = _run(context, "adjudication-rejected")
    assert outcome.accepted
    assert outcome.adjudication is not None
    assert outcome.adjudication.verdict is Verdict.REJECTED
    assert outcome.adjudication.cwe is None


def test_an_outcome_is_a_proposal_or_a_reason_and_never_both() -> None:
    from caudit.llm.service import AdjudicationOutcome

    with pytest.raises(ValueError, match="never be both or neither"):
        AdjudicationOutcome(candidate_id="c", tier=Tier.ADJUDICATION, model_id="m")


def test_the_cassette_refuses_a_prompt_version_it_was_not_recorded_against(
    context: EvidenceContext,
) -> None:
    """A prompt bump without a re-record must fail loudly, not replay quietly."""
    from caudit.config.loader import Config
    from caudit.llm.cassette import CassetteError

    config = Config.model_validate(
        {"llm": {"triage_enabled": False, "cache_enabled": False}, "policy_versions": {}}
    )
    provider, cassette = cassette_provider(
        "adjudication-confirmed-v1", evidence_ids=context.evidence_ids()
    )
    assert cassette.prompt_version != config.policy_versions.prompt
    with pytest.raises(CassetteError, match="re-record"):
        adjudicate(
            context,
            config=config,
            provider=provider,
            consent=granted_consent(),
            account=RunAccount(config=config),
            sleeper=no_sleep,
        )


def test_a_cassette_asked_more_often_than_it_was_recorded_refuses(
    context: EvidenceContext,
) -> None:
    from caudit.llm.cassette import CassetteError

    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    config = llm_config()
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )
    with pytest.raises(CassetteError, match="was asked 2 time"):
        adjudicate(
            context,
            config=config,
            provider=provider,
            consent=granted_consent(),
            account=RunAccount(config=config),
            sleeper=no_sleep,
        )


def test_a_context_that_did_not_fit_is_never_sent(tmp_path: Path) -> None:
    """Part 09's refusal is respected rather than re-litigated here."""
    from caudit.config.loader import Config

    config = Config.model_validate(
        {"token_budget": {"per_candidate": 40}, "llm": {"cache_enabled": False}}
    )
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    assert context.review_reason is ReviewReason.CONTEXT_BUDGET_EXCEEDED

    provider = RefusingProvider()
    outcome = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )
    assert provider.calls == 0
    assert outcome.review_reason is ReviewReason.CONTEXT_BUDGET_EXCEEDED


def test_a_prompt_larger_than_the_per_candidate_budget_is_refused_whole(
    tmp_path: Path,
) -> None:
    """The scaffolding is charged to the same budget, and nothing is trimmed."""
    from caudit.config.loader import Config

    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27)
    assert context.is_adjudicable
    # Big enough for part 09's units, too small once the instructions and the
    # response schema are counted.
    config = Config.model_validate(
        {
            "token_budget": {"per_candidate": context.total_tokens + 10},
            "llm": {"cache_enabled": False},
        }
    )
    provider = RefusingProvider()
    outcome = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )
    assert provider.calls == 0
    assert outcome.review_reason is ReviewReason.CONTEXT_BUDGET_EXCEEDED
    assert any("never done" in item.detail for item in outcome.limitations)

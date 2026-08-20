"""Response caching and cost control: T-10-13, T-10-14, T-10-15, T-10-16."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.llm.service import (
    AttemptOutcome,
    ResponseCache,
    RunAccount,
    Tier,
    adjudicate,
    cache_key,
    response_cache,
)
from caudit.model.finding import ReviewReason
from caudit.retrieval.context import EvidenceContext
from tests.conftest import (
    RefusingProvider,
    cassette_provider,
    granted_consent,
    llm_config,
    no_sleep,
    retrieval_context,
)


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> EvidenceContext:
    return retrieval_context(tmp_path_factory.mktemp("cache"), "macro_bounds", "macro_bounds.c", 27)


def _cached_config(tmp_path: Path, **overrides: object) -> Config:
    settings: dict[str, object] = {
        "triage_enabled": False,
        "cache_enabled": True,
        "cache_dir": str(tmp_path / "llm-cache"),
    }
    settings.update(overrides)
    return Config.model_validate({"llm": settings})


# --------------------------------------------------------------------- T-10-13


def test_the_second_adjudication_of_one_candidate_is_a_cache_hit(
    context: EvidenceContext, tmp_path: Path
) -> None:
    """T-10-13: one call, two identical results."""
    config = _cached_config(tmp_path)
    cache = response_cache(config)
    account = RunAccount(config=config)

    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    first = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        cache=cache,
        sleeper=no_sleep,
    )
    assert first.accepted
    assert provider.calls == 1

    # The second run gets a provider that fails if it is asked anything at all.
    second = adjudicate(
        context,
        config=config,
        provider=RefusingProvider(),
        consent=granted_consent(),
        account=account,
        cache=cache,
        sleeper=no_sleep,
    )
    assert second.accepted
    assert second.from_cache
    assert second.adjudication == first.adjudication
    assert [attempt.outcome for attempt in second.attempts] == [AttemptOutcome.CACHED]
    assert cache.hits == 1


def test_a_cache_hit_is_not_counted_as_a_call(context: EvidenceContext, tmp_path: Path) -> None:
    """It cost nothing and reached no network; the manifest must not imply it did."""
    config = _cached_config(tmp_path)
    cache = response_cache(config)
    account = RunAccount(config=config)
    provider, _ = cassette_provider("adjudication-usage", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        cache=cache,
        sleeper=no_sleep,
    )
    before = account.total_tokens
    adjudicate(
        context,
        config=config,
        provider=RefusingProvider(),
        consent=granted_consent(),
        account=account,
        cache=cache,
        sleeper=no_sleep,
    )
    assert account.calls == 1
    assert account.total_tokens == before
    assert account.accounts[Tier.ADJUDICATION].cached_calls == 1


def test_a_cache_entry_holds_no_source_by_default(context: EvidenceContext, tmp_path: Path) -> None:
    """The prompt is reduced to a fingerprint; the raw exchange is dropped."""
    config = _cached_config(tmp_path)
    cache = response_cache(config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=cache,
        sleeper=no_sleep,
    )
    files = list((tmp_path / "llm-cache").glob("*.json"))
    assert len(files) == 1
    entry = json.loads(files[0].read_text(encoding="utf-8"))
    assert entry["prompt"] is None
    assert entry["response_text"] is None
    assert len(entry["prompt_fingerprint"]) == 64
    # A distinctive line of the fixture's source must not be in the file.
    assert "CHECK_LEN" not in files[0].read_text(encoding="utf-8")


def test_retaining_the_raw_exchange_is_explicit(context: EvidenceContext, tmp_path: Path) -> None:
    config = _cached_config(tmp_path, retain_raw=True)
    cache = response_cache(config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=cache,
        sleeper=no_sleep,
    )
    entry = json.loads(next((tmp_path / "llm-cache").glob("*.json")).read_text("utf-8"))
    assert entry["prompt"] is not None
    assert entry["response_text"] is not None
    # And the setting is part of the configuration snapshot the manifest carries.
    assert config.model_dump(mode="json")["llm"]["retain_raw"] is True


def test_a_corrupt_cache_entry_costs_a_call_and_not_the_run(
    context: EvidenceContext, tmp_path: Path
) -> None:
    config = _cached_config(tmp_path)
    cache = response_cache(config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=cache,
        sleeper=no_sleep,
    )
    entry = next((tmp_path / "llm-cache").glob("*.json"))
    entry.write_text("{ this is not json", encoding="utf-8")

    provider2, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    outcome = adjudicate(
        context,
        config=config,
        provider=provider2,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=response_cache(config),
        sleeper=no_sleep,
    )
    assert outcome.accepted
    assert provider2.calls == 1


# --------------------------------------------------------------------- T-10-14

_BASE = {
    "prompt": "the assembled request body",
    "model_id": "model-a",
    "prompt_version": "1",
    "schema_version": "1.5.0",
}


@pytest.mark.parametrize("component", sorted(_BASE))
def test_changing_any_key_component_misses_the_cache(component: str) -> None:
    """T-10-14: one component at a time, each on its own."""
    baseline = cache_key(**_BASE)
    changed = dict(_BASE)
    changed[component] = _BASE[component] + "-changed"
    assert cache_key(**changed) != baseline


def test_an_unchanged_request_produces_the_same_key() -> None:
    assert cache_key(**_BASE) == cache_key(**_BASE)


def test_a_prompt_version_bump_alone_misses_the_cache(
    context: EvidenceContext, tmp_path: Path
) -> None:
    """T-10-14: the risk this closes is a cassette silently outliving its prompt."""
    config = _cached_config(tmp_path)
    cache = response_cache(config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=cache,
        sleeper=no_sleep,
    )
    stored = json.loads(next((tmp_path / "llm-cache").glob("*.json")).read_text("utf-8"))
    assert stored["prompt_version"] == config.policy_versions.prompt

    bumped = cache_key(
        prompt="the assembled request body",
        model_id=stored["model_id"],
        prompt_version="2",
        schema_version=stored["schema_version"],
    )
    assert bumped != stored["key"]


def test_a_disabled_cache_stores_nothing_and_answers_nothing(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path / "unused", enabled=False)
    assert cache.get("any-key") is None
    assert (
        cache.put(
            key="any-key",
            tier=Tier.ADJUDICATION,
            model_id="m",
            prompt_version="1",
            schema_version="1",
            prompt="p",
            payload={},
            usage=__import__("caudit.model.adjudication", fromlist=["Usage"]).Usage(),
            finish_reason="STOP",
            response_text="r",
        )
        is None
    )
    assert not (tmp_path / "unused").exists()


# --------------------------------------------------------------------- T-10-16


def test_accounting_matches_the_cassettes_reported_usage(
    context: EvidenceContext,
) -> None:
    """T-10-16: exactly, and from the response rather than an estimate."""
    config = llm_config()
    account = RunAccount(config=config)
    provider, cassette = cassette_provider(
        "adjudication-usage", evidence_ids=context.evidence_ids()
    )
    outcome = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    recorded = cassette.turns[0].usage
    assert (recorded.input_tokens, recorded.output_tokens) == (12345, 678)
    assert outcome.usage == recorded
    assert account.total_tokens == 12345 + 678

    adjudication_record = next(r for r in account.records() if r.tier == "adjudication")
    assert adjudication_record.input_tokens == 12345
    assert adjudication_record.output_tokens == 678
    assert adjudication_record.calls == 1


def test_usage_from_every_attempt_is_counted_including_rejected_ones(
    context: EvidenceContext,
) -> None:
    """A malformed answer was still generated, and still billed."""
    config = llm_config()
    account = RunAccount(config=config)
    provider, cassette = cassette_provider(
        "adjudication-malformed-twice", evidence_ids=context.evidence_ids()
    )
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    expected = sum(turn.usage.input_tokens + turn.usage.output_tokens for turn in cassette.turns)
    assert account.total_tokens == expected


def test_cost_is_computed_from_reported_usage_and_the_configured_price(
    context: EvidenceContext,
) -> None:
    """T-10-16: prices are configuration; usage is the provider's own number."""
    config = Config.model_validate(
        {
            "llm": {
                "triage_enabled": False,
                "cache_enabled": False,
                "pricing": {
                    "adjudication": {
                        "input_per_million_usd": 100.0,
                        "output_per_million_usd": 400.0,
                    }
                },
            }
        }
    )
    account = RunAccount(config=config)
    provider, _ = cassette_provider("adjudication-usage", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    expected = (12345 * 100.0 + 678 * 400.0) / 1_000_000
    assert account.cost_usd() == pytest.approx(expected)


# --------------------------------------------------------------------- T-10-15


def _priced_config(ceiling: float) -> Config:
    return Config.model_validate(
        {
            "llm": {
                "triage_enabled": False,
                "cache_enabled": False,
                "max_run_cost_usd": ceiling,
                "pricing": {
                    "adjudication": {
                        "input_per_million_usd": 100.0,
                        "output_per_million_usd": 400.0,
                    }
                },
            }
        }
    )


def test_the_cost_ceiling_stops_further_calls_and_records_a_limitation(
    context: EvidenceContext,
) -> None:
    """T-10-15: calls stop at the ceiling, and no context is trimmed to continue."""
    config = _priced_config(0.5)
    account = RunAccount(config=config)

    provider, _ = cassette_provider("adjudication-usage", evidence_ids=context.evidence_ids())
    first = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    assert first.accepted
    assert account.cost_usd() >= 0.5
    assert account.exhausted

    refusing = RefusingProvider()
    second = adjudicate(
        context,
        config=config,
        provider=refusing,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    assert refusing.calls == 0
    assert second.review_reason is ReviewReason.RUN_BUDGET_EXHAUSTED
    assert account.refused == [context.candidate.candidate_id]

    detail = " ".join(item.detail for item in account.limitations())
    assert "cost ceiling" in detail
    assert "$0.5000" in detail


def test_a_run_below_the_ceiling_keeps_going(context: EvidenceContext) -> None:
    config = _priced_config(100.0)
    account = RunAccount(config=config)
    provider, _ = cassette_provider("adjudication-usage", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    assert not account.exhausted
    assert account.limitations() == []


def test_a_ceiling_with_no_prices_says_it_cannot_bind() -> None:
    """A cost ceiling against a zero price table is a setting that does nothing."""
    config = Config.model_validate({"llm": {"max_run_cost_usd": 5.0, "cache_enabled": False}})
    account = RunAccount(config=config)
    assert not account.priced
    detail = " ".join(item.detail for item in account.limitations())
    assert "cannot bind" in detail
    assert "llm.pricing" in detail


def test_the_token_ceiling_binds_when_no_cost_ceiling_is_configured(
    context: EvidenceContext,
) -> None:
    config = Config.model_validate(
        {
            "token_budget": {"per_run": 1000},
            "llm": {"triage_enabled": False, "cache_enabled": False},
        }
    )
    account = RunAccount(config=config)
    provider, _ = cassette_provider("adjudication-usage", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    reason = account.stop_reason()
    assert reason is not None
    assert reason.kind == "token_ceiling"

    refusing = RefusingProvider()
    outcome = adjudicate(
        context,
        config=config,
        provider=refusing,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    assert refusing.calls == 0
    assert outcome.review_reason is ReviewReason.RUN_BUDGET_EXHAUSTED

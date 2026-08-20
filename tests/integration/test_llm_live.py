"""The one test that talks to a real model: T-10-21.

Deselected by default and marked ``needs_network``. Everything else in part 10
runs from cassettes, which is what makes the default suite offline,
deterministic, and runnable with no key — but a suite built entirely from
recordings can drift from the API it claims to describe, so exactly one test
holds the recordings to the real thing.

It asserts what a live call can honestly be asked to prove: that the request
this package assembles is accepted, and that what comes back validates against
the committed response schema. It does *not* assert a verdict. Whether a model
confirms a defect is a property of the model, not of this code, and a test that
pinned it would fail on every model release for no reason a reader could act
on.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.llm.attempts import request_adjudication
from caudit.llm.gemini import API_KEY_ENV, GeminiProvider
from caudit.llm.prompts import assemble
from caudit.llm.provider import ProviderRequest
from caudit.llm.service import (
    ConsentDecision,
    ConsentSource,
    RunAccount,
    Tier,
    adjudicate,
    adjudication_response_schema,
)
from tests.conftest import retrieval_context

pytestmark = pytest.mark.needs_network


@pytest.fixture
def live_provider() -> GeminiProvider:
    if not any(os.environ.get(name, "").strip() for name in API_KEY_ENV):
        pytest.skip(f"set one of {', '.join(API_KEY_ENV)} to run the live test")
    return GeminiProvider(
        consent=ConsentDecision(
            granted=True,
            source=ConsentSource.CONFIG,
            detail="--consent-cloud, supplied by the test runner",
        )
    )


def test_a_real_response_validates_against_the_committed_schema(
    tmp_path: Path, live_provider: GeminiProvider
) -> None:
    """T-10-21."""
    config = Config.model_validate(
        {"cloud_consent": True, "llm": {"triage_enabled": False, "cache_enabled": False}}
    )
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    account = RunAccount(config=config)

    outcome = adjudicate(
        context,
        config=config,
        provider=live_provider,
        consent=ConsentDecision(granted=True, source=ConsentSource.CONFIG, detail="test runner"),
        account=account,
    )

    assert outcome.review_reason is None, outcome.attempts
    proposal = outcome.adjudication
    assert proposal is not None
    # Every field of the contract came back, whatever the verdict is.
    assert proposal.unresolved_assumptions is not None
    assert set(proposal.cited_evidence_ids) <= set(context.evidence_ids())
    # Usage is the provider's own number, not an estimate.
    assert account.total_tokens > 0
    assert outcome.usage.input_tokens > 0


def test_the_provider_accepts_the_flattened_response_schema(
    tmp_path: Path, live_provider: GeminiProvider
) -> None:
    """The mapping is only correct if the API agrees it is."""
    config = Config.model_validate({"cloud_consent": True})
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    schema = adjudication_response_schema()
    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version=config.policy_versions.prompt,
        exclude_globs=config.exclude_globs,
        response_fields=schema["required"],
    )
    response = live_provider.adjudicate(
        ProviderRequest(
            tier=Tier.ADJUDICATION,
            model_id=config.models.adjudication,
            prompt=prompt,
            response_schema=schema,
        )
    )
    assert response.text.strip().startswith("{")
    assert response.usage.input_tokens > 0


def test_the_retry_loop_survives_a_real_exchange(
    tmp_path: Path, live_provider: GeminiProvider
) -> None:
    """The same loop the cassettes drive, against the real thing."""
    config = Config.model_validate({"cloud_consent": True})
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    schema = adjudication_response_schema()
    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version=config.policy_versions.prompt,
        exclude_globs=config.exclude_globs,
        response_fields=schema["required"],
    )
    account = RunAccount(config=config)
    outcome = request_adjudication(
        live_provider,
        prompt,
        tier=Tier.ADJUDICATION,
        config=config.llm,
        account=account,
        response_schema=schema,
        schema_version="live",
    )
    assert outcome.adjudication is not None, [a.detail for a in outcome.attempts]
    assert outcome.calls >= 1

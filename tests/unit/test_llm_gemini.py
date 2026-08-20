"""The Gemini backend, exercised without a socket.

A fake client stands in for ``google.genai``. That is enough to test everything
this module actually decides — how a failure is classified, what is extracted
from a response, which model id the request carries, where the key comes from —
because the one thing it does *not* decide is what the model says. T-10-21 is
the test that talks to the real API, and it is deselected by default.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from caudit.config.loader import Config
from caudit.llm.consent import ConsentError, consent_state
from caudit.llm.gemini import API_KEY_ENV, GeminiProvider
from caudit.llm.prompts import AssembledPrompt
from caudit.llm.provider import ProviderRefusedError, ProviderUnavailableError
from caudit.llm.schema import adjudication_response_schema
from caudit.llm.service import ProviderRequest, Tier
from caudit.model.adjudication import Usage
from tests.conftest import granted_consent


class _FakeUsage:
    def __init__(self, prompt: int, candidates: int) -> None:
        self.prompt_token_count = prompt
        self.candidates_token_count = candidates


class _FakeCandidate:
    def __init__(self, finish_reason: str) -> None:
        self.finish_reason = finish_reason


class _FakeResponse:
    def __init__(
        self,
        text: str = "{}",
        usage: _FakeUsage | None = None,
        finish_reason: str = "STOP",
    ) -> None:
        self.text = text
        self.usage_metadata = usage
        self.candidates = [_FakeCandidate(finish_reason)]


class _FakeModels:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class _FakeClient:
    def __init__(self, outcome: Any) -> None:
        self.models = _FakeModels(outcome)


class _StatusError(Exception):
    """An exception carrying an HTTP code, the way the SDK's errors do."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _request(**overrides: Any) -> ProviderRequest:
    prompt = AssembledPrompt(
        tier=Tier.ADJUDICATION,
        prompt_version="1",
        candidate_id="cand-1",
        text="the assembled body",
    )
    fields: dict[str, Any] = {
        "tier": Tier.ADJUDICATION,
        "model_id": Config().models.adjudication,
        "prompt": prompt,
        "response_schema": adjudication_response_schema(),
    }
    fields.update(overrides)
    return ProviderRequest(**fields)


def _provider(outcome: Any, **kwargs: Any) -> GeminiProvider:
    return GeminiProvider(consent=granted_consent(), client=_FakeClient(outcome), **kwargs)


# ------------------------------------------------------------------- consent


def test_the_backend_refuses_to_exist_without_consent() -> None:
    with pytest.raises(ConsentError):
        GeminiProvider(consent=consent_state(Config()), client=_FakeClient(_FakeResponse()))


def test_a_granted_decision_is_kept_so_a_run_can_say_why_it_sent() -> None:
    provider = _provider(_FakeResponse())
    assert provider.consent.granted


# ----------------------------------------------------------------- the call


def test_the_request_carries_the_configured_model_id_and_the_schema() -> None:
    provider = _provider(_FakeResponse(text='{"ok": true}'))
    request = _request(model_id="configured-model-1")
    provider.adjudicate(request)

    call = provider._connect().models.calls[0]
    assert call["model"] == "configured-model-1"
    assert call["contents"] == request.body()
    assert call["config"].response_json_schema == request.response_schema
    assert call["config"].response_mime_type == "application/json"
    # Determinism: a cache and a reproducible run both depend on it.
    assert call["config"].temperature == 0.0


def test_a_correction_is_appended_to_the_body_verbatim() -> None:
    provider = _provider(_FakeResponse())
    request = _request(correction="field 'cwe': missing")
    provider.adjudicate(request)

    sent = provider._connect().models.calls[0]["contents"]
    assert "the assembled body" in sent
    assert "field 'cwe': missing" in sent
    assert "previous answer was rejected" in sent


def test_usage_and_finish_reason_come_from_the_response() -> None:
    provider = _provider(
        _FakeResponse(text='{"a": 1}', usage=_FakeUsage(1200, 340), finish_reason="STOP")
    )
    response = provider.adjudicate(_request())

    assert response.text == '{"a": 1}'
    assert response.usage == Usage(input_tokens=1200, output_tokens=340)
    assert response.finish_reason == "STOP"
    assert response.from_cache is False


def test_a_response_with_no_usage_metadata_reports_zero_rather_than_guessing() -> None:
    response = _provider(_FakeResponse(usage=None)).adjudicate(_request())
    assert response.usage == Usage()


def test_a_response_with_no_text_is_an_empty_answer_not_a_salvage() -> None:
    """The schema check that follows says so; nothing is inferred here."""

    class _NoText:
        text = None
        usage_metadata = None
        candidates: ClassVar[list[object]] = []

    response = _provider(_NoText()).adjudicate(_request())
    assert response.text == ""
    assert response.finish_reason == "unknown"


# ------------------------------------------------------------ classification


@pytest.mark.parametrize("code", [408, 425, 429, 500, 502, 503, 504])
def test_a_retryable_status_becomes_a_transport_failure(code: int) -> None:
    provider = _provider(_StatusError(code, "try again later"))
    with pytest.raises(ProviderUnavailableError, match=str(code)):
        provider.adjudicate(_request())


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
def test_a_client_error_is_a_refusal_that_a_retry_cannot_fix(code: int) -> None:
    provider = _provider(_StatusError(code, "bad request"))
    with pytest.raises(ProviderRefusedError, match="rejected the request"):
        provider.adjudicate(_request())


def test_a_failure_with_no_status_is_treated_as_transport() -> None:
    """A dropped socket or a DNS failure is retryable by nature."""
    provider = _provider(OSError("connection reset by peer"))
    with pytest.raises(ProviderUnavailableError, match="connection reset"):
        provider.adjudicate(_request())


def test_a_nameless_exception_still_produces_a_message() -> None:
    provider = _provider(RuntimeError(""))
    with pytest.raises(ProviderUnavailableError, match="RuntimeError"):
        provider.adjudicate(_request())


# ----------------------------------------------------------------- the key


def test_the_key_is_read_from_the_environment_at_call_time() -> None:
    """Read now, never memoized: rotating the variable rotates the key.

    The provider holds a reference to the environment, not a copy of the
    value, which is what "at call time" has to mean for it to be true.
    """
    env = {"GEMINI_API_KEY": "AIzaSyTESTKEY000000000000000000000000000"}
    provider = GeminiProvider(consent=granted_consent(), env=env)
    assert provider._api_key() == env["GEMINI_API_KEY"]

    env["GEMINI_API_KEY"] = "AIzaSyROTATED0000000000000000000000000"
    assert provider._api_key() == env["GEMINI_API_KEY"]
    assert not any(
        isinstance(value, str) and value.startswith("AIza") for value in provider.__dict__.values()
    )


def test_the_first_variable_that_is_set_wins() -> None:
    provider = GeminiProvider(
        consent=granted_consent(),
        env={"GEMINI_API_KEY": "AIzaSyFIRST00000000000000000000000000", "GOOGLE_API_KEY": "second"},
    )
    assert provider._api_key().endswith("0")
    assert API_KEY_ENV[0] == "GEMINI_API_KEY"


def test_reading_the_key_registers_it_as_a_secret() -> None:
    from caudit.logging import registered_secrets

    key = "AIzaSyREGISTERME00000000000000000000000"
    GeminiProvider(consent=granted_consent(), env={"GOOGLE_API_KEY": key})._api_key()
    assert key in registered_secrets()


def test_a_missing_key_is_a_refusal_naming_the_variables() -> None:
    provider = GeminiProvider(consent=granted_consent(), env={})
    with pytest.raises(ProviderRefusedError) as raised:
        provider._api_key()
    for name in API_KEY_ENV:
        assert name in raised.value.message
    assert raised.value.hint is not None
    assert "never read from a config file" in raised.value.hint


def test_a_blank_key_is_the_same_as_no_key() -> None:
    provider = GeminiProvider(consent=granted_consent(), env={"GEMINI_API_KEY": "   "})
    with pytest.raises(ProviderRefusedError):
        provider._api_key()


# ------------------------------------------------------------- token counting


def test_token_count_is_local_and_never_a_round_trip() -> None:
    """A network call inside the affordability check would spend to ask."""
    provider = _provider(_FakeResponse())
    counted = provider.token_count("int main(void) { return 0; }")
    assert counted > 0
    # Nothing reached the client.
    assert provider._connect().models.calls == []


def test_the_provider_satisfies_part_09s_tokenizer_protocol() -> None:
    from caudit.llm.service import ProviderTokenizer
    from caudit.retrieval.budget import Tokenizer

    tokenizer: Tokenizer = ProviderTokenizer(_provider(_FakeResponse()))
    assert tokenizer.count("some text") > 0

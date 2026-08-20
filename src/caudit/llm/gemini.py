"""The Gemini backend.

The only implementation of :class:`~caudit.llm.provider.LLMProvider` the MVP
ships, and the only code in this package that can open a socket. Four
properties are load-bearing:

* **Consent is a constructor argument.** There is no way to build this object
  without a granted :class:`~caudit.llm.consent.ConsentDecision`, so "was
  consent checked?" is answered by the type rather than by an audit of call
  sites.
* **The key is read at call time, from the environment, and never stored.**
  It is not a field of :class:`~caudit.config.loader.Config`, so it cannot be
  dumped by ``--print-config`` or written into a manifest, and it is
  registered with :mod:`caudit.logging` so it cannot reach a log record.
* **No model id is written here.** Every request carries the id the
  configuration named, which the manifest records.
* **Failures are classified before they are raised.** A rate limit and a bad
  API key both end a request, but only one of them is worth retrying, and a
  retry loop that cannot tell them apart burns the run's budget on a request
  that will never succeed.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Final

from caudit.llm.consent import ConsentDecision, require_consent
from caudit.llm.provider import ProviderRefusedError, ProviderRequest, ProviderUnavailableError
from caudit.logging import get_logger, register_secret
from caudit.model.adjudication import ProviderResponse, Usage
from caudit.retrieval.budget import DEFAULT_TOKENIZER, Tokenizer

__all__ = ["API_KEY_ENV", "GeminiProvider"]

log = get_logger(__name__)

#: Where the key comes from. Checked in order; the first one set wins.
API_KEY_ENV: Final[tuple[str, ...]] = ("GEMINI_API_KEY", "GOOGLE_API_KEY")

#: HTTP statuses worth trying again. Everything else is a refusal: the request
#: is wrong, and sending it a second time is a second wrong request.
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({408, 425, 429, 500, 502, 503, 504})


class GeminiProvider:
    """Structured-output calls to the Gemini API."""

    def __init__(
        self,
        *,
        consent: ConsentDecision,
        env: Mapping[str, str] | None = None,
        client: Any | None = None,
        tokenizer: Tokenizer = DEFAULT_TOKENIZER,
    ) -> None:
        require_consent(consent)
        self.consent = consent
        self._env = os.environ if env is None else env
        self._client = client
        self._tokenizer = tokenizer

    # ------------------------------------------------------------------ key

    def _api_key(self) -> str:
        """The key, read now. Never cached on the instance, never logged."""
        for name in API_KEY_ENV:
            value = self._env.get(name, "").strip()
            if value:
                # Registering it here means every logger in the process
                # redacts it from this point on, including ones installed by
                # libraries underneath us.
                register_secret(value)
                return value
        raise ProviderRefusedError(
            f"no API key in the environment ({' or '.join(API_KEY_ENV)})",
            hint="export GEMINI_API_KEY='...' — it is never read from a config file.",
        )

    def _connect(self) -> Any:
        if self._client is not None:
            return self._client
        from google import genai

        self._client = genai.Client(api_key=self._api_key())
        return self._client

    # -------------------------------------------------------------- protocol

    def adjudicate(self, request: ProviderRequest) -> ProviderResponse:
        """One structured-output call."""
        from google.genai import types

        client = self._connect()
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            response_json_schema=request.response_schema,
            # The same context must produce the same answer for a cache to be
            # meaningful and for two runs of one revision to be comparable.
            temperature=0.0,
            http_options=types.HttpOptions(timeout=int(request.timeout_seconds * 1000)),
        )
        try:
            response = client.models.generate_content(
                model=request.model_id,
                contents=request.body(),
                config=config,
            )
        except Exception as exc:
            raise _classify(exc) from exc
        return _to_response(request, response)

    def token_count(self, text: str) -> int:
        """A local estimate, deliberately.

        The API can count tokens exactly, but that is a round trip — and this
        number is used to decide whether a request may be *made*. Putting a
        network call inside that decision would spend a call to find out
        whether a call is affordable. The local estimate over-counts by
        construction (see
        :class:`~caudit.retrieval.budget.HeuristicTokenizer`), which is the
        safe direction for a ceiling, and the ceiling that actually binds is
        enforced on the usage the provider reports.
        """
        return self._tokenizer.count(text)


def _classify(exc: Exception) -> ProviderUnavailableError | ProviderRefusedError:
    """Turn a backend exception into one this package's retry loop understands."""
    status = getattr(exc, "code", None)
    if not isinstance(status, int):
        status = getattr(exc, "status_code", None)
    message = str(exc).strip() or type(exc).__name__

    if isinstance(status, int):
        if status in _RETRYABLE_STATUS:
            return ProviderUnavailableError(f"provider returned {status}: {message}")
        return ProviderRefusedError(f"provider rejected the request ({status}): {message}")

    # No status at all: a socket error, a DNS failure, a timeout raised by the
    # transport. Those are the retryable kind by nature.
    return ProviderUnavailableError(f"provider call failed: {message}")


def _to_response(request: ProviderRequest, response: Any) -> ProviderResponse:
    """Extract text, usage, and finish reason without trusting any to be present."""
    usage = getattr(response, "usage_metadata", None)
    text = getattr(response, "text", None)
    if not isinstance(text, str):
        # An answer with no text is not prose to be salvaged; it is an empty
        # answer, and the schema check that follows will say so.
        text = ""
    return ProviderResponse(
        tier=request.tier,
        model_id=request.model_id,
        text=text,
        usage=Usage(
            input_tokens=_count(usage, "prompt_token_count"),
            output_tokens=_count(usage, "candidates_token_count"),
        ),
        finish_reason=_finish_reason(response),
    )


def _count(usage: Any, field: str) -> int:
    value = getattr(usage, field, None) if usage is not None else None
    return value if isinstance(value, int) and value >= 0 else 0


def _finish_reason(response: Any) -> str:
    candidates = getattr(response, "candidates", None) or []
    for candidate in candidates:
        reason = getattr(candidate, "finish_reason", None)
        if reason is not None:
            return str(reason)
    return "unknown"

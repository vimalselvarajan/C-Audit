"""Framework-neutral contracts for LLM backends.

Providers receive fully assembled prompts and can only return structured
responses. Routing, retry/validation, and caching are separate responsibilities
so each can be characterized independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from caudit.errors import CauditError
from caudit.llm.prompts import AssembledPrompt
from caudit.llm.routing import route
from caudit.model.adjudication import ProviderResponse, Tier
from caudit.status import ExitCode

__all__ = [
    "LLMProvider",
    "ProviderError",
    "ProviderRefusedError",
    "ProviderRequest",
    "ProviderTokenizer",
    "ProviderUnavailableError",
    "route",
]


class ProviderError(CauditError):
    """A backend could not answer."""

    exit_code = ExitCode.ENVIRONMENT


class ProviderUnavailableError(ProviderError):
    """Transport failure: a timeout, a rate limit, a connection that dropped.

    Retryable by construction — it says nothing about the request, only about
    whether it arrived.
    """


class ProviderRefusedError(ProviderError):
    """The provider rejected the request itself: bad key, bad model id, bad schema.

    Not retryable. Sending the same request again produces the same refusal
    and costs another round trip.
    """


class ProviderRequest(BaseModel):
    """Everything a backend needs, and nothing it could use to skip a check.

    The prompt arrives **already assembled** — exclusion enforced, secrets
    scrubbed, budget counted. A backend that took an
    :class:`~caudit.retrieval.context.EvidenceContext` instead would have to
    perform those steps itself, and a second backend could forget to.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: Tier
    model_id: str = Field(min_length=1)
    prompt: AssembledPrompt
    #: The flattened response schema for this tier, from :mod:`caudit.llm.schema`.
    response_schema: dict[str, Any]
    structured_output: bool = True
    thinking_level: str = "low"
    max_output_tokens: int = Field(default=4_096, gt=0)
    thinking_token_reserve: int = Field(default=0, ge=0)
    timeout_seconds: float = Field(default=120.0, gt=0.0)

    @property
    def quota_token_reservation(self) -> int:
        return self.prompt.token_estimate + self.max_output_tokens + self.thinking_token_reserve

    #: Feedback from a rejected attempt, appended verbatim so the model is told
    #: what was wrong rather than asked again in the same words.
    correction: str | None = None

    def body(self) -> str:
        """The text actually sent, correction included."""
        if self.correction is None:
            return self.prompt.text
        return (
            f"{self.prompt.text}\n\n"
            "## Your previous answer was rejected\n\n"
            f"{self.correction}\n\n"
            "Return a single JSON object matching the response schema, and nothing else."
        )


class LLMProvider(Protocol):
    """What a backend must do. Deliberately two methods and no state."""

    def adjudicate(self, request: ProviderRequest) -> ProviderResponse:
        """Answer one request, or raise a :class:`ProviderError`."""
        ...

    def token_count(self, text: str) -> int:
        """How many tokens ``text`` costs, the way this backend counts them."""
        ...


@dataclass(frozen=True)
class ProviderTokenizer:
    """Adapts a provider to part 09's :class:`~caudit.retrieval.budget.Tokenizer`.

    This is the seam part 09 was written against: retrieval spends a budget
    against whatever counts tokens, and once a real backend exists the number
    a context is measured by is the number the backend will charge for.
    """

    provider: LLMProvider

    def count(self, text: str) -> int:
        return self.provider.token_count(text)

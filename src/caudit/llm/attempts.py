"""Provider-attempt execution, response validation, and cache integration."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from enum import StrEnum
from typing import Any, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from caudit.config.schema import LLMConfig
from caudit.llm.accounting import RunAccount
from caudit.llm.cache import ResponseCache, cache_key
from caudit.llm.prompts import AssembledPrompt
from caudit.llm.provider import (
    LLMProvider,
    ProviderRefusedError,
    ProviderRequest,
    ProviderUnavailableError,
)
from caudit.llm.redaction import RedactionReport
from caudit.model.adjudication import Adjudication, ProviderResponse, Tier, TriageResult, Usage
from caudit.model.finding import Limitation, ReviewReason

__all__ = [
    "AdjudicationOutcome",
    "Attempt",
    "AttemptOutcome",
    "request_adjudication",
    "request_structured",
    "request_triage",
]


class AttemptOutcome(StrEnum):
    """How one request to a backend ended."""

    ACCEPTED = "accepted"
    #: The response was not a schema-valid object. Prose lands here too.
    SCHEMA_INVALID = "schema_invalid"
    #: The response cited an id this candidate's bundle never issued.
    CITATION_UNKNOWN = "citation_unknown"
    #: The provider did not answer. Retryable.
    TRANSPORT_ERROR = "transport_error"
    #: The provider rejected the request. Not retryable.
    REFUSED = "refused"
    #: Served from the cache; no request was made.
    CACHED = "cached"


class Attempt(BaseModel):
    """One request, recorded so a run can be explained after the fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: Tier
    model_id: str = Field(min_length=1)
    number: int = Field(ge=1)
    outcome: AttemptOutcome
    detail: str = ""
    #: Seconds waited *before* this attempt. Zero on the first one.
    delay_seconds: float = Field(default=0.0, ge=0.0)
    usage: Usage = Field(default_factory=Usage)


class AdjudicationOutcome(BaseModel):
    """What one candidate's adjudication produced. A proposal, or a reason."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    tier: Tier
    model_id: str = Field(min_length=1)
    adjudication: Adjudication | None = None
    review_reason: ReviewReason | None = None
    attempts: list[Attempt] = Field(default_factory=list)
    usage: Usage = Field(default_factory=Usage)
    from_cache: bool = False
    #: The request's content address. Recorded instead of the request.
    prompt_fingerprint: str = ""
    redactions: RedactionReport = Field(default_factory=RedactionReport)
    limitations: list[Limitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_exactly_one_result(self) -> Self:
        if (self.adjudication is None) == (self.review_reason is None):
            raise ValueError(
                "an adjudication outcome is either a proposal or a reason it is not "
                "one; it can never be both or neither"
            )
        return self

    @property
    def accepted(self) -> bool:
        return self.adjudication is not None

    @property
    def answered(self) -> bool:
        """Whether any model tier supplied a usable structured answer.

        A valid triage dismissal is an answer even though it intentionally
        produces no full adjudication proposal.
        """
        return self.accepted or any(
            attempt.outcome in {AttemptOutcome.ACCEPTED, AttemptOutcome.CACHED}
            for attempt in self.attempts
        )

    @property
    def calls(self) -> int:
        """Requests that reached a backend. Cached answers are not calls."""
        return sum(1 for attempt in self.attempts if attempt.outcome is not AttemptOutcome.CACHED)


def request_triage(
    provider: LLMProvider,
    prompt: AssembledPrompt,
    *,
    config: LLMConfig,
    account: RunAccount,
    response_schema: dict[str, Any],
    schema_version: str,
    cache: ResponseCache | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[TriageResult | None, list[Attempt]]:
    """Ask the cheap tier. ``None`` means it could not be asked or would not answer.

    A triage failure is not a run failure: routing simply proceeds as if the
    tier had said "adjudicate, ambiguous", which is the answer that costs the
    most and assumes the least.
    """
    parsed, attempts, _usage = _attempt_loop(
        provider,
        prompt,
        tier=Tier.TRIAGE,
        model=TriageResult,
        config=config,
        account=account,
        response_schema=response_schema,
        schema_version=schema_version,
        cache=cache,
        sleeper=sleeper,
        check_citations=None,
    )
    return parsed, attempts


def request_structured(
    provider: LLMProvider,
    prompt: AssembledPrompt,
    *,
    tier: Tier,
    model: type[Any],
    config: LLMConfig,
    account: RunAccount,
    response_schema: dict[str, Any],
    schema_version: str,
    cache: ResponseCache | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    check_citations: Sequence[str] | None = None,
) -> tuple[Any, list[Attempt], Usage]:
    """Request and validate an arbitrary structured response model.

    Product adjudication and triage have narrower wrappers above because they
    attach their respective result contracts. Experimental controls use a
    smaller schema but must retain the same retry, validation, cache, and
    accounting behaviour rather than reimplementing that safety boundary.
    """
    return _attempt_loop(
        provider,
        prompt,
        tier=tier,
        model=model,
        config=config,
        account=account,
        response_schema=response_schema,
        schema_version=schema_version,
        cache=cache,
        sleeper=sleeper,
        check_citations=check_citations,
    )


def request_adjudication(
    provider: LLMProvider,
    prompt: AssembledPrompt,
    *,
    tier: Tier,
    config: LLMConfig,
    account: RunAccount,
    response_schema: dict[str, Any],
    schema_version: str,
    cache: ResponseCache | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    limitations: Sequence[Limitation] = (),
) -> AdjudicationOutcome:
    """Ask one tier for a proposal, retrying only what a retry can fix."""
    parsed, attempts, usage = _attempt_loop(
        provider,
        prompt,
        tier=tier,
        model=Adjudication,
        config=config,
        account=account,
        response_schema=response_schema,
        schema_version=schema_version,
        cache=cache,
        sleeper=sleeper,
        check_citations=prompt.evidence_ids,
    )
    return AdjudicationOutcome(
        candidate_id=prompt.candidate_id,
        tier=tier,
        model_id=account.model_id(tier),
        adjudication=parsed,
        review_reason=None if parsed is not None else _reason_for(attempts),
        attempts=attempts,
        usage=usage,
        from_cache=any(a.outcome is AttemptOutcome.CACHED for a in attempts),
        prompt_fingerprint=prompt.fingerprint,
        redactions=prompt.redactions,
        limitations=[*prompt.limitations, *limitations],
    )


def _reason_for(attempts: Sequence[Attempt]) -> ReviewReason:
    """Why no proposal came back, from the last thing that went wrong."""
    last = attempts[-1].outcome if attempts else AttemptOutcome.TRANSPORT_ERROR
    if last is AttemptOutcome.CITATION_UNKNOWN:
        return ReviewReason.CITATION_UNRESOLVED
    if last in {AttemptOutcome.TRANSPORT_ERROR, AttemptOutcome.REFUSED}:
        return ReviewReason.PROVIDER_UNAVAILABLE
    return ReviewReason.SCHEMA_INVALID_RESPONSE


class _Parsed(Protocol):
    """Anything ``model_validate_json`` can produce here."""


def _attempt_loop(
    provider: LLMProvider,
    prompt: AssembledPrompt,
    *,
    tier: Tier,
    model: type[Any],
    config: LLMConfig,
    account: RunAccount,
    response_schema: dict[str, Any],
    schema_version: str,
    cache: ResponseCache | None,
    sleeper: Callable[[float], None],
    check_citations: Sequence[str] | None,
) -> tuple[Any, list[Attempt], Usage]:
    """Ask until the answer is valid, the attempts run out, or a retry is pointless."""
    model_id = account.model_id(tier)
    attempts: list[Attempt] = []
    total = Usage()
    correction: str | None = None

    key = cache_key(
        prompt=prompt.text,
        model_id=model_id,
        prompt_version=prompt.prompt_version,
        schema_version=schema_version,
    )
    if cache is not None:
        remembered = cache.get(key)
        if remembered is not None:
            try:
                parsed = model.model_validate(remembered.payload)
            except ValidationError:
                parsed = None
            if parsed is not None:
                account.charge(tier, remembered.usage, cached=True)
                attempts.append(
                    Attempt(
                        tier=tier,
                        model_id=model_id,
                        number=1,
                        outcome=AttemptOutcome.CACHED,
                        detail=f"served from the response cache ({key[:12]})",
                        usage=remembered.usage,
                    )
                )
                return parsed, attempts, remembered.usage

    for number in range(1, config.max_attempts + 1):
        request = ProviderRequest(
            tier=tier,
            model_id=model_id,
            prompt=prompt,
            response_schema=response_schema,
            timeout_seconds=config.request_timeout_seconds,
            correction=correction,
        )
        response, transport = _call(provider, request, config=config, sleeper=sleeper)
        attempts.extend(transport)
        if response is None:
            return None, attempts, total

        total = total + response.usage
        account.charge(tier, response.usage)

        try:
            parsed = model.model_validate_json(response.text)
        except ValidationError as exc:
            correction = _correction(exc)
            attempts.append(
                Attempt(
                    tier=tier,
                    model_id=model_id,
                    number=number,
                    outcome=AttemptOutcome.SCHEMA_INVALID,
                    detail=correction,
                    usage=response.usage,
                )
            )
            continue

        unknown = _unknown_citations(parsed, check_citations)
        if unknown:
            attempts.append(
                Attempt(
                    tier=tier,
                    model_id=model_id,
                    number=number,
                    outcome=AttemptOutcome.CITATION_UNKNOWN,
                    detail=(
                        f"cited {len(unknown)} evidence id(s) that were never issued: "
                        f"{', '.join(unknown)}"
                    ),
                    usage=response.usage,
                ),
            )
            return None, attempts, total

        attempts.append(
            Attempt(
                tier=tier,
                model_id=model_id,
                number=number,
                outcome=AttemptOutcome.ACCEPTED,
                usage=response.usage,
            )
        )
        if cache is not None and not response.from_cache:
            cache.put(
                key=key,
                tier=tier,
                model_id=model_id,
                prompt_version=prompt.prompt_version,
                schema_version=schema_version,
                prompt=request.body(),
                payload=parsed.model_dump(mode="json"),
                usage=response.usage,
                finish_reason=response.finish_reason,
                response_text=response.text,
            )
        return parsed, attempts, total

    return None, attempts, total


def _call(
    provider: LLMProvider,
    request: ProviderRequest,
    *,
    config: LLMConfig,
    sleeper: Callable[[float], None],
) -> tuple[ProviderResponse | None, list[Attempt]]:
    """One logical request, retrying transport failures with backoff."""
    attempts: list[Attempt] = []
    delay = 0.0
    for number in range(1, config.max_transport_attempts + 1):
        if delay:
            sleeper(delay)
        try:
            return provider.adjudicate(request), attempts
        except ProviderRefusedError as exc:
            attempts.append(
                Attempt(
                    tier=request.tier,
                    model_id=request.model_id,
                    number=number,
                    outcome=AttemptOutcome.REFUSED,
                    detail=exc.message,
                    delay_seconds=delay,
                )
            )
            return None, attempts
        except ProviderUnavailableError as exc:
            attempts.append(
                Attempt(
                    tier=request.tier,
                    model_id=request.model_id,
                    number=number,
                    outcome=AttemptOutcome.TRANSPORT_ERROR,
                    detail=exc.message,
                    delay_seconds=delay,
                )
            )
            delay = config.backoff_seconds if delay == 0.0 else delay * config.backoff_multiplier
    return None, attempts


def _correction(error: ValidationError) -> str:
    """What the model is told about its rejected answer.

    The validation errors themselves, trimmed. Not a paraphrase: the model
    needs the field names and the rule it broke, and inventing friendlier prose
    would describe a schema that is not the one being enforced.
    """
    lines = [
        f"- {'.'.join(str(part) for part in item['loc']) or '<root>'}: {item['msg']}"
        for item in error.errors()[:8]
    ]
    return "The response did not satisfy the schema:\n" + "\n".join(lines)


def _unknown_citations(parsed: Any, issued: Sequence[str] | None) -> list[str]:
    """Cited ids the bundle never handed out."""
    if issued is None:
        return []
    cited: Sequence[str] = getattr(parsed, "cited_evidence_ids", ())
    allowed = set(issued)
    return sorted({identifier for identifier in cited if identifier not in allowed})

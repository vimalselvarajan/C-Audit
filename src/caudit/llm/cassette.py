"""Recorded exchanges, replayed offline.

A cassette is a list of turns: what the backend said, or how it failed, in the
order it was asked. Replaying one takes exactly the path a live call takes —
same request assembly, same schema validation, same retry loop — so a test
never exercises a shortcut production does not have, and a run can be
reproduced on a machine with no key and no network.

Two guards keep a cassette from quietly testing a prompt that no longer
exists:

* it records the prompt version it was captured against, and refuses to answer
  a request assembled from a different one;
* it refuses to answer more requests than it holds, rather than repeating the
  last turn. A loop that asked one more time than the recording expected is a
  behaviour change, and silently answering it would hide exactly that.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.llm.provider import ProviderRefusedError, ProviderRequest, ProviderUnavailableError
from caudit.model.adjudication import ProviderResponse, Usage
from caudit.retrieval.budget import DEFAULT_TOKENIZER, Tokenizer

__all__ = ["Cassette", "CassetteError", "CassetteProvider", "TurnFailure"]


class CassetteError(RuntimeError):
    """A cassette cannot answer the request it was handed."""


class TurnFailure(StrEnum):
    """How a recorded turn fails instead of answering."""

    #: Transport: a timeout, a rate limit. The retry loop should try again.
    UNAVAILABLE = "unavailable"
    #: The provider rejected the request. The retry loop should stop.
    REFUSED = "refused"


class CassetteTurn(BaseModel):
    """One recorded answer, or one recorded failure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Exactly what came back, byte for byte — including malformed JSON and
    #: prose. Storing the parsed object instead would make it impossible to
    #: record the failures this part exists to handle.
    text: str | None = None
    fails: TurnFailure | None = None
    detail: str = "recorded failure"
    usage: Usage = Field(default_factory=Usage)
    finish_reason: str = "STOP"
    #: Optional note explaining what this turn is for. Never sent anywhere.
    note: str = ""

    @model_validator(mode="after")
    def _check_exactly_one_behaviour(self) -> Self:
        if (self.text is None) == (self.fails is None):
            raise ValueError("a turn either returns text or fails; never both, never neither")
        return self


class Cassette(BaseModel):
    """A recorded sequence of exchanges for one scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    description: str = ""
    #: The prompt version this was captured against. A mismatch is refused.
    prompt_version: str = Field(default="1", min_length=1)
    turns: list[CassetteTurn] = Field(min_length=1)

    @classmethod
    def load(cls, path: Path) -> Cassette:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.loads(self.model_dump_json())
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path


class CassetteProvider:
    """An :class:`~caudit.llm.provider.LLMProvider` that replays a cassette."""

    def __init__(self, cassette: Cassette, *, tokenizer: Tokenizer = DEFAULT_TOKENIZER) -> None:
        self.cassette = cassette
        self.requests: list[ProviderRequest] = []
        self._tokenizer = tokenizer
        self._position = 0

    @property
    def calls(self) -> int:
        """How many requests reached this provider. Zero is a meaningful answer."""
        return len(self.requests)

    def adjudicate(self, request: ProviderRequest) -> ProviderResponse:
        if request.prompt.prompt_version != self.cassette.prompt_version:
            raise CassetteError(
                f"cassette '{self.cassette.name}' was recorded against prompt version "
                f"{self.cassette.prompt_version}, but this request was assembled from "
                f"version {request.prompt.prompt_version}; re-record it"
            )
        if self._position >= len(self.cassette.turns):
            raise CassetteError(
                f"cassette '{self.cassette.name}' holds {len(self.cassette.turns)} turn(s) "
                f"and was asked {self._position + 1} time(s)"
            )
        turn = self.cassette.turns[self._position]
        self._position += 1
        self.requests.append(request)

        if turn.fails is TurnFailure.UNAVAILABLE:
            raise ProviderUnavailableError(turn.detail)
        if turn.fails is TurnFailure.REFUSED:
            raise ProviderRefusedError(turn.detail)
        return ProviderResponse(
            tier=request.tier,
            model_id=request.model_id,
            text=turn.text or "",
            usage=turn.usage,
            finish_reason=turn.finish_reason,
        )

    def token_count(self, text: str) -> int:
        return self._tokenizer.count(text)

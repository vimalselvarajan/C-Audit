"""Content-addressed response cache.

The key is ``sha256(prompt || model_id || prompt_version || schema_version)``.
Each component earns its place: the prompt is the question, the model id is who
answered it, the prompt version is the instructions that shaped it, and the
schema version is the shape the answer had to take. Change any one of them and
the cached answer is an answer to a different question, so it must miss.

What is stored is the **parsed** result, not the exchange. The prompt is
reduced to a fingerprint and the raw response text is dropped, so a cache
directory contains no source, no quoted code, and nothing that could carry a
credential out of the repository. ``llm.retain_raw`` turns that off explicitly,
and a run that sets it records the fact in the manifest.

A cache hit is also what makes cassette-based testing honest: replaying a
recorded answer takes exactly the path a cached one does, through the same
validation, so a test never exercises a shortcut production does not have.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.logging import get_logger, redact
from caudit.model.adjudication import ProviderResponse, Tier, Usage

__all__ = ["CacheEntry", "ResponseCache", "cache_key"]

log = get_logger(__name__)

_SEP: Final = b"\x00"


def cache_key(*, prompt: str, model_id: str, prompt_version: str, schema_version: str) -> str:
    """The content address of one request. Domain-separated, like every other id."""
    hasher = sha256()
    hasher.update(b"caudit/llm-cache/v1")
    for part in (prompt, model_id, prompt_version, schema_version):
        hasher.update(_SEP)
        hasher.update(part.encode("utf-8"))
    return hasher.hexdigest()


class CacheEntry(BaseModel):
    """One remembered answer, with everything needed to know it still applies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1)
    tier: Tier
    model_id: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    #: The prompt's content address. The prompt itself is not stored.
    prompt_fingerprint: str = Field(min_length=1)
    #: The parsed, schema-valid response object.
    payload: dict[str, Any]
    usage: Usage = Field(default_factory=Usage)
    finish_reason: str = "unknown"
    created_at: datetime
    #: Populated only when ``llm.retain_raw`` is set.
    prompt: str | None = None
    response_text: str | None = None

    def as_response(self) -> ProviderResponse:
        """Replay this entry down the same path a live answer takes."""
        return ProviderResponse(
            tier=self.tier,
            model_id=self.model_id,
            text=json.dumps(self.payload, sort_keys=True),
            usage=self.usage,
            finish_reason=self.finish_reason,
            from_cache=True,
        )


class ResponseCache:
    """A directory of remembered answers. Disabled is a first-class state."""

    def __init__(
        self,
        directory: Path | None,
        *,
        enabled: bool = True,
        retain_raw: bool = False,
    ) -> None:
        self.directory = directory
        self.enabled = enabled and directory is not None
        self.retain_raw = retain_raw
        self.hits = 0
        self.misses = 0
        self.writes = 0

    def path_for(self, key: str) -> Path | None:
        if self.directory is None:
            return None
        return self.directory / f"{key}.json"

    def get(self, key: str) -> CacheEntry | None:
        """A remembered answer, or ``None``.

        An entry that will not parse is a miss, not an error. A cache is an
        optimisation; a corrupt one must cost a call, never a run.
        """
        path = self.path_for(key)
        if not self.enabled or path is None:
            self.misses += 1
            return None
        try:
            entry = CacheEntry.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.misses += 1
            return None
        self.hits += 1
        return entry

    def put(
        self,
        *,
        key: str,
        tier: Tier,
        model_id: str,
        prompt_version: str,
        schema_version: str,
        prompt: str,
        payload: dict[str, Any],
        usage: Usage,
        finish_reason: str,
        response_text: str,
        now: datetime | None = None,
    ) -> Path | None:
        """Remember one answer. Returns the file written, or ``None`` when disabled."""
        path = self.path_for(key)
        if not self.enabled or path is None:
            return None
        entry = CacheEntry(
            key=key,
            tier=tier,
            model_id=model_id,
            prompt_version=prompt_version,
            schema_version=schema_version,
            prompt_fingerprint=sha256(prompt.encode("utf-8")).hexdigest(),
            payload=payload,
            usage=usage,
            finish_reason=finish_reason,
            created_at=now or datetime.now(UTC),
            # Redacted even when retained: the process already knows which
            # literals are secrets, and a cache file is a file on disk like
            # any other.
            prompt=redact(prompt) if self.retain_raw else None,
            response_text=redact(response_text) if self.retain_raw else None,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                json.loads(entry.model_dump_json()), indent=2, sort_keys=True, ensure_ascii=False
            )
            + "\n",
            encoding="utf-8",
        )
        self.writes += 1
        return path

    def describe(self) -> str:
        if not self.enabled:
            return "response cache disabled"
        return f"{self.hits} hit(s), {self.misses} miss(es), {self.writes} write(s)"

"""Machine-readable repeated-pilot records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = ["PilotRepetition", "RepeatedCastlePilot", "write_castle_pilot"]


class PilotRepetition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repetition: int = Field(ge=1)
    status: Literal["completed", "failed"]
    report: str | None = None
    candidate_set_hash: str | None = None
    corpus_hash: str | None = None
    precision: float | None = None
    recall: float | None = None
    macro_f2: float | None = None
    failure: str = ""


class RepeatedCastlePilot(BaseModel):
    """First development pilot; a deterministic control, not model variance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    suite: str = "castle"
    condition: str = "attribution_a0"
    scope: str = "claimed-scope stratified development pilot"
    selection_seed: int
    selection_algorithm: str
    case_ids: list[str]
    requested_repetitions: int = Field(ge=1)
    stopping_rule: str
    condition_order: list[str] = Field(default_factory=lambda: ["A0"])
    model_cache: str = "not applicable; analyzer-only"
    cold_repetition_definition: str
    repetitions: list[PilotRepetition]
    candidate_identity_stable: bool
    corpus_identity_stable: bool
    result_stable: bool
    inference: str = (
        "This establishes harness repeatability only. It contains no model calls and "
        "must not be used to estimate Gemini variance or an enhancement effect."
    )

    @model_validator(mode="after")
    def every_attempt_is_recorded(self) -> Self:
        if len(self.repetitions) != self.requested_repetitions:
            raise ValueError("every requested repetition, including failures, must be recorded")
        return self


def write_castle_pilot(pilot: RepeatedCastlePilot, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(json.loads(pilot.model_dump_json()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path

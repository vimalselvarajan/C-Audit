"""The run manifest — what makes a report reproducible and comparable.

Every field here exists so two runs can be told apart for a reason. A
manifest missing an analyzer version is rejected: a run whose tool versions
are unknown cannot be reproduced, and a report that cannot be reproduced
cannot be audited.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.model.finding import SCHEMA_VERSION
from caudit.model.source import Sha256

__all__ = [
    "CoverageReport",
    "ModelRecord",
    "RunManifest",
    "StageRecord",
    "StageStatus",
    "ToolRecord",
]


class ToolRecord(BaseModel):
    """One analyzer or compiler, and the version that actually ran."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    path: str | None = None


class ModelRecord(BaseModel):
    """One model tier as configured for this run.

    Model ids are configuration and are recorded per run, never hard-coded in
    the architecture.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)


class StageStatus(StrEnum):
    """How one pipeline stage ended.

    ``skipped`` and ``failed`` are deliberately different: a stage nobody asked
    for did not fail, and a stage that failed did not decline to run. Only the
    second makes a report partial.
    """

    OK = "ok"
    #: The stage produced output, but less than it was asked for — some
    #: translation units failed to parse, some candidates were never sent.
    DEGRADED = "degraded"
    #: The stage produced nothing. The run continues on what it already had.
    FAILED = "failed"
    #: Never asked to run. Adjudication without consent is the usual case.
    SKIPPED = "skipped"


class StageRecord(BaseModel):
    """One pipeline stage: how long it took and how it ended.

    Timings live here rather than beside the findings for the same reason the
    timestamps do — a duration is machine-specific, and ``report.md`` and
    ``results.sarif`` have to stay byte-identical across two runs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: str = Field(min_length=1)
    status: StageStatus
    duration_seconds: float = Field(ge=0.0)
    #: Why a stage is anything other than ``ok``. Required for those, because
    #: a degraded stage a reader cannot diagnose is just a worse ``ok``.
    detail: str | None = None

    @model_validator(mode="after")
    def _check_a_problem_is_explained(self) -> Self:
        if self.status is not StageStatus.OK and not (self.detail or "").strip():
            raise ValueError(
                f"stage '{self.stage}' is {self.status} with no detail; a run that cannot "
                "say what went wrong cannot be acted on"
            )
        return self


class CoverageReport(BaseModel):
    """How much of the repository was actually analysed.

    Confirmed and review-required counts live side by side and are never
    summed. There is no ``total_findings`` field, by design.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    translation_units_total: int = Field(ge=0)
    translation_units_parsed: int = Field(ge=0)
    translation_units_failed: int = Field(ge=0)
    excluded_paths: list[PurePosixPath] = Field(default_factory=list)
    excluded_reasons: dict[str, str] = Field(default_factory=dict)
    lines_of_code: int = Field(default=0, ge=0)
    confirmed_count: int = Field(default=0, ge=0)
    review_required_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _check_arithmetic(self) -> Self:
        counted = self.translation_units_parsed + self.translation_units_failed
        if counted > self.translation_units_total:
            raise ValueError(
                f"parsed + failed ({counted}) exceeds total translation units "
                f"({self.translation_units_total})"
            )
        return self


class RunManifest(BaseModel):
    """Everything needed to reproduce and compare a run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    caudit_version: str = Field(min_length=1)
    started_at: datetime
    finished_at: datetime
    repository_root: str = Field(min_length=1)
    #: Resolved commit hash, or an explicit marker when the tree is not a
    #: repository. Never blank, never guessed.
    revision: str = Field(min_length=1)
    revision_dirty: bool = False
    compile_commands_path: str | None = None
    compile_commands_sha256: Sha256 | None = None
    #: Every analyzer and compiler that ran, with its version.
    tools: list[ToolRecord] = Field(min_length=1)
    models: list[ModelRecord] = Field(default_factory=list)
    config_snapshot: dict[str, object] = Field(default_factory=dict)
    #: Content address of the effective configuration. Two runs whose reports
    #: differ can be told apart by this one line without diffing the whole
    #: snapshot, and it is what makes "same inputs" a checkable claim.
    config_hash: Sha256
    policy_versions: dict[str, str] = Field(default_factory=dict)
    #: Hashes of every cited region, keyed by the finding that cites it, so a
    #: later run can detect drift under an unchanged finding id.
    cited_region_hashes: dict[str, Sha256] = Field(default_factory=dict)
    coverage: CoverageReport
    #: One record per pipeline stage, in the order the run executed them.
    stages: list[StageRecord] = Field(default_factory=list)
    #: Total spend from reported provider usage and the configured price
    #: table. ``0.0`` on a run that asked no model, and on one whose tiers are
    #: all priced at zero — the two are told apart by :attr:`models`.
    total_cost_usd: float = Field(default=0.0, ge=0.0)
    #: Whether a stage failed or degraded, so this report is incomplete.
    #: Never set by a caller: :meth:`_derive_partial` recomputes it from
    #: :attr:`stages` on every construction, including when a manifest is read
    #: back from disk. A stored flag that could disagree with the records under
    #: it is the one mistake this field exists to prevent, and a JSON consumer
    #: should not have to re-implement the rule to learn the answer.
    partial: bool = False

    @model_validator(mode="before")
    @classmethod
    def _derive_partial(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        stages = data.get("stages") or ()
        if not isinstance(stages, list | tuple):
            return data
        data = dict(data)
        data["partial"] = any(_stage_is_a_problem(stage) for stage in stages)
        return data

    @model_validator(mode="after")
    def _check_timing(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        return self

    def failed_stages(self) -> list[StageRecord]:
        """Every stage that did not complete as asked, in run order."""
        return [record for record in self.stages if record.status is not StageStatus.OK]


#: Statuses that make a report partial. ``skipped`` is deliberately absent: a
#: run that was never asked to adjudicate is complete, not degraded.
_PARTIAL_STATUSES: frozenset[StageStatus] = frozenset({StageStatus.FAILED, StageStatus.DEGRADED})


def _stage_is_a_problem(stage: object) -> bool:
    """Whether one stage — as a record or as raw JSON — makes a run partial."""
    if isinstance(stage, StageRecord):
        return stage.status in _PARTIAL_STATUSES
    if isinstance(stage, dict):
        return stage.get("status") in {str(status) for status in _PARTIAL_STATUSES}
    return False

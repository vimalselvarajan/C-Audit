"""Cumulative A0-A7 attribution matrix and comparability contract."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.eval.case import TruthFrame
from caudit.eval.compare import CostSummary, RunReport
from caudit.eval.experiment import ExperimentCondition

__all__ = [
    "ATTRIBUTION_DEFINITIONS",
    "AttributionInvariant",
    "AttributionMatrix",
    "AttributionRow",
    "AttributionStage",
    "AttributionStatus",
    "build_attribution_matrix",
    "write_attribution_matrix",
]


class AttributionStage(StrEnum):
    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"
    A5 = "A5"
    A6 = "A6"
    A7 = "A7"


class AttributionStatus(StrEnum):
    MEASURED = "measured"
    NOT_RUN = "not_run"
    DEFERRED = "deferred"


ATTRIBUTION_DEFINITIONS: Final[dict[AttributionStage, tuple[str, ...]]] = {
    AttributionStage.A0: ("analyzer-only promotion",),
    AttributionStage.A1: (
        "analyzer candidates",
        "naïve Gemini diagnostic + fixed ±40-line window",
    ),
    AttributionStage.A2: (
        "analyzer candidates",
        "naïve Gemini diagnostic + fixed ±40-line window",
        "compact structured verdict schema",
    ),
    AttributionStage.A3: (
        "analyzer candidates",
        "compact structured verdict schema",
        "compiler-aware structural retrieval",
        "issued evidence identifiers",
    ),
    AttributionStage.A4: (
        "analyzer candidates",
        "compact structured verdict schema",
        "compiler-aware structural retrieval",
        "issued evidence identifiers",
        "deterministic citation/quotation/call-edge/CWE verification",
    ),
    AttributionStage.A5: (
        "analyzer candidates",
        "compact structured verdict schema",
        "compiler-aware structural retrieval",
        "issued evidence identifiers",
        "deterministic citation/quotation/call-edge/CWE verification",
        "compact triage and empirical routing",
    ),
    AttributionStage.A6: (
        "A5",
        "bounded read-only evidence-navigation loop",
    ),
    AttributionStage.A7: (
        "A6",
        "complete quota-aware free-tier configuration",
    ),
}


class AttributionInvariant(BaseModel):
    """Fields that must be identical in every measured Track-A row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_set_hash: str = Field(min_length=64, max_length=64)
    candidate_count: int = Field(ge=0)
    corpus_hash: str = Field(min_length=64, max_length=64)
    corpus_revision: str
    truth_frame: TruthFrame
    model_id: str
    thinking_level: str
    max_output_tokens: int = Field(gt=0)


class AttributionRow(BaseModel):
    """One cumulative condition, measured or named as intentionally absent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: AttributionStage
    capabilities: tuple[str, ...]
    status: AttributionStatus
    condition: ExperimentCondition
    report: str | None = None
    reason: str = ""
    precision: float | None = None
    recall: float | None = None
    macro_f2: float | None = None
    confirmed_count: int | None = Field(default=None, ge=0)
    review_required_count: int | None = Field(default=None, ge=0)
    cost: CostSummary = Field(default_factory=CostSummary)

    @model_validator(mode="after")
    def measured_has_a_report(self) -> Self:
        if self.status is AttributionStatus.MEASURED and self.report is None:
            raise ValueError("a measured attribution row must name its immutable run report")
        if self.status is not AttributionStatus.MEASURED and self.report is not None:
            raise ValueError("an unmeasured attribution row cannot name a run report")
        return self


class LeaveOneOutRow(BaseModel):
    """Predeclared A7 leave-one-out comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    removed_capability: str
    status: AttributionStatus = AttributionStatus.DEFERRED
    reason: str = "requires a measured A7 reference row"


class AttributionMatrix(BaseModel):
    """A matrix whose measured rows share candidate, corpus, and model identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    suite: str
    invariant: AttributionInvariant
    rows: list[AttributionRow]
    leave_one_out: list[LeaveOneOutRow]
    primary_endpoint: str = "confirmed-finding precision"
    recall_noninferiority_margin: float = -0.02

    @model_validator(mode="after")
    def contains_every_stage_once(self) -> Self:
        stages = [row.stage for row in self.rows]
        if stages != list(AttributionStage):
            raise ValueError("attribution rows must contain A0 through A7 exactly once, in order")
        return self


def build_attribution_matrix(
    *,
    suite: str,
    reports: dict[AttributionStage, tuple[Path, RunReport]],
    model_id: str,
    thinking_level: str,
    max_output_tokens: int,
) -> AttributionMatrix:
    """Validate shared Track-A identity and build all cumulative/LOO rows."""

    if AttributionStage.A0 not in reports:
        raise ValueError("an attribution matrix requires the A0 analyzer control")
    first_report = reports[AttributionStage.A0][1]
    first = first_report.experiment
    if first is None:
        raise ValueError("attribution reports require immutable experiment manifests")

    invariant = AttributionInvariant(
        candidate_set_hash=first.candidate_set_hash,
        candidate_count=first.candidate_count,
        corpus_hash=first.corpus_hash,
        corpus_revision=first.corpus_revision,
        truth_frame=first.truth_frame,
        model_id=model_id,
        thinking_level=thinking_level,
        max_output_tokens=max_output_tokens,
    )
    rows: list[AttributionRow] = []
    for stage in AttributionStage:
        measured = reports.get(stage)
        if measured is None:
            deferred = stage in {AttributionStage.A6, AttributionStage.A7}
            rows.append(
                AttributionRow(
                    stage=stage,
                    capabilities=ATTRIBUTION_DEFINITIONS[stage],
                    status=AttributionStatus.DEFERRED if deferred else AttributionStatus.NOT_RUN,
                    condition=_condition(stage),
                    reason=(
                        "bounded evidence tools are deliberately sequenced after the first six "
                        "strategic change sets"
                        if deferred
                        else "condition was not selected for this run"
                    ),
                )
            )
            continue
        path, report = measured
        experiment = report.experiment
        if experiment is None:
            raise ValueError(f"{stage} has no immutable experiment manifest")
        for field in (
            "candidate_set_hash",
            "candidate_count",
            "corpus_hash",
            "corpus_revision",
            "truth_frame",
        ):
            if getattr(experiment, field) != getattr(invariant, field):
                raise ValueError(f"{stage} experiment {field} differs from A0")
        metrics = report.metrics
        rows.append(
            AttributionRow(
                stage=stage,
                capabilities=ATTRIBUTION_DEFINITIONS[stage],
                status=AttributionStatus.MEASURED,
                condition=_condition(stage),
                report=str(path),
                precision=metrics.precision,
                recall=metrics.recall,
                macro_f2=metrics.macro_f2,
                confirmed_count=metrics.confirmed_count,
                review_required_count=metrics.review_required_count,
                cost=report.cost,
            )
        )

    return AttributionMatrix(
        suite=suite,
        invariant=invariant,
        rows=rows,
        leave_one_out=[
            LeaveOneOutRow(
                name="A7-minus-verifier",
                removed_capability="deterministic citation/quotation/call-edge/CWE verification",
            ),
            LeaveOneOutRow(
                name="A7-minus-structural-retrieval",
                removed_capability="compiler-aware structural retrieval",
            ),
        ],
    )


def write_attribution_matrix(matrix: AttributionMatrix, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(json.loads(matrix.model_dump_json()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _condition(stage: AttributionStage) -> ExperimentCondition:
    return ExperimentCondition(f"attribution_{stage.lower()}")

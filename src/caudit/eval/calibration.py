"""Do the confidence labels mean anything?

`high` and `medium` are printed on every finding, and a reader will act on
them. This module checks the one thing that makes them worth printing: that
findings labelled `high` are true more often than findings labelled `medium`.
If they are not, the labels are decoration, and the honest response is to fail
loudly rather than to keep printing them.

Part 11 computes confidence from whether the citations resolved, so a
miscalibration here is a statement about that rule rather than about a model's
self-assessment — which is exactly the kind of claim this project should be
willing to have measured.

Two rules:

**Nothing is pooled across policy versions.** A reliability curve mixing two
prompt versions is a curve of neither. :func:`calibrate` refuses outright, with
both versions named, rather than producing a number that averages two
different tools.

**The overall score stays behind the hard gates.** The spec makes the 50/50
average valid only once every gate passes, and part 04's
:func:`~caudit.eval.gates.overall_score` already refuses otherwise. This module
routes through it rather than computing its own average, so there is one place
that rule lives.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from itertools import pairwise
from pathlib import Path
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.eval.gates import GateResult, overall_score
from caudit.model.finding import Confidence, Severity

__all__ = [
    "CONFIDENCE_ORDER",
    "CalibrationError",
    "CalibrationReport",
    "ReliabilityBin",
    "ScoredFinding",
    "SeverityAgreement",
    "calibrate",
    "gated_overall_score",
    "severity_agreement",
]

#: Strongest first. A calibrated set has a non-increasing accuracy down this
#: list; anything else means the labels are not ordered by what they claim.
CONFIDENCE_ORDER: Final[tuple[Confidence, ...]] = (
    Confidence.HIGH,
    Confidence.MEDIUM,
    Confidence.REVIEW_REQUIRED,
)


class CalibrationError(ValueError):
    """The labels do not mean what they say, or cannot be measured."""


class ScoredFinding(BaseModel):
    """One finding with the answer known, for calibration only.

    ``truth`` comes from a pair set or an adjudicated corpus — never from the
    run being measured. A calibration computed from the tool's own confidence
    would be perfectly calibrated and entirely uninformative.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1)
    confidence: Confidence
    #: Whether the finding was actually a defect.
    truth: bool
    #: What the report claimed, and what an adjudicator judged. Both optional:
    #: severity calibration needs a corpus that has adjudicated severities, and
    #: a pair set does not always.
    reported_severity: Severity | None = None
    adjudicated_severity: Severity | None = None


class ReliabilityBin(BaseModel):
    """One confidence label's observed accuracy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    confidence: Confidence
    count: int = Field(ge=0)
    correct: int = Field(ge=0)

    @property
    def accuracy(self) -> float:
        """Share that turned out to be true. Vacuously 1.0 for an empty bin."""
        return 1.0 if not self.count else self.correct / self.count

    def describe(self) -> str:
        return f"{self.confidence}: {self.correct}/{self.count} true ({self.accuracy:.3f})"


class SeverityAgreement(BaseModel):
    """How often the reported severity matched an adjudicator's."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    compared: int = Field(ge=0)
    exact: int = Field(ge=0)
    #: Reported higher than adjudicated. The direction that costs a reader
    #: time; the other direction costs them a defect, so they are counted apart.
    overstated: int = Field(ge=0)
    understated: int = Field(ge=0)

    @property
    def exact_rate(self) -> float:
        return 1.0 if not self.compared else self.exact / self.compared

    def describe(self) -> str:
        return (
            f"{self.exact}/{self.compared} severities matched exactly "
            f"({self.exact_rate:.3f}); {self.overstated} overstated, "
            f"{self.understated} understated"
        )


class CalibrationReport(BaseModel):
    """The reliability curve, and whether it holds up."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bins: list[ReliabilityBin] = Field(default_factory=list)
    severity: SeverityAgreement | None = None
    policy_versions: dict[str, str] = Field(default_factory=dict)
    #: Why the labels are not ordered as they claim, when they are not.
    miscalibration: str | None = None

    @model_validator(mode="after")
    def _check_bins_are_ordered_and_unique(self) -> Self:
        labels = [entry.confidence for entry in self.bins]
        if len(set(labels)) != len(labels):
            raise ValueError("a reliability curve has one bin per confidence label")
        return self

    @property
    def calibrated(self) -> bool:
        return self.miscalibration is None

    def accuracy_for(self, confidence: Confidence) -> float | None:
        for entry in self.bins:
            if entry.confidence is confidence:
                return entry.accuracy
        return None

    def describe(self) -> str:
        curve = "; ".join(entry.describe() for entry in self.bins)
        if self.miscalibration:
            return f"{curve} — MISCALIBRATED: {self.miscalibration}"
        return curve

    def assert_calibrated(self) -> None:
        """Raise when the labels are not ordered as they claim (AC-13-10)."""
        if self.miscalibration is not None:
            raise CalibrationError(self.miscalibration)


def calibrate(
    findings: Sequence[ScoredFinding],
    *,
    policy_versions: Mapping[str, str],
    minimum_per_bin: int = 5,
) -> CalibrationReport:
    """Build the reliability curve and check that the labels are ordered.

    ``minimum_per_bin`` is the point below which a bin is too small to judge.
    Two `high` findings, one of them wrong, is not evidence of miscalibration —
    calling it that would make the check fire on noise and be switched off,
    which is worse than not having it.
    """
    bins = [
        ReliabilityBin(
            confidence=confidence,
            count=sum(1 for finding in findings if finding.confidence is confidence),
            correct=sum(
                1 for finding in findings if finding.confidence is confidence and finding.truth
            ),
        )
        for confidence in CONFIDENCE_ORDER
    ]
    return CalibrationReport(
        bins=bins,
        severity=severity_agreement(findings),
        policy_versions=dict(sorted(policy_versions.items())),
        miscalibration=_miscalibration(bins, minimum_per_bin),
    )


def _miscalibration(bins: Sequence[ReliabilityBin], minimum: int) -> str | None:
    """The first pair of labels whose accuracies are out of order.

    Only adjacent pairs with enough data on both sides are compared. A label
    that outranks the one below it by less than nothing is the failure; a label
    nobody used often enough to judge is silence, not a pass.
    """
    judged = [entry for entry in bins if entry.count >= minimum]
    for stronger, weaker in pairwise(judged):
        if stronger.accuracy < weaker.accuracy:
            return (
                f"findings labelled {stronger.confidence} were true "
                f"{stronger.accuracy:.3f} of the time, less often than "
                f"{weaker.confidence} at {weaker.accuracy:.3f}. The labels are not "
                "ordered by what they claim, so they should be recomputed rather than "
                "printed"
            )
    return None


def severity_agreement(findings: Iterable[ScoredFinding]) -> SeverityAgreement | None:
    """Reported severity against an adjudicator's, where both exist.

    ``None`` when nothing in the corpus carries an adjudicated severity, which
    is a different answer from perfect agreement and must not be rendered as
    one.
    """
    rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    compared = exact = overstated = understated = 0
    for finding in findings:
        reported, adjudicated = finding.reported_severity, finding.adjudicated_severity
        if reported is None or adjudicated is None:
            continue
        compared += 1
        if reported is adjudicated:
            exact += 1
        elif rank[reported] < rank[adjudicated]:
            overstated += 1
        else:
            understated += 1
    if not compared:
        return None
    return SeverityAgreement(
        compared=compared, exact=exact, overstated=overstated, understated=understated
    )


# ------------------------------------------------------------------- pooling


def assert_same_policy(reports: Sequence[CalibrationReport]) -> None:
    """Refuse to combine results from different policy versions (AC-13-11).

    Raises with both configurations named. A calibration curve that mixed two
    prompt versions describes neither tool, and the mistake is invisible in the
    output — which is why it has to be impossible rather than discouraged.
    """
    seen = {
        json.dumps(report.policy_versions, sort_keys=True)
        for report in reports
        if report.policy_versions
    }
    if len(seen) > 1:
        raise CalibrationError(
            f"these {len(reports)} results were produced under {len(seen)} different "
            "policy configurations and cannot be pooled: " + "; ".join(sorted(seen))
        )


def pooled(reports: Sequence[CalibrationReport], *, minimum_per_bin: int = 5) -> CalibrationReport:
    """One curve from several runs under the *same* policy configuration."""
    assert_same_policy(reports)
    if not reports:
        return CalibrationReport()
    bins = [
        ReliabilityBin(
            confidence=confidence,
            count=sum(_bin_of(report, confidence).count for report in reports),
            correct=sum(_bin_of(report, confidence).correct for report in reports),
        )
        for confidence in CONFIDENCE_ORDER
    ]
    return CalibrationReport(
        bins=bins,
        policy_versions=dict(reports[0].policy_versions),
        miscalibration=_miscalibration(bins, minimum_per_bin),
    )


def _bin_of(report: CalibrationReport, confidence: Confidence) -> ReliabilityBin:
    for entry in report.bins:
        if entry.confidence is confidence:
            return entry
    return ReliabilityBin(confidence=confidence, count=0, correct=0)


# --------------------------------------------------------------- the score


def gated_overall_score(
    security_score: float,
    maintainability_score: float,
    gates: Sequence[GateResult],
    calibration: CalibrationReport | None = None,
) -> float:
    """0.5·security + 0.5·maintainability, behind every gate (AC-13-12).

    Routes through part 04's :func:`~caudit.eval.gates.overall_score` rather
    than repeating the average, so the rule that an overall score is refused
    while a gate fails lives in exactly one place. Miscalibrated confidence is
    an additional refusal: a score built on labels that do not mean what they
    say is a number nobody should quote.
    """
    if calibration is not None:
        calibration.assert_calibrated()
    return overall_score(security_score, maintainability_score, gates)


def write_calibration(report: CalibrationReport, path: Path) -> Path:
    """Record a curve. Sorted keys, so two policy versions diff cleanly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.loads(report.model_dump_json())
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path

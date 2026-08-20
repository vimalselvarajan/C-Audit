"""Part 13's calibration: T-13-12 to T-13-16 (AC-13-10 to AC-13-12).

The check that matters is T-13-13: if findings labelled ``high`` are true less
often than findings labelled ``medium``, the labels are decoration and the run
should say so loudly rather than keep printing them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.eval.calibration import (
    CalibrationError,
    CalibrationReport,
    ReliabilityBin,
    ScoredFinding,
    assert_same_policy,
    calibrate,
    gated_overall_score,
    pooled,
    severity_agreement,
    write_calibration,
)
from caudit.eval.gates import GateResult
from caudit.model.finding import Confidence, Severity

POLICIES = {"matching": "1", "prompt": "2"}


def _findings(
    high: tuple[int, int], medium: tuple[int, int], review: tuple[int, int] = (0, 0)
) -> list[ScoredFinding]:
    """``(count, true_count)`` per label, as a flat list of scored findings."""
    out: list[ScoredFinding] = []
    for label, (count, correct) in (
        (Confidence.HIGH, high),
        (Confidence.MEDIUM, medium),
        (Confidence.REVIEW_REQUIRED, review),
    ):
        for index in range(count):
            out.append(
                ScoredFinding(
                    finding_id=f"{label}-{index}",
                    confidence=label,
                    truth=index < correct,
                )
            )
    return out


def _gate(name: str, *, passed: bool) -> GateResult:
    return GateResult(name=name, passed=passed, observed=1.0, threshold=0.95, detail="")


# ------------------------------------------------------------------- T-13-12


def test_the_reliability_curve_matches_the_hand_computation() -> None:
    """T-13-12 (AC-13-10): 8/10 high, 5/10 medium, computed on paper."""
    report = calibrate(_findings(high=(10, 8), medium=(10, 5)), policy_versions=POLICIES)

    assert report.accuracy_for(Confidence.HIGH) == pytest.approx(0.8)
    assert report.accuracy_for(Confidence.MEDIUM) == pytest.approx(0.5)
    assert report.calibrated
    assert report.policy_versions == POLICIES
    assert "high: 8/10 true (0.800)" in report.describe()


def test_an_empty_bin_is_vacuously_accurate_rather_than_zero() -> None:
    """A label nobody used is not a label that was always wrong."""
    report = calibrate(_findings(high=(4, 4), medium=(0, 0)), policy_versions=POLICIES)
    assert report.accuracy_for(Confidence.MEDIUM) == pytest.approx(1.0)
    assert report.calibrated


# ------------------------------------------------------------------- T-13-13


def test_a_high_label_that_is_true_less_often_than_medium_fails_loudly() -> None:
    """T-13-13 (AC-13-10): the labels are not ordered by what they claim."""
    report = calibrate(_findings(high=(10, 3), medium=(10, 9)), policy_versions=POLICIES)

    assert not report.calibrated
    assert report.miscalibration is not None
    assert "high" in report.miscalibration and "medium" in report.miscalibration
    assert "recomputed rather than printed" in report.miscalibration
    assert "MISCALIBRATED" in report.describe()

    with pytest.raises(CalibrationError, match="not ordered by what they claim"):
        report.assert_calibrated()


def test_a_bin_too_small_to_judge_is_silence_rather_than_a_failure() -> None:
    """Two high findings, one wrong, is noise — and a check that fires on noise
    is a check somebody switches off."""
    report = calibrate(
        _findings(high=(2, 1), medium=(10, 9)), policy_versions=POLICIES, minimum_per_bin=5
    )
    assert report.calibrated, report.miscalibration

    # With the threshold lowered, the same data does fire.
    strict = calibrate(
        _findings(high=(2, 1), medium=(10, 9)), policy_versions=POLICIES, minimum_per_bin=2
    )
    assert not strict.calibrated


def test_review_required_is_part_of_the_ordering_too() -> None:
    """Ordering runs the whole way down, not just high against medium."""
    report = calibrate(
        _findings(high=(10, 9), medium=(10, 5), review=(10, 8)), policy_versions=POLICIES
    )
    assert not report.calibrated
    assert report.miscalibration is not None
    assert "medium" in report.miscalibration and "review_required" in report.miscalibration


# --------------------------------------------------------------- severity


def test_severity_is_compared_against_an_adjudicator_in_both_directions() -> None:
    """AC-13-10: overstating costs a reader time, understating costs a defect."""
    findings = [
        ScoredFinding(
            finding_id="a",
            confidence=Confidence.HIGH,
            truth=True,
            reported_severity=Severity.HIGH,
            adjudicated_severity=Severity.HIGH,
        ),
        ScoredFinding(
            finding_id="b",
            confidence=Confidence.HIGH,
            truth=True,
            reported_severity=Severity.CRITICAL,
            adjudicated_severity=Severity.MEDIUM,
        ),
        ScoredFinding(
            finding_id="c",
            confidence=Confidence.MEDIUM,
            truth=True,
            reported_severity=Severity.LOW,
            adjudicated_severity=Severity.HIGH,
        ),
    ]
    report = severity_agreement(findings)

    assert report is not None
    assert report.compared == 3
    assert (report.exact, report.overstated, report.understated) == (1, 1, 1)
    assert report.exact_rate == pytest.approx(1 / 3)
    assert "overstated" in report.describe()


def test_a_corpus_with_no_adjudicated_severities_reports_nothing_rather_than_perfection() -> None:
    """``None`` must never render as complete agreement."""
    assert severity_agreement(_findings(high=(3, 3), medium=(0, 0))) is None
    assert calibrate(_findings(high=(3, 3), medium=(0, 0)), policy_versions=POLICIES).severity is (
        None
    )


# ------------------------------------------------------------------- T-13-14


def test_results_from_two_policy_versions_cannot_be_pooled() -> None:
    """T-13-14 (AC-13-11): a curve of two versions is a curve of neither."""
    first = calibrate(_findings(high=(10, 9), medium=(10, 5)), policy_versions={"prompt": "1"})
    second = calibrate(_findings(high=(10, 8), medium=(10, 4)), policy_versions={"prompt": "2"})

    with pytest.raises(CalibrationError) as caught:
        assert_same_policy([first, second])

    message = str(caught.value)
    assert '"prompt": "1"' in message and '"prompt": "2"' in message
    assert "cannot be pooled" in message

    with pytest.raises(CalibrationError, match="cannot be pooled"):
        pooled([first, second])


def test_two_runs_under_one_policy_pool_into_one_curve() -> None:
    first = calibrate(_findings(high=(10, 9), medium=(10, 5)), policy_versions=POLICIES)
    second = calibrate(_findings(high=(10, 7), medium=(10, 5)), policy_versions=POLICIES)

    combined = pooled([first, second])
    assert combined.accuracy_for(Confidence.HIGH) == pytest.approx(16 / 20)
    assert combined.accuracy_for(Confidence.MEDIUM) == pytest.approx(10 / 20)
    assert combined.policy_versions == POLICIES
    assert combined.calibrated


def test_pooling_nothing_is_an_empty_curve_rather_than_an_error() -> None:
    assert pooled([]) == CalibrationReport()


def test_a_reliability_curve_holds_one_bin_per_label() -> None:
    with pytest.raises(ValueError, match="one bin per confidence label"):
        CalibrationReport(
            bins=[
                ReliabilityBin(confidence=Confidence.HIGH, count=1, correct=1),
                ReliabilityBin(confidence=Confidence.HIGH, count=2, correct=1),
            ]
        )


# ------------------------------------------------------- T-13-15 and T-13-16


def test_the_overall_score_is_refused_while_a_gate_is_failing() -> None:
    """T-13-15 (AC-13-12): the gate failure is reported instead of a number."""
    gates = [_gate("citation_resolution", passed=False), _gate("zero_fabrication", passed=True)]

    with pytest.raises(ValueError, match="citation_resolution"):
        gated_overall_score(0.9, 0.9, gates)


def test_the_overall_score_is_half_security_and_half_maintainability() -> None:
    """T-13-16 (AC-13-12): computed only once every gate passes."""
    gates = [_gate("citation_resolution", passed=True), _gate("zero_fabrication", passed=True)]
    assert gated_overall_score(0.8, 0.6, gates) == pytest.approx(0.7)


def test_the_overall_score_is_refused_on_miscalibrated_confidence() -> None:
    """AC-13-10 and AC-13-12 together: a score built on labels that do not mean
    what they say is a number nobody should quote."""
    gates = [_gate("citation_resolution", passed=True)]
    broken = calibrate(_findings(high=(10, 2), medium=(10, 9)), policy_versions=POLICIES)

    with pytest.raises(CalibrationError, match="not ordered"):
        gated_overall_score(0.9, 0.9, gates, broken)

    healthy = calibrate(_findings(high=(10, 9), medium=(10, 5)), policy_versions=POLICIES)
    assert gated_overall_score(0.9, 0.9, gates, healthy) == pytest.approx(0.9)


# ------------------------------------------------------------------- the file


def test_a_calibration_report_is_written_with_sorted_keys(tmp_path: Path) -> None:
    report = calibrate(_findings(high=(10, 9), medium=(10, 5)), policy_versions=POLICIES)
    path = write_calibration(report, tmp_path / "calibration.json")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["policy_versions"] == POLICIES
    assert payload["miscalibration"] is None
    assert [entry["confidence"] for entry in payload["bins"]] == [
        "high",
        "medium",
        "review_required",
    ]

"""Part 13 calibration-bridge tests: T-13-24.

Covers AC-13-10 for the half that was missing: the curve and the refusal were
built, and nothing fed them from a real run. What matters here is where the
truth comes from — the suite's ground truth through part 04's matching policy,
never the tool's own opinion of whether it was right, which would produce a
perfectly calibrated and entirely uninformative curve.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from caudit.cli.calibrate_cmd import run_calibrate, scored_findings
from caudit.config.loader import Config
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.calibration import ScoredFinding, calibrate
from caudit.eval.case import BenchmarkCase, GroundTruth
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import Confidence
from caudit.status import ExitCode
from tests.conftest import make_finding

POLICIES = {"matching": "1", "prompt": "2"}


def _provenance() -> list[Provenance]:
    return [
        Provenance(
            producer=Producer.CLANG_TIDY,
            tool_name="clang-tidy",
            tool_version="18.1.8",
            rule_id="bugprone.demo",
        )
    ]


def _case(tmp_path: Path, *truths: GroundTruth) -> BenchmarkCase:
    return BenchmarkCase(
        case_id="demo",
        root=tmp_path,
        ground_truth=list(truths),
        lines_of_code=40,
    )


# ------------------------------------------------------------------ T-13-24


def test_truth_comes_from_ground_truth_not_from_the_finding(tmp_path: Path) -> None:
    """T-13-24, AC-13-10: a confident finding on nothing is labelled false.

    Both findings below say ``high``. One sits on a labelled defect and one
    does not, and only the ground truth can tell them apart — which is the
    whole point of calibrating against a corpus rather than against the run.
    """
    case = _case(
        tmp_path, GroundTruth(path="src/main.c", line=5, cwe="CWE-787", family="out_of_bounds")
    )
    findings = (
        make_finding(_provenance(), path="src/main.c", start_line=5),
        make_finding(_provenance(), path="src/other.c", start_line=90, message="a second claim"),
    )

    scored = scored_findings([case], {"demo": findings})

    assert [entry.truth for entry in scored] == [True, False]
    assert {entry.confidence for entry in scored} == {Confidence.HIGH}


def test_the_reported_severity_is_the_one_the_report_showed(tmp_path: Path) -> None:
    """Not ``impact.severity``, which is the model's own grading.

    Calibrating a number the report never displayed would measure something
    no reader ever saw.
    """
    case = _case(
        tmp_path, GroundTruth(path="src/main.c", line=5, cwe="CWE-787", family="out_of_bounds")
    )
    finding = make_finding(_provenance(), path="src/main.c", start_line=5)

    scored = scored_findings([case], {"demo": (finding,)})

    assert scored[0].reported_severity is not None
    # The two are allowed to agree; what must not happen is the model's field
    # being read directly. Asserted through the ranking function that owns the
    # derivation, so a change to the table cannot silently desynchronise them.
    from caudit.finding_policy.ranking import severity_of

    assert scored[0].reported_severity is severity_of(finding)


def test_a_miscalibrated_set_fails_the_check_and_the_command() -> None:
    """AC-13-10: `high` less often true than `medium` is a failure, loudly.

    Built directly rather than through a suite, because a corpus where the
    labels are inverted is exactly what does not exist yet — and the check
    must work before it does.
    """
    scored = [
        ScoredFinding(finding_id=f"high-{index}", confidence=Confidence.HIGH, truth=index < 2)
        for index in range(6)
    ] + [
        ScoredFinding(finding_id=f"med-{index}", confidence=Confidence.MEDIUM, truth=True)
        for index in range(6)
    ]

    report = calibrate(scored, policy_versions=POLICIES)

    assert report.calibrated is False
    assert report.miscalibration is not None
    assert "high" in report.miscalibration


def test_a_bin_below_the_minimum_is_reported_and_not_judged(tmp_path: Path) -> None:
    """A check that fires on two findings is a check somebody switches off."""
    scored = [
        ScoredFinding(finding_id="high-0", confidence=Confidence.HIGH, truth=False),
        ScoredFinding(finding_id="med-0", confidence=Confidence.MEDIUM, truth=True),
    ]

    report = calibrate(scored, policy_versions=POLICIES, minimum_per_bin=5)

    assert report.calibrated is True
    assert report.accuracy_for(Confidence.HIGH) == 0.0


def test_the_command_records_a_curve_for_the_mini_suite(tmp_path: Path) -> None:
    """The bridge end to end, offline: score the suite, then calibrate it."""
    out = tmp_path / "calibration"
    log = StringIO()

    code = run_calibrate(
        config=Config(),
        suite="mini",
        out_dir=out,
        console=Console(file=log, width=200),
    )

    assert code is ExitCode.OK
    written = out / "calibration-mini.json"
    assert written.is_file()
    # The mini suite is far too small to judge, and the run says so rather
    # than reporting a curve nobody should read.
    assert "nothing here was judged" in log.getvalue()


def test_every_confirmed_finding_in_the_suite_is_labelled(tmp_path: Path) -> None:
    """No finding is quietly left out of the curve it belongs in."""
    from caudit.application.evaluation import default_source, run_suite

    suite = MiniSuite()
    result = run_suite(suite, source=default_source())
    scored = scored_findings(list(suite.cases()), dict(result.findings_by_case))

    assert len(scored) == sum(len(items) for items in result.findings_by_case.values())
    assert all(entry.finding_id for entry in scored)


def test_a_review_required_finding_lands_in_its_own_bin() -> None:
    """The three labels stay three bins; nothing merges them."""
    scored = [
        ScoredFinding(
            finding_id="review-0",
            confidence=Confidence.REVIEW_REQUIRED,
            truth=False,
        ),
        ScoredFinding(finding_id="high-0", confidence=Confidence.HIGH, truth=True),
    ]

    report = calibrate(scored, policy_versions=POLICIES)

    assert {entry.confidence for entry in report.bins} == {
        Confidence.HIGH,
        Confidence.MEDIUM,
        Confidence.REVIEW_REQUIRED,
    }
    assert report.accuracy_for(Confidence.REVIEW_REQUIRED) == 0.0


def test_the_curve_records_the_policy_versions_it_was_built_under() -> None:
    """Nothing is pooled across policy versions, so a curve must name its own."""
    report = calibrate(
        [ScoredFinding(finding_id="a", confidence=Confidence.HIGH, truth=True)],
        policy_versions=POLICIES,
    )

    assert report.policy_versions == dict(sorted(POLICIES.items()))

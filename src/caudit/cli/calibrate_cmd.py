"""``caudit calibrate`` — check that a confidence label means what it says.

A finding marked ``high`` should be true more often than one marked
``medium``. If it is not, the labels are decoration, and every number computed
from them is worth less than it looks. Part 13 built the curve and the
refusal; this is the bridge that feeds them from a real run.

The truth comes from a benchmark suite's ground truth through part 04's
matching policy — the same policy that scores the run — and never from the
tool's own judgement. A curve built from the tool's confidence and the tool's
opinion of whether it was right would be perfectly calibrated and entirely
uninformative.

One consequence worth stating plainly: a suite has to be big enough. The check
judges only bins with at least ``minimum_per_bin`` entries, so on a small
corpus it will usually report that nothing could be judged. That is the
correct answer, and it is why this command prints the bin sizes next to the
curve rather than only the verdict.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from caudit.application.evaluation import EvalResult
from caudit.config.loader import Config
from caudit.eval.calibration import (
    CalibrationReport,
    ScoredFinding,
    calibrate,
    severity_agreement,
    write_calibration,
)
from caudit.eval.case import BenchmarkCase
from caudit.eval.matching import MatchingPolicy, default_policy
from caudit.finding_policy.ranking import severity_of
from caudit.model.finding import Finding
from caudit.status import ExitCode

__all__ = ["run_calibrate", "scored_findings"]


def scored_findings(
    cases: Sequence[BenchmarkCase],
    findings_by_case: dict[str, tuple[Finding, ...]],
    *,
    policy: MatchingPolicy | None = None,
) -> list[ScoredFinding]:
    """Label every finding true or false against the suite's ground truth.

    A finding is true when the matching policy credits it against a
    ``vulnerable`` truth entry — exactly the rule that decides a true positive
    in the metrics, so the calibration cannot disagree with the score it sits
    beside.
    """
    matching = policy or default_policy()
    scored: list[ScoredFinding] = []

    for case in sorted(cases, key=lambda item: item.case_id):
        findings = list(findings_by_case.get(case.case_id, ()))
        truths = list(case.ground_truth)
        matched = matching.match_all(truths, findings)
        true_indices = {finding_index for _truth_index, finding_index in matched.pairs}

        for index, finding in enumerate(findings):
            scored.append(
                ScoredFinding(
                    finding_id=finding.finding_id,
                    confidence=finding.confidence,
                    truth=index in true_indices,
                    # The severity the *report* showed, which part 12 derives
                    # from the CWE family capped by the impact kind.
                    # ``impact.severity`` is the model's own grading, and
                    # calibrating that would measure a number the report never
                    # displayed.
                    reported_severity=severity_of(finding),
                )
            )
    return scored


def run_calibrate(
    *,
    config: Config,
    suite: str,
    out_dir: Path,
    case_ids: Sequence[str] = (),
    console: Console | None = None,
    minimum_per_bin: int = 5,
    result: EvalResult | None = None,
) -> ExitCode:
    """Score a suite, then calibrate its confidence labels against ground truth.

    ``result`` is injectable so a test can calibrate a run it constructed. Left
    ``None``, the suite is scored here through the same runner ``caudit eval``
    uses.
    """
    from caudit.application.evaluation import default_source, run_suite
    from caudit.cli.eval_cmd import resolve_suite

    out = console or Console(soft_wrap=True, highlight=False)
    benchmark = resolve_suite(suite)
    wanted = set(case_ids)
    cases = [case for case in benchmark.cases() if not wanted or case.case_id in wanted]

    if result is None:
        result = run_suite(
            benchmark,
            source=default_source(),
            case_ids=tuple(case_ids),
            max_file_bytes=config.token_budget.max_file_bytes,
        )

    scored = scored_findings(cases, dict(result.findings_by_case))
    report = calibrate(
        scored,
        policy_versions={
            key: str(value) for key, value in config.policy_versions.model_dump().items()
        },
        minimum_per_bin=minimum_per_bin,
    )
    report = report.model_copy(update={"severity": severity_agreement(scored)})

    render_calibration(report, out, judged_at=minimum_per_bin)
    path = write_calibration(report, out_dir / f"calibration-{benchmark.name}.json")
    out.print(f"\ncalibration: {path}")

    if not report.calibrated:
        out.print(
            "\nThe confidence labels are not ordered as they claim. No overall score is "
            "reported while that is true: a number built on labels that do not mean what "
            "they say is one nobody should quote."
        )
        return ExitCode.FINDINGS
    return ExitCode.OK


def render_calibration(report: CalibrationReport, out: Console, *, judged_at: int) -> None:
    """The curve, with bin sizes beside it and the unjudged bins named."""
    table = Table(title="reliability curve")
    table.add_column("confidence")
    table.add_column("true", justify="right")
    table.add_column("of", justify="right")
    table.add_column("accuracy", justify="right")
    table.add_column("judged")

    for entry in report.bins:
        table.add_row(
            str(entry.confidence),
            str(entry.correct),
            str(entry.count),
            f"{entry.accuracy:.3f}",
            "yes" if entry.count >= judged_at else f"no — fewer than {judged_at}",
        )
    out.print(table)

    if report.severity is not None:
        out.print(f"\nseverity: {report.severity.describe()}")
    if all(entry.count < judged_at for entry in report.bins):
        out.print(
            f"\nNo bin reached {judged_at} findings, so nothing here was judged. A check "
            "that fired on two findings would be a check somebody switches off."
        )

"""Part 12's comparison: T-12-13 and T-12-14 (AC-12-9).

The deltas are arithmetic and the refusals are the design. A comparison drawn
across two matching policies, two prompt versions, two check profiles, or two
case sets looks exactly like a result and is not one, so most of what is
checked here is that the refusal fires and names both values.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.cli.compare import run_compare, write_comparison
from caudit.errors import UsageError
from caudit.eval.compare import (
    ComparisonError,
    CostSummary,
    RunReport,
    compare_runs,
    load_run_report,
)
from caudit.eval.gates import GateResult
from caudit.eval.metrics import FamilyMetrics, Metrics
from caudit.model.cwe import WeaknessFamily
from caudit.status import ExitCode

_POLICIES = {"matching": "1", "prompt": "2", "retrieval": "1", "profile": "security"}
_SCOPE = ["oob-write-stack-copy", "uaf-double-free"]


def _metrics(
    *,
    macro_f2: float = 0.5,
    confirmed: int = 4,
    review: int = 2,
    families: dict[WeaknessFamily, tuple[int, int, int]] | None = None,
    evidence_validity: float = 1.0,
    citations: float = 1.0,
    fp_per_kloc: float = 2.0,
    policy_version: str = "1",
) -> Metrics:
    per_family = {
        family: FamilyMetrics.build(family, *counts)
        for family, counts in (families or {WeaknessFamily.OUT_OF_BOUNDS: (2, 1, 1)}).items()
    }
    return Metrics(
        suite="mini",
        policy_version=policy_version,
        per_family=per_family,
        macro_f2=macro_f2,
        fp_per_kloc=fp_per_kloc,
        evidence_validity_rate=evidence_validity,
        citation_resolution_rate=citations,
        confirmed_count=confirmed,
        review_required_count=review,
        lines_of_code=1000,
        case_count=2,
    )


def _report(
    metrics: Metrics | None = None,
    *,
    policies: dict[str, str] | None = None,
    scope: list[str] | None = None,
    cost: CostSummary | None = None,
    gates: list[GateResult] | None = None,
    adjudicated: bool = False,
) -> RunReport:
    return RunReport(
        metrics=metrics or _metrics(),
        gates=gates if gates is not None else [_gate("citation_resolution", passed=True)],
        policy_versions=dict(policies if policies is not None else _POLICIES),
        scope=list(scope if scope is not None else _SCOPE),
        cost=cost or CostSummary(),
        adjudicated=adjudicated,
    )


def _gate(name: str, *, passed: bool) -> GateResult:
    return GateResult(name=name, passed=passed, observed=1.0, threshold=0.95, detail="")


# ------------------------------------------------------------------- T-12-13


def test_the_deltas_are_adjudicated_minus_baseline() -> None:
    """T-12-13 (AC-12-9): per-family and macro deltas, plus the cost summary."""
    baseline = _report(
        _metrics(
            macro_f2=0.60, confirmed=4, review=2, families={WeaknessFamily.OUT_OF_BOUNDS: (2, 2, 2)}
        )
    )
    adjudicated = _report(
        _metrics(
            macro_f2=0.75, confirmed=6, review=5, families={WeaknessFamily.OUT_OF_BOUNDS: (3, 1, 1)}
        ),
        cost=CostSummary(
            calls=24, input_tokens=90_000, output_tokens=7_000, usd=0.42, wall_seconds=61.0
        ),
        adjudicated=True,
    )

    report = compare_runs(baseline, adjudicated)

    assert report.delta.macro_f2 == pytest.approx(0.15)
    assert report.delta.confirmed_count == 2
    assert report.delta.review_required_count == 3

    family = report.delta.per_family[WeaknessFamily.OUT_OF_BOUNDS]
    assert family.true_positives == 1
    assert family.false_positives == -1
    assert family.false_negatives == -1
    assert family.recall > 0.0
    assert family.precision > 0.0

    assert report.cost.calls == 24
    assert report.cost.usd == pytest.approx(0.42)
    assert report.cost.total_tokens == 97_000
    assert report.cost.wall_seconds == pytest.approx(61.0)
    assert report.valid


def test_the_two_counts_are_differenced_apart_and_never_summed() -> None:
    """AC-12-9: no field anywhere adds the two counts, delta included."""
    from caudit.eval.compare import ComparisonReport, MetricsDelta

    for model in (MetricsDelta, ComparisonReport):
        names = set(model.model_fields) | {
            name for name in dir(model) if isinstance(getattr(model, name, None), property)
        }
        assert not any("total" in name for name in names), names


def test_a_family_present_on_one_side_only_still_appears_in_the_delta() -> None:
    """A family the model found and the baseline did not is the result."""
    baseline = _report(_metrics(families={WeaknessFamily.OUT_OF_BOUNDS: (1, 0, 1)}))
    adjudicated = _report(
        _metrics(
            families={
                WeaknessFamily.OUT_OF_BOUNDS: (1, 0, 1),
                WeaknessFamily.MEMORY_LIFETIME: (2, 0, 0),
            }
        )
    )
    report = compare_runs(baseline, adjudicated)

    assert WeaknessFamily.MEMORY_LIFETIME in report.delta.per_family
    assert report.delta.per_family[WeaknessFamily.MEMORY_LIFETIME].true_positives == 2


def test_a_failing_gate_makes_the_comparison_invalid_rather_than_absent() -> None:
    """AC-12-9: the numbers are shown and then flagged, never quietly reported."""
    baseline = _report()
    adjudicated = _report(gates=[_gate("zero_fabrications", passed=False)])

    report = compare_runs(baseline, adjudicated)
    assert report.failing_gates == ["zero_fabrications"]
    assert not report.valid
    assert "NOT VALID" in report.headline()


def test_the_cost_delta_never_goes_below_zero() -> None:
    """A cheaper adjudicated run reports zero extra cost, not a negative one."""
    baseline = _report(cost=CostSummary(calls=10, usd=1.0, wall_seconds=100.0))
    adjudicated = _report(cost=CostSummary(calls=2, usd=0.2, wall_seconds=10.0))

    report = compare_runs(baseline, adjudicated)
    assert report.cost.calls == 0
    assert report.cost.usd == 0.0
    assert report.cost.wall_seconds == 0.0


# ------------------------------------------------------------------- T-12-14


@pytest.mark.parametrize("policy", ["profile", "matching"])
def test_compare_refuses_two_runs_under_different_policies(policy: str) -> None:
    """T-12-14 (AC-12-9): the refusal names both versions."""
    baseline = _report()
    altered = dict(_POLICIES)
    altered[policy] = "99"
    adjudicated = _report(policies=altered)

    with pytest.raises(ComparisonError) as caught:
        compare_runs(baseline, adjudicated)

    message = str(caught.value)
    assert policy in message
    assert _POLICIES[policy] in message and "99" in message
    assert "not comparable" in message


@pytest.mark.parametrize("policy", ["prompt", "retrieval"])
def test_two_adjudicated_runs_must_agree_on_the_prompt_policy(policy: str) -> None:
    """T-12-14 (AC-12-9): checked when both sides actually used one."""
    baseline = _report(adjudicated=True)
    altered = dict(_POLICIES)
    altered[policy] = "99"

    with pytest.raises(ComparisonError, match=policy):
        compare_runs(baseline, _report(policies=altered, adjudicated=True))


def test_a_baseline_with_no_prompt_version_is_still_comparable() -> None:
    """The Milestone 2 comparison itself: no prompt on one side, by definition.

    An analyzer-only baseline never assembled a prompt. Holding it to the
    adjudicated run's prompt version would refuse exactly the comparison the
    milestone is defined by, so the check applies only when both sides used one
    — and the asymmetry is stated as a caveat rather than assumed away.
    """
    baseline = _report(policies={"matching": "1", "profile": "security"}, adjudicated=False)
    adjudicated = _report(adjudicated=True)

    report = compare_runs(baseline, adjudicated)
    assert report.valid
    assert not any("prompt" in caveat for caveat in report.caveats)


def test_compare_refuses_a_run_whose_own_matching_version_disagrees() -> None:
    """The authoritative matching version is the one that scored the run.

    A report can record ``policy_versions.matching`` and be scored under a
    different one. Preferring either would let an incomparable pair through, so
    both are checked and a disagreement is a refusal.
    """
    baseline = _report()
    adjudicated = _report(_metrics(policy_version="2"))

    with pytest.raises(ComparisonError, match="not comparable"):
        compare_runs(baseline, adjudicated)


def test_compare_refuses_two_runs_over_different_cases() -> None:
    """AC-12-9: different scan plans are not two measurements of one change."""
    baseline = _report(scope=["oob-write-stack-copy"])
    adjudicated = _report(scope=["oob-write-stack-copy", "uaf-double-free"])

    with pytest.raises(ComparisonError) as caught:
        compare_runs(baseline, adjudicated)
    assert "uaf-double-free" in str(caught.value)


def test_compare_refuses_two_different_suites() -> None:
    baseline = _report()
    other = _report()
    adjudicated = other.model_copy(
        update={"metrics": other.metrics.model_copy(update={"suite": "castle"})}
    )

    with pytest.raises(ComparisonError, match="different suites"):
        compare_runs(baseline, adjudicated)


# ----------------------------------------------------------------- the file


def test_a_report_written_before_this_module_existed_still_loads(tmp_path: Path) -> None:
    """The baseline being compared against was recorded by an earlier revision."""
    legacy = tmp_path / "metrics-old.json"
    legacy.write_text(
        json.dumps(
            {
                "metrics": _metrics().model_dump(mode="json"),
                "gates": [],
                "tool_versions": {"clang-tidy": "18.1.8"},
            }
        ),
        encoding="utf-8",
    )
    loaded = load_run_report(legacy)

    assert loaded.metrics.suite == "mini"
    assert loaded.policy_versions == {}
    assert loaded.cost == CostSummary()

    # It compares, because refusing would reject the one baseline an
    # adjudicated run most needs to be measured against — and the unrecorded
    # case list becomes a stated caveat rather than a silent assumption.
    report = compare_runs(loaded, _report(adjudicated=True))
    assert report.valid
    assert any("which cases it scored" in caveat for caveat in report.caveats)

    # The matching policy still falls back to the version that actually scored
    # it, rather than comparing two blanks and passing.
    with pytest.raises(ComparisonError, match="matching"):
        compare_runs(loaded, _report(policies={**_POLICIES, "matching": "7"}))


def test_a_bare_metrics_object_loads_as_a_run_report(tmp_path: Path) -> None:
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(_metrics().model_dump(mode="json")), encoding="utf-8")
    assert load_run_report(path).metrics.macro_f2 == pytest.approx(0.5)


def test_the_comparison_can_be_recorded_and_read_back(tmp_path: Path) -> None:
    """AC-12-9: "with the comparison recorded" is a file, not a console dump."""
    report = compare_runs(_report(), _report(_metrics(macro_f2=0.8)))
    path = write_comparison(report, tmp_path / "comparison.json")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["delta"]["macro_f2"] == pytest.approx(0.3)
    assert payload["cost"]["calls"] == 0
    assert payload["policy_versions"]["prompt"] == "2"
    assert "total" not in json.dumps(payload)


# ------------------------------------------------------------------- the CLI


def _write(path: Path, report: RunReport) -> Path:
    path.write_text(json.dumps(json.loads(report.model_dump_json())), encoding="utf-8")
    return path


def test_run_compare_writes_the_comparison_and_exits_zero(tmp_path: Path) -> None:
    baseline = _write(tmp_path / "baseline.json", _report())
    adjudicated = _write(tmp_path / "adjudicated.json", _report(_metrics(macro_f2=0.7)))

    code = run_compare(baseline, adjudicated, out=tmp_path / "comparison.json")

    assert code is ExitCode.OK
    assert (tmp_path / "comparison.json").is_file()


def test_run_compare_exits_non_zero_when_a_gate_is_failing(tmp_path: Path) -> None:
    baseline = _write(tmp_path / "baseline.json", _report())
    adjudicated = _write(
        tmp_path / "adjudicated.json", _report(gates=[_gate("zero_fabrications", passed=False)])
    )

    assert run_compare(baseline, adjudicated) is ExitCode.FINDINGS


def test_run_compare_reports_a_missing_file_as_a_usage_error(tmp_path: Path) -> None:
    present = _write(tmp_path / "baseline.json", _report())
    with pytest.raises(UsageError, match="not found"):
        run_compare(present, tmp_path / "nope.json")


def test_run_compare_reports_an_unreadable_file_as_a_usage_error(tmp_path: Path) -> None:
    present = _write(tmp_path / "baseline.json", _report())
    junk = tmp_path / "junk.json"
    junk.write_text("this is not json", encoding="utf-8")

    with pytest.raises(UsageError, match="not a metrics report"):
        run_compare(present, junk)

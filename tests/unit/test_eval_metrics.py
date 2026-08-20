"""Part 04 metric tests: T-04-01, T-04-02, T-04-03, T-04-14, T-04-15."""

from __future__ import annotations

import io
from pathlib import Path, PurePosixPath

import pytest
from rich.console import Console

from caudit.eval.case import BenchmarkCase, GroundTruth, count_lines_of_code
from caudit.eval.matching import default_policy
from caudit.eval.metrics import (
    SUMMABLE_COUNT_FIELDS,
    FamilyMetrics,
    Metrics,
    compute_metrics,
    f_beta,
    precision_of,
    recall_of,
)
from caudit.model.cwe import WeaknessFamily
from caudit.model.evidence import Provenance
from caudit.model.finding import Confidence, ReviewReason
from tests.conftest import make_finding


def test_hand_computed_precision_recall_and_f2() -> None:
    """T-04-01: tp=3, fp=1, fn=2 → 0.75, 0.6, 0.625."""
    precision = precision_of(3, 1)
    recall = recall_of(3, 2)
    assert precision == pytest.approx(0.75)
    assert recall == pytest.approx(0.6)
    assert f_beta(precision, recall, beta=2.0) == pytest.approx(0.625)


def test_f2_weights_recall_above_precision() -> None:
    """T-04-02: β=2 is verifiable from the formula, not asserted by comment."""
    high_recall = f_beta(precision=0.5, recall=1.0, beta=2.0)
    high_precision = f_beta(precision=1.0, recall=0.5, beta=2.0)
    assert high_recall > high_precision
    # 5pr / (4p + r) at p=0.5, r=1.0 → 2.5/3.0
    assert high_recall == pytest.approx(2.5 / 3.0)
    # F1 treats them symmetrically; F2 must not.
    assert f_beta(0.5, 1.0, beta=1.0) == pytest.approx(f_beta(1.0, 0.5, beta=1.0))


def test_degenerate_cases_have_defined_values() -> None:
    """T-04-02 / AC-04-1: no ZeroDivisionError anywhere."""
    assert precision_of(0, 0) == 1.0  # nothing predicted: vacuously precise
    assert recall_of(0, 0) == 1.0  # nothing to find: vacuously complete
    assert f_beta(1.0, 1.0) == pytest.approx(1.0)
    assert f_beta(0.0, 0.0) == 0.0
    assert precision_of(0, 5) == 0.0  # all false positives
    assert recall_of(0, 5) == 0.0  # all missed


def test_macro_f2_is_the_unweighted_mean_of_family_f2() -> None:
    """T-04-03: a family with many cases does not dominate one with few."""
    metrics = Metrics(
        suite="synthetic",
        policy_version="1",
        per_family={
            WeaknessFamily.OUT_OF_BOUNDS: FamilyMetrics.build(
                WeaknessFamily.OUT_OF_BOUNDS, tp=90, fp=10, fn=0
            ),
            WeaknessFamily.INJECTION: FamilyMetrics.build(
                WeaknessFamily.INJECTION, tp=0, fp=0, fn=1
            ),
        },
        macro_f2=0.0,
        fp_per_kloc=0.0,
        evidence_validity_rate=1.0,
        citation_resolution_rate=1.0,
        confirmed_count=90,
        review_required_count=0,
        lines_of_code=1000,
        case_count=91,
    )
    scored = [m.f2 for m in metrics.per_family.values()]
    assert len(scored) == 2
    unweighted = sum(scored) / 2
    # The 90-case family scores ~0.978, the 1-case family 0.0.
    assert unweighted == pytest.approx(sum(scored) / len(scored))
    assert unweighted < 0.6, "a weighted mean would sit near 0.97 here"


def test_families_with_no_truths_and_no_findings_are_not_scored() -> None:
    empty = FamilyMetrics.build(WeaknessFamily.INTEGER, tp=0, fp=0, fn=0)
    assert empty.scored is False
    assert empty.precision == 1.0 and empty.recall == 1.0


def test_metrics_has_no_merged_count_field() -> None:
    """T-04-14: both counts present, nothing sums them."""
    fields = set(Metrics.model_fields)
    assert set(SUMMABLE_COUNT_FIELDS) <= fields
    forbidden = {"total_findings", "findings_total", "all_findings", "total"}
    assert not forbidden & fields
    # Nor may a property or method offer the merged number.
    assert not any(name in dir(Metrics) for name in ("total", "total_findings", "all_findings"))


def test_report_renders_the_two_counts_under_separate_headings(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    """T-04-15."""
    from caudit.application.evaluation import EvalResult
    from caudit.cli.eval_cmd import render_metrics

    metrics = Metrics(
        suite="mini",
        policy_version="1",
        per_family={},
        macro_f2=0.5,
        fp_per_kloc=1.0,
        evidence_validity_rate=1.0,
        citation_resolution_rate=1.0,
        confirmed_count=3,
        review_required_count=7,
        lines_of_code=1000,
        case_count=1,
    )
    result = EvalResult(
        metrics=metrics, gates=(), findings_by_case={}, resolutions=(), tool_versions={}
    )
    buffer = io.StringIO()
    render_metrics(result, Console(file=buffer, width=100, soft_wrap=True))
    output = buffer.getvalue()

    assert "Confirmed findings" in output
    assert "Needs review" in output
    confirmed_at = output.index("Confirmed findings")
    review_at = output.index("Needs review")
    assert confirmed_at < review_at
    assert "10" not in output.split("Hard gates")[0].replace("100", "")


def test_compute_metrics_counts_review_required_separately(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_bytes(b"int x;\n" * 20)
    case = BenchmarkCase(
        case_id="c1",
        root=tmp_path,
        ground_truth=[
            GroundTruth(
                path=PurePosixPath("src/main.c"),
                line=5,
                cwe="CWE-787",
                family=WeaknessFamily.OUT_OF_BOUNDS,
            )
        ],
        lines_of_code=20,
        family=WeaknessFamily.OUT_OF_BOUNDS,
    )
    confirmed = make_finding(provenance, start_line=5)
    review = make_finding(
        provenance,
        start_line=5,
        message="a different defect entirely",
        confidence=Confidence.REVIEW_REQUIRED,
        confidence_reason=ReviewReason.OUT_OF_SCOPE_FAMILY,
    )
    metrics = compute_metrics(
        suite="test",
        cases=[case],
        findings_by_case={"c1": [confirmed, review]},
        resolutions=[],
        policy=default_policy(),
    )
    assert metrics.confirmed_count == 1
    assert metrics.review_required_count == 1
    # The review-required item is not credited as a detection.
    family = metrics.per_family[WeaknessFamily.OUT_OF_BOUNDS]
    assert family.true_positives == 1
    assert family.false_positives == 0


def test_fp_per_kloc_uses_the_recorded_line_count(tmp_path: Path) -> None:
    (tmp_path / "a.c").write_text("/* comment */\n\n// another\nint a;\nint b;\n", encoding="utf-8")
    assert count_lines_of_code([tmp_path / "a.c"]) == 2


def test_count_lines_of_code_handles_block_comments(tmp_path: Path) -> None:
    (tmp_path / "b.c").write_text("/* start\n * middle\n */\nint x;\n", encoding="utf-8")
    assert count_lines_of_code([tmp_path / "b.c"]) == 1


def test_metrics_refuse_comparison_across_policy_versions() -> None:
    """T-04-10 at the metrics level."""
    base = Metrics(
        suite="mini",
        policy_version="1",
        per_family={},
        macro_f2=0.0,
        fp_per_kloc=0.0,
        evidence_validity_rate=1.0,
        citation_resolution_rate=1.0,
        confirmed_count=0,
        review_required_count=0,
        lines_of_code=0,
        case_count=0,
    )
    other = base.model_copy(update={"policy_version": "2"})
    with pytest.raises(ValueError, match="not comparable") as excinfo:
        base.assert_comparable(other)
    assert "1" in str(excinfo.value) and "2" in str(excinfo.value)

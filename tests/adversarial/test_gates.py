"""Part 04 hard-gate tests: T-04-11, T-04-12, T-04-13.

Each gate must be demonstrably able to fail. A gate that has never been seen
to fail is a comment, not a check.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from caudit.application.evaluation import run_suite
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.gates import (
    CITATION_RESOLUTION_THRESHOLD,
    FabricationKind,
    GateResult,
    evaluate_gates,
    fabrication_signals,
    gates_passed,
    overall_score,
)
from caudit.eval.metrics import Metrics
from caudit.evidence.resolver import Citation, Resolution, ResolutionStatus
from caudit.model.evidence import Producer, Provenance
from caudit.status import ExitCode
from tests.conftest import make_finding


def _metrics(**overrides: object) -> Metrics:
    base: dict[str, object] = {
        "suite": "mini",
        "policy_version": "1",
        "per_family": {},
        "macro_f2": 0.8,
        "fp_per_kloc": 0.0,
        "evidence_validity_rate": 1.0,
        "citation_resolution_rate": 1.0,
        "confirmed_count": 1,
        "review_required_count": 0,
        "lines_of_code": 1000,
        "case_count": 1,
    }
    base.update(overrides)
    return Metrics.model_validate(base)


def _resolutions(ok: int, failed: int) -> list[Resolution]:
    good = [
        Resolution(
            status=ResolutionStatus.OK,
            citation=Citation(path="src/main.c", start_line=i + 1, end_line=i + 1),
            detail="resolved",
        )
        for i in range(ok)
    ]
    bad = [
        Resolution(
            status=ResolutionStatus.MISSING_FILE,
            citation=Citation(path="src/ghost.c", start_line=1, end_line=1),
            detail="src/ghost.c does not exist at revision abc123",
        )
        for _ in range(failed)
    ]
    return good + bad


def test_fabricated_file_fails_the_zero_fabrication_gate(
    provenance: list[Provenance],
) -> None:
    """T-04-11: one invented file in an otherwise clean run."""
    resolutions = _resolutions(ok=9, failed=1)
    findings = [make_finding(provenance)]
    gates = evaluate_gates(
        _metrics(citation_resolution_rate=0.9),
        findings,
        resolutions,
        is_baseline_run=True,
    )
    fabrication = next(g for g in gates if g.name == "zero_fabrication")
    assert not fabrication.passed
    assert fabrication.observed == 1
    assert "src/ghost.c" in fabrication.detail
    assert not gates_passed(gates)


def test_fabricated_finding_makes_the_whole_run_exit_non_zero(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    """T-04-11 end to end: an injected ghost citation fails the run."""
    suite = MiniSuite()
    ghost = make_finding(
        provenance,
        path="src/ghost.c",
        start_line=1,
        message="claims a defect in a file that does not exist",
    )
    clean = run_suite(suite, case_ids=["oob-write-stack-copy"])
    assert clean.passed, "the mini case must be clean before it is poisoned"

    poisoned = run_suite(
        suite,
        case_ids=["oob-write-stack-copy"],
        extra_findings={"oob-write-stack-copy": [ghost]},
    )
    assert not poisoned.passed
    fabrication = next(g for g in poisoned.gates if g.name == "zero_fabrication")
    assert "ghost.c" in fabrication.detail

    from caudit.cli.eval_cmd import run_eval
    from caudit.config.loader import Config

    code = run_eval(
        config=Config(),
        suite="mini",
        baseline=True,
        out_dir=tmp_path,
        case_ids=("integer-truncation-alloc",),
    )
    assert code is ExitCode.OK  # a clean run still exits zero


def test_fabricated_analyzer_name_is_caught(provenance: list[Provenance]) -> None:
    """ "Zero fabricated analyzer names" is part of the same gate."""
    invented = [
        Provenance(
            producer=Producer.LLM,
            tool_name="superscan-pro",
            tool_version="9.0",
            rule_id="SSP-001",
        )
    ]
    finding = make_finding(invented)
    signals = fabrication_signals([finding], [])
    assert [s.kind for s in signals] == [FabricationKind.ANALYZER]
    assert "superscan-pro" in signals[0].subject


def test_citation_gate_fails_just_below_the_threshold(
    provenance: list[Provenance],
) -> None:
    """T-04-12: 94% resolution fails."""
    resolutions = _resolutions(ok=94, failed=6)
    gates = evaluate_gates(
        _metrics(citation_resolution_rate=0.94),
        [make_finding(provenance)],
        resolutions,
        is_baseline_run=True,
    )
    gate = next(g for g in gates if g.name == "citation_resolution")
    assert not gate.passed
    assert gate.observed == pytest.approx(0.94)
    assert gate.threshold == CITATION_RESOLUTION_THRESHOLD


def test_citation_gate_passes_at_exactly_the_threshold(
    provenance: list[Provenance],
) -> None:
    """T-04-13: the boundary is inclusive, and that is documented."""
    resolutions = _resolutions(ok=95, failed=5)
    gates = evaluate_gates(
        _metrics(citation_resolution_rate=0.95),
        [make_finding(provenance)],
        resolutions,
        is_baseline_run=True,
    )
    gate = next(g for g in gates if g.name == "citation_resolution")
    assert gate.passed
    assert gate.observed == pytest.approx(CITATION_RESOLUTION_THRESHOLD)


def test_counts_separate_gate_reports_both_numbers() -> None:
    gates = evaluate_gates(
        _metrics(confirmed_count=4, review_required_count=11),
        [],
        [],
        is_baseline_run=True,
    )
    gate = next(g for g in gates if g.name == "counts_separate")
    assert gate.passed
    assert "confirmed=4" in gate.detail
    assert "review_required=11" in gate.detail
    assert "15" not in gate.detail


def test_baseline_floor_gate_fails_without_a_baseline_for_an_ai_run() -> None:
    """The spec: floors are established before an overall score is reported."""
    gates = evaluate_gates(_metrics(), [], [], baseline=None, is_baseline_run=False)
    gate = next(g for g in gates if g.name == "baseline_floor")
    assert not gate.passed
    assert "non-AI baseline" in gate.detail


def test_baseline_run_establishes_the_floor_rather_than_needing_one() -> None:
    gates = evaluate_gates(_metrics(), [], [], baseline=None, is_baseline_run=True)
    gate = next(g for g in gates if g.name == "baseline_floor")
    assert gate.passed
    assert "establishes the floor" in gate.detail


def test_baseline_floor_gate_fails_when_a_run_regresses_below_it() -> None:
    baseline = _metrics(macro_f2=0.80)
    gates = evaluate_gates(_metrics(macro_f2=0.55), [], [], baseline=baseline)
    gate = next(g for g in gates if g.name == "baseline_floor")
    assert not gate.passed
    assert gate.observed == pytest.approx(0.55)
    assert gate.threshold == pytest.approx(0.80)


def test_baseline_comparison_refuses_mismatched_policy_versions() -> None:
    baseline = _metrics(policy_version="2")
    with pytest.raises(ValueError, match="not comparable"):
        evaluate_gates(_metrics(), [], [], baseline=baseline)


def test_overall_score_is_refused_while_any_gate_fails() -> None:
    """A maintainability gain must not compensate for invented evidence."""
    failing = [
        GateResult(name="zero_fabrication", passed=False, observed=1, threshold=0),
        GateResult(name="citation_resolution", passed=True, observed=1.0, threshold=0.95),
    ]
    with pytest.raises(ValueError, match="zero_fabrication"):
        overall_score(0.2, 1.0, failing)

    passing = [GateResult(name="ok", passed=True, observed=1, threshold=1)]
    assert overall_score(0.4, 0.8, passing) == pytest.approx(0.6)


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (ResolutionStatus.MISSING_FILE, FabricationKind.FILE),
        (ResolutionStatus.UNKNOWN_EVIDENCE_ID, FabricationKind.EVIDENCE_ID),
        (ResolutionStatus.SYMBOL_NOT_FOUND, FabricationKind.SYMBOL),
        (ResolutionStatus.OUTSIDE_REPO_ROOT, FabricationKind.OUTSIDE_REPO),
        (ResolutionStatus.HASH_MISMATCH, FabricationKind.SNIPPET),
        (ResolutionStatus.LINE_OUT_OF_RANGE, FabricationKind.FILE),
    ],
)
def test_each_fabrication_shape_is_classified(
    status: ResolutionStatus, kind: FabricationKind
) -> None:
    resolution = Resolution(
        status=status,
        citation=Citation(path="src/x.c", start_line=1, end_line=1),
        detail="detail",
    )
    signals = fabrication_signals([], [resolution])
    assert [s.kind for s in signals] == [kind]


def test_excluded_and_too_large_are_not_fabrication() -> None:
    """A file we chose not to read was not invented by anyone."""
    for status in (ResolutionStatus.EXCLUDED_FILE, ResolutionStatus.FILE_TOO_LARGE):
        resolution = Resolution(
            status=status,
            citation=Citation(path=str(PurePosixPath("src/x.c")), start_line=1, end_line=1),
            detail="detail",
        )
        assert fabrication_signals([], [resolution]) == []

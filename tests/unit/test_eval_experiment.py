"""Immutable experiment manifests and paired-run refusals."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from caudit.config.loader import Config
from caudit.eval.case import TruthFrame
from caudit.eval.compare import ComparisonError, RunReport, compare_runs
from caudit.eval.experiment import (
    CacheMode,
    ExperimentCondition,
    ExperimentManifest,
    build_experiment_manifest,
)
from caudit.eval.metrics import Metrics


def _metrics(*, truth_frame: TruthFrame | None = None) -> Metrics:
    return Metrics(
        suite="mini",
        policy_version="1",
        truth_frame=truth_frame or TruthFrame(),
        per_family={},
        macro_f2=0.0,
        fp_per_kloc=0.0,
        evidence_validity_rate=1.0,
        citation_resolution_rate=1.0,
        confirmed_count=0,
        review_required_count=0,
        lines_of_code=0,
        case_count=1,
    )


def _manifest(condition: ExperimentCondition) -> ExperimentManifest:
    return build_experiment_manifest(
        config=Config(),
        condition=condition,
        candidate_set_hash="a" * 64,
        candidate_count=3,
        corpus_hash="b" * 64,
        corpus_revision="fixture-v1",
        analyzer_versions={"clang-tidy": "18.1.8"},
        policy_versions={"matching": "1", "profile": "security", "prompt": "2", "retrieval": "1"},
        truth_frame=TruthFrame(),
    )


def _reports() -> tuple[RunReport, RunReport]:
    return (
        RunReport(
            metrics=_metrics(),
            scope=["case"],
            experiment=_manifest(ExperimentCondition.ANALYZER_CONTROL),
        ),
        RunReport(
            metrics=_metrics(),
            scope=["case"],
            adjudicated=True,
            experiment=_manifest(ExperimentCondition.ADJUDICATED),
        ),
    )


def test_the_condition_is_the_only_manifest_difference_allowed() -> None:
    baseline, adjudicated = _reports()
    report = compare_runs(baseline, adjudicated)

    assert report.valid
    assert not any("immutable experiment manifest" in caveat for caveat in report.caveats)


def test_manifest_records_stable_model_effort_sdk_quota_and_jitter() -> None:
    manifest = _manifest(ExperimentCondition.ADJUDICATED)

    assert set(manifest.model_ids.values()) == {"gemini-3.5-flash-lite"}
    assert manifest.model_policy["triage"]["thinking_level"] == "minimal"
    assert manifest.model_policy["adjudication"]["thinking_level"] == "low"
    assert manifest.model_policy["escalation"]["thinking_level"] == "medium"
    assert manifest.sdk_versions["google-genai"] == "1.75.0"
    assert manifest.capability_profile_version == "1"
    assert manifest.quota_snapshot["source"] == "not_recorded"
    assert manifest.retry_policy.backoff_jitter_seconds == pytest.approx(0.25)


@pytest.mark.parametrize(
    ("field", "change"),
    [
        ("candidate_set_hash", lambda _manifest: "c" * 64),
        ("candidate_count", lambda manifest: manifest.candidate_count + 1),
        ("corpus_hash", lambda _manifest: "d" * 64),
        ("corpus_revision", lambda _manifest: "fixture-v2"),
        ("config_hash", lambda _manifest: "e" * 64),
        ("analyzer_versions", lambda _manifest: {"clang-tidy": "19"}),
        ("model_ids", lambda manifest: {**manifest.model_ids, "triage": "different"}),
        ("policy_versions", lambda manifest: {**manifest.policy_versions, "profile": "other"}),
        ("sdk_versions", lambda manifest: {**manifest.sdk_versions, "pydantic": "different"}),
        ("prompt_hashes", lambda manifest: {**manifest.prompt_hashes, "triage": "f" * 64}),
        ("schema_hashes", lambda manifest: {**manifest.schema_hashes, "triage": "f" * 64}),
        ("cache_mode", lambda _manifest: CacheMode.DISABLED),
        (
            "model_policy",
            lambda manifest: {
                **manifest.model_policy,
                "triage": {**manifest.model_policy["triage"], "thinking_level": "high"},
            },
        ),
        ("capability_profile_version", lambda _manifest: "different"),
        (
            "quota_snapshot",
            lambda manifest: {**manifest.quota_snapshot, "requests_per_day": 20},
        ),
        (
            "retry_policy",
            lambda manifest: manifest.retry_policy.model_copy(
                update={"max_transport_attempts": manifest.retry_policy.max_transport_attempts + 1}
            ),
        ),
        ("runtime", lambda manifest: {**manifest.runtime, "python": "different"}),
    ],
)
def test_compare_refuses_every_manifest_mismatch(
    field: str,
    change: Callable[[ExperimentManifest], object],
) -> None:
    baseline, adjudicated = _reports()
    assert adjudicated.experiment is not None
    altered = adjudicated.experiment.model_copy(update={field: change(adjudicated.experiment)})

    with pytest.raises(ComparisonError, match=f"experiment {field} differs"):
        compare_runs(baseline, adjudicated.model_copy(update={"experiment": altered}))


def test_a_report_refuses_an_internal_truth_frame_disagreement() -> None:
    manifest = _manifest(ExperimentCondition.ANALYZER_CONTROL).model_copy(
        update={"truth_frame": TruthFrame(single_cwe=True)}
    )
    with pytest.raises(ValidationError, match="truth frame disagrees"):
        RunReport(metrics=_metrics(), experiment=manifest)


def test_legacy_reports_are_readable_but_identity_is_an_explicit_caveat() -> None:
    baseline, adjudicated = _reports()
    report = compare_runs(
        baseline.model_copy(update={"experiment": None}),
        adjudicated,
    )

    assert any("immutable experiment manifest" in caveat for caveat in report.caveats)

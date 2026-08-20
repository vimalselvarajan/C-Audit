"""Part 02 manifest tests: T-02-18."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from caudit.model.manifest import CoverageReport, ModelRecord, RunManifest, ToolRecord

NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 8, 11, 12, 5, tzinfo=UTC)


def _coverage(**overrides: object) -> CoverageReport:
    base: dict[str, object] = {
        "translation_units_total": 3,
        "translation_units_parsed": 3,
        "translation_units_failed": 0,
        "lines_of_code": 120,
        "confirmed_count": 2,
        "review_required_count": 5,
    }
    base.update(overrides)
    return CoverageReport.model_validate(base)


def _manifest(**overrides: object) -> RunManifest:
    base: dict[str, object] = {
        "caudit_version": "0.1.0",
        "started_at": NOW,
        "finished_at": LATER,
        "repository_root": "/repo",
        "revision": "abc123",
        "tools": [ToolRecord(name="clang-tidy", version="18.1.8")],
        "config_hash": "0" * 64,
        "coverage": _coverage(),
    }
    base.update(overrides)
    return RunManifest.model_validate(base)


def test_manifest_round_trips() -> None:
    manifest = _manifest()
    assert RunManifest.model_validate(manifest.model_dump(mode="json")) == manifest


def test_missing_analyzer_version_is_rejected() -> None:
    """T-02-18: a run whose tool versions are unknown is not reproducible."""
    with pytest.raises(ValidationError):
        ToolRecord(name="clang-tidy", version="")
    with pytest.raises(ValidationError):
        ToolRecord.model_validate({"name": "clang-tidy"})


def test_manifest_requires_at_least_one_tool() -> None:
    with pytest.raises(ValidationError, match="tools"):
        _manifest(tools=[])


def test_revision_must_not_be_blank() -> None:
    with pytest.raises(ValidationError):
        _manifest(revision="")


def test_finished_before_started_is_rejected() -> None:
    with pytest.raises(ValidationError, match="precedes"):
        _manifest(started_at=LATER, finished_at=NOW)


def test_coverage_arithmetic_is_checked() -> None:
    with pytest.raises(ValidationError, match="exceeds total"):
        _coverage(translation_units_total=1, translation_units_parsed=1, translation_units_failed=1)


def test_coverage_has_no_merged_finding_count() -> None:
    """Confirmed and review-required live side by side and are never summed."""
    fields = set(CoverageReport.model_fields)
    assert {"confirmed_count", "review_required_count"} <= fields
    assert not {"total_findings", "findings_total", "all_findings"} & fields


def test_model_tiers_are_recorded_per_run() -> None:
    manifest = _manifest(
        models=[
            ModelRecord(
                tier="adjudication",
                model_id="gemini-flash-latest",
                calls=4,
                input_tokens=100,
                output_tokens=20,
            )
        ]
    )
    assert manifest.models[0].model_id == "gemini-flash-latest"

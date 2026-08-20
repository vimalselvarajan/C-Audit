"""Part 08 manifest tests: T-08-11, T-08-12, T-08-13, T-08-18 (AC-08-7, 8, 9).

The manifest is the file that makes a report auditable. Every test here is a
variation on one rule: it is complete, or the run fails. A null where a tool
version belongs would leave a report that looks reproducible and is not.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.intake.plan import UNKNOWN_REVISION, ScanPlan
from caudit.model.manifest import RunManifest
from caudit.report.manifest import (
    VOLATILE_FIELDS,
    ReportError,
    assemble_manifest,
    config_fingerprint,
    repo_display_name,
    reproducibility_diff,
)
from tests.conftest import (
    REPORT_FINISHED_AT,
    REPORT_STARTED_AT,
    demo_coverage,
    demo_manifest,
    demo_sections,
    write_demo_repo,
)

RAN = ("clang", "clang-static-analyzer", "clang-tidy", "libclang")
VERSIONS = {
    "clang": "18.1.8",
    "clang-static-analyzer": "18.1.8",
    "clang-tidy": "18.1.8",
    "libclang": "18.1.1",
}
POLICIES = {"prompt": "1", "retrieval": "1", "matching": "1", "profile": "1"}


def _plan(root: Path) -> ScanPlan:
    return ScanPlan(
        repo_root=root,
        revision="demo-revision",
        compile_commands_path=root / "compile_commands.json",
        units=[],
        coverage=demo_coverage(tus_in_database=3, tus_selected=0),
    )


def _assemble(root: Path, **overrides: object) -> RunManifest:
    sections = demo_sections(root)
    arguments: dict[str, object] = {
        "plan": _plan(root),
        "sections": sections,
        "config": Config(),
        "caudit_version": "0.1.0",
        "started_at": REPORT_STARTED_AT,
        "finished_at": REPORT_FINISHED_AT,
        "analyzer_versions": dict(VERSIONS),
        "analyzers_that_ran": list(RAN),
        "policy_versions": dict(POLICIES),
    }
    arguments.update(overrides)
    return assemble_manifest(**arguments)  # type: ignore[arg-type]


# ---------------------------------------------------------------- T-08-11


def test_a_missing_analyzer_version_fails_the_run_by_name(tmp_path: Path) -> None:
    """T-08-11, AC-08-8: the message names the analyzer, not just the field."""
    root = write_demo_repo(tmp_path / "demo")
    versions = {name: value for name, value in VERSIONS.items() if name != "clang-tidy"}

    with pytest.raises(ReportError) as caught:
        _assemble(root, analyzer_versions=versions)
    assert "clang-tidy" in caught.value.message
    assert "cannot be reproduced" in caught.value.message


def test_a_tool_that_would_not_name_its_version_is_the_same_failure(tmp_path: Path) -> None:
    """ "unknown" is what part 07 records for a tool that ran and said nothing."""
    root = write_demo_repo(tmp_path / "demo")
    with pytest.raises(ReportError, match="clang-static-analyzer"):
        _assemble(root, analyzer_versions={**VERSIONS, "clang-static-analyzer": "unknown"})


def test_a_run_in_which_no_tool_ran_has_no_manifest(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    with pytest.raises(ReportError, match="no tool ran"):
        _assemble(root, analyzers_that_ran=[])


def test_a_blank_policy_version_fails_the_run(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    with pytest.raises(ReportError, match="retrieval"):
        _assemble(root, policy_versions={**POLICIES, "retrieval": " "})


def test_a_blank_revision_fails_the_run(tmp_path: Path) -> None:
    """``unknown`` is a recorded answer; blank means nobody looked."""
    root = write_demo_repo(tmp_path / "demo")
    plan = _plan(root).model_copy(update={"revision": "   "})
    with pytest.raises(ReportError, match="revision"):
        _assemble(root, plan=plan)

    unknown = _assemble(root, plan=_plan(root).model_copy(update={"revision": UNKNOWN_REVISION}))
    assert unknown.revision == UNKNOWN_REVISION


# ---------------------------------------------------------------- T-08-12


def test_every_manifest_key_is_present_and_only_models_is_empty(tmp_path: Path) -> None:
    """T-08-12: complete at M1, with ``models`` empty because none was consulted."""
    root = write_demo_repo(tmp_path / "demo")
    manifest = _assemble(root)
    payload = manifest.model_dump(mode="json")

    assert set(payload) == set(RunManifest.model_fields)
    empty = {key for key, value in payload.items() if value in (None, "", [], {})}
    # ``models`` is empty because no tier was consulted; ``stages`` because this
    # helper calls ``assemble_manifest`` directly rather than through part 12's
    # pipeline, which is what records them. Both emptinesses are claims: no
    # model answered, and nobody timed anything.
    assert empty == {"models", "stages"}, empty
    assert payload["partial"] is False
    assert payload["total_cost_usd"] == 0.0

    assert manifest.config_hash == config_fingerprint(Config())
    assert [tool.name for tool in manifest.tools] == sorted(RAN)
    assert manifest.policy_versions == POLICIES
    assert manifest.coverage.confirmed_count == 5
    assert manifest.coverage.review_required_count == 1


def test_the_manifest_records_the_analyzer_versions_that_actually_ran(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    manifest = _assemble(root, tool_paths={"clang": "/usr/lib/llvm-18/bin/clang"})

    versions = {tool.name: tool.version for tool in manifest.tools}
    assert versions == VERSIONS
    clang = next(tool for tool in manifest.tools if tool.name == "clang")
    assert clang.path == "/usr/lib/llvm-18/bin/clang"


def test_the_manifest_is_the_only_place_absolute_paths_are_allowed(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    manifest = _assemble(root)
    assert manifest.repository_root == str(root)
    assert repo_display_name(manifest) == "demo"


# ---------------------------------------------------------------- T-08-13


def test_finding_hashes_cover_every_rendered_finding(tmp_path: Path) -> None:
    """T-08-13, AC-08-9: six entries, each the hash recorded at candidate time."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    manifest = _assemble(root, sections=sections)

    assert len(manifest.cited_region_hashes) == 6
    for finding in [*sections.confirmed, *sections.needs_review]:
        assert manifest.cited_region_hashes[finding.finding_id] == finding.location.sha256


def test_a_region_hash_matches_the_bytes_on_disk(tmp_path: Path) -> None:
    """The hash is over real bytes, so a later run can detect drift with it."""
    from caudit.evidence.store import SourceStore

    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    store = SourceStore(root, revision="demo-revision")

    for finding in sections.confirmed:
        assert store.hash_region(finding.location) == finding.location.sha256


# ---------------------------------------------------------------- T-08-18


def test_two_runs_differ_only_in_the_volatile_allowlist(tmp_path: Path) -> None:
    """T-08-18, AC-08-7: reproducibility is compared, not asserted."""
    root = write_demo_repo(tmp_path / "demo")
    first = _assemble(root)
    second = _assemble(
        root,
        started_at=REPORT_STARTED_AT + timedelta(hours=3),
        finished_at=REPORT_FINISHED_AT + timedelta(hours=3),
    )

    assert reproducibility_diff(first, second) == {}
    assert first.started_at != second.started_at


def test_the_allowlist_is_minimal_and_the_diff_catches_everything_else(
    tmp_path: Path,
) -> None:
    """An allowlist that hid a real difference would make the check vacuous."""
    root = write_demo_repo(tmp_path / "demo")
    first = _assemble(root)
    second = _assemble(root, caudit_version="0.2.0")

    assert set(VOLATILE_FIELDS) == {"started_at", "finished_at"}
    assert reproducibility_diff(first, second) == {"caudit_version": ("0.1.0", "0.2.0")}


def test_a_changed_configuration_changes_the_hash(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    other = Config.model_validate({"analyzers": {"enable_tidy": False}})

    assert config_fingerprint(Config()) != config_fingerprint(other)
    assert config_fingerprint(Config()) == config_fingerprint(Config())
    assert reproducibility_diff(_assemble(root), _assemble(root, config=other))


def test_the_manifest_round_trips_through_json(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    manifest = _assemble(root)
    assert RunManifest.model_validate_json(manifest.model_dump_json()) == manifest


def test_the_committed_fixture_manifest_stays_valid(tmp_path: Path) -> None:
    """The golden report is rendered from this; a drifted model must show up."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    manifest = demo_manifest(root, sections)
    assert manifest.schema_version
    assert manifest.coverage.review_required_count == sections.review_count

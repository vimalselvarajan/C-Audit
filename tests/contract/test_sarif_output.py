"""Part 08 contract tests: T-08-01 … T-08-04 (AC-08-1 … AC-08-4).

Every SARIF document this project emits is validated against the official
OASIS schema, vendored at ``schemas/sarif-2.1.0.schema.json`` and fetched from
https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
— byte-for-byte upstream, so "SARIF 2.1.0 compatible" is a checked property
rather than a claim. The schema declares draft-04, hence ``Draft4Validator``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft4Validator

from caudit.application.schema_export import SCHEMA_DIR
from caudit.model.evidence import EvidenceKind
from caudit.report.sarif import CWE_TAXONOMY_GUID, build_sarif, render_sarif
from caudit.report.sections import ReportSections
from tests.conftest import (
    DEMO_DIAGNOSTICS,
    demo_coverage,
    demo_manifest,
    demo_sections,
    write_demo_repo,
)

SARIF_SCHEMA_PATH = SCHEMA_DIR / "sarif-2.1.0.schema.json"


@pytest.fixture(scope="session")
def sarif_validator() -> Draft4Validator:
    schema = json.loads(SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft4Validator.check_schema(schema)
    return Draft4Validator(schema)


def _errors(validator: Draft4Validator, document: dict[str, Any]) -> list[str]:
    return [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in sorted(validator.iter_errors(document), key=str)
    ]


def _results(document: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = document["runs"][0]["results"]
    return results


# ---------------------------------------------------------------- T-08-01


def _documents(root: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    """Empty, one-finding, and twelve-finding runs.

    Twelve rather than six because the six-case fixture has one diagnostic per
    location: doubling it forces two findings onto one rule and one CWE, which
    is where a rules table built by accident would produce duplicate ids.
    """
    empty = ReportSections(coverage=demo_coverage())
    yield "empty", build_sarif(empty, demo_manifest(root, empty))

    single = demo_sections(root, diagnostics=DEMO_DIAGNOSTICS[:1])
    yield "one finding", build_sarif(single, demo_manifest(root, single))

    many = demo_sections(root, diagnostics=DEMO_DIAGNOSTICS * 2)
    yield "twelve findings", build_sarif(many, demo_manifest(root, many))


def test_every_shape_of_run_validates_against_the_official_schema(
    tmp_path: Path, sarif_validator: Draft4Validator
) -> None:
    """T-08-01: empty, single-finding, and multi-finding runs are all valid."""
    root = write_demo_repo(tmp_path / "demo")
    for label, document in _documents(root):
        assert _errors(sarif_validator, document) == [], label


def test_a_twelve_finding_run_declares_each_rule_once(tmp_path: Path) -> None:
    """Duplicated diagnostics share rules; duplicated rule ids are invalid."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root, diagnostics=DEMO_DIAGNOSTICS * 2)
    document = build_sarif(sections, demo_manifest(root, sections))

    rules = document["runs"][0]["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
    # Every result points at a rule that exists, by index as well as by id.
    for result in _results(document):
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


# ---------------------------------------------------------------- T-08-02


def test_confirmed_and_review_serialize_as_different_kinds(tmp_path: Path) -> None:
    """T-08-02, AC-08-2: the separation survives the export, not just the page.

    A code-scanning system that ingests this file cannot count a review-
    required item as a vulnerability: it is ``kind=review`` at ``level=none``,
    which is how SARIF spells "this is not a failure".
    """
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))
    results = _results(document)

    confirmed = [result for result in results if result["kind"] == "fail"]
    review = [result for result in results if result["kind"] == "review"]
    assert len(confirmed) == sections.confirmed_count == 5
    assert len(review) == sections.review_count == 1
    assert {result["level"] for result in review} == {"none"}
    assert "none" not in {result["level"] for result in confirmed}
    assert len(results) == len(confirmed) + len(review)


def test_no_notification_states_a_combined_finding_count(tmp_path: Path) -> None:
    """The run notes report both counts; nothing reports their sum."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))
    texts = [
        note["message"]["text"]
        for note in document["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    ]
    combined = f"{sections.confirmed_count + sections.review_count}"
    assert any("5 confirmed" in text and "1 item" in text for text in texts)
    assert not any(f"{combined} finding" in text for text in texts)


# ---------------------------------------------------------------- T-08-03


def test_cwe_appears_as_a_tag_and_as_a_taxonomy_relationship(tmp_path: Path) -> None:
    """T-08-03, AC-08-3: both forms, on every rule that has a CWE."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))
    run = document["runs"][0]

    strcpy = next(
        rule
        for rule in run["tool"]["driver"]["rules"]
        if rule["id"] == "clang-analyzer-security.insecureAPI.strcpy"
    )
    assert "CWE-787" in strcpy["properties"]["tags"]
    assert "out_of_bounds" in strcpy["properties"]["tags"]
    targets = [relation["target"]["id"] for relation in strcpy["relationships"]]
    assert targets == ["CWE-787"]

    taxonomy = run["taxonomies"][0]
    assert taxonomy["name"] == "CWE"
    assert taxonomy["guid"] == CWE_TAXONOMY_GUID
    assert "CWE-787" in {taxon["id"] for taxon in taxonomy["taxa"]}
    # The relationship has to point at the taxonomy this run actually declares.
    assert strcpy["relationships"][0]["target"]["toolComponent"]["guid"] == taxonomy["guid"]


def test_every_rule_with_a_cwe_carries_both_forms(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))
    declared = {taxon["id"] for taxon in document["runs"][0]["taxonomies"][0]["taxa"]}

    for rule in document["runs"][0]["tool"]["driver"]["rules"]:
        tagged = {tag for tag in rule["properties"]["tags"] if tag.startswith("CWE-")}
        related = {relation["target"]["id"] for relation in rule["relationships"]}
        assert tagged == related, rule["id"]
        assert related <= declared, rule["id"]


# ---------------------------------------------------------------- T-08-04


def test_a_four_step_analyzer_path_renders_as_an_ordered_code_flow(tmp_path: Path) -> None:
    """T-08-04, AC-08-4: the flow keeps the order the analyzer walked it."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))

    # unix.Malloc maps to CWE-401, CWE-416, CWE-415 in that order, and
    # promotion takes the first in-scope entry — the mapping is data, and the
    # test reads it rather than restating a preference.
    result = next(r for r in _results(document) if r["properties"]["cwe"] == "CWE-401")
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == 4
    assert [entry["executionOrder"] for entry in locations] == [1, 2, 3, 4]
    assert [
        entry["location"]["physicalLocation"]["region"]["startLine"] for entry in locations
    ] == [5, 6, 9, 10]


def test_a_finding_with_no_path_has_no_code_flow(tmp_path: Path) -> None:
    """An empty ``codeFlows`` array would assert a path that was never walked."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))

    flowless = [result for result in _results(document) if result["properties"]["cwe"] != "CWE-401"]
    assert flowless
    assert all("codeFlows" not in result for result in flowless)


def test_only_control_flow_evidence_becomes_a_flow(tmp_path: Path) -> None:
    """A supporting declaration is evidence; it is not step three of a path."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    finding = next(f for f in sections.confirmed if f.cwe == "CWE-401")

    kinds = [item.kind for item in finding.evidence]
    assert kinds.count(EvidenceKind.ANALYZER_DIAGNOSTIC) == 1
    assert kinds.count(EvidenceKind.CONTROL_FLOW_STEP) == 4

    document = build_sarif(sections, demo_manifest(root, sections))
    result = next(
        r for r in _results(document) if r["properties"]["findingId"] == finding.finding_id
    )
    assert len(result["codeFlows"][0]["threadFlows"][0]["locations"]) == 4


# --------------------------------------------------------- shape and text


def test_rendered_sarif_is_deterministic_json(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    manifest = demo_manifest(root, sections)
    text = render_sarif(sections, manifest)

    assert text == render_sarif(sections, manifest)
    assert text.endswith("\n")
    assert json.loads(text)["version"] == "2.1.0"


def test_each_result_carries_its_dedup_fingerprint_and_region_hash(tmp_path: Path) -> None:
    """Part 07's fingerprint is what a consumer uses to track one defect."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    document = build_sarif(sections, demo_manifest(root, sections))

    for result in _results(document):
        assert result["partialFingerprints"]["caudit/v1"]
        assert len(result["properties"]["regionHash"]) == 64
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["properties"]["sha256"] == result["properties"]["regionHash"]

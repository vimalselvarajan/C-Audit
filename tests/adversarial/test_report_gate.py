"""Part 08 adversarial test: T-08-16 (AC-08-12).

Each test here hands the report a claim that cannot be checked and asserts it
comes out labelled rather than confirmed. Two of them are the accidental
version — a file deleted or edited between analysis and rendering — and two
are the deliberate one: a finding that cites a file which never existed, or a
symbol that is not where it says it is. Part 11 will face the deliberate
version from a model; the gate that catches it exists here first.
"""

from __future__ import annotations

from pathlib import Path

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import CitationResolver
from caudit.evidence.store import SourceStore
from caudit.finding_policy.promotion import promote_candidate
from caudit.model.evidence import Provenance
from caudit.model.finding import Confidence, Finding, ReviewReason
from caudit.model.source import Symbol
from caudit.report.sarif import build_sarif
from caudit.report.sections import ReportSections, build_sections
from tests.conftest import (
    demo_candidates,
    demo_coverage,
    demo_manifest,
    demo_sections,
    make_evidence,
    make_finding,
    write_demo_repo,
)


def _gate(root: Path, findings: list[Finding]) -> ReportSections:
    store = SourceStore(root, revision="demo-revision")
    return build_sections(
        findings,
        resolver=CitationResolver(store, EvidenceBundle(store)),
        coverage=demo_coverage(),
    )


def test_a_finding_whose_file_was_deleted_after_analysis_cannot_be_confirmed(
    tmp_path: Path,
) -> None:
    """T-08-16: the deletion is discovered at render time, and it is fatal."""
    root = write_demo_repo(tmp_path / "demo")
    store = SourceStore(root, revision="demo-revision")
    findings = [promote_candidate(c, store=store) for c in demo_candidates(store)]
    confirmable = {f.finding_id for f in findings if f.is_confirmed}

    (root / "src" / "alpha.c").unlink()
    sections = _gate(root, list(findings))

    moved = [f for f in sections.needs_review if str(f.location.path) == "src/alpha.c"]
    assert len(moved) == 2
    assert moved[0].finding_id in confirmable
    for finding in moved:
        assert finding.confidence is Confidence.REVIEW_REQUIRED
        assert finding.confidence_reason is ReviewReason.MISSING_FILE
    assert not any(str(f.location.path) == "src/alpha.c" for f in sections.confirmed)


def test_the_deleted_finding_is_never_a_failing_sarif_result(tmp_path: Path) -> None:
    """A consumer must not see it as a vulnerability either."""
    root = write_demo_repo(tmp_path / "demo")
    store = SourceStore(root, revision="demo-revision")
    findings = [promote_candidate(c, store=store) for c in demo_candidates(store)]
    (root / "src" / "beta.c").unlink()

    sections = _gate(root, list(findings))
    document = build_sarif(sections, demo_manifest(root, sections))
    failing = [result for result in document["runs"][0]["results"] if result["kind"] == "fail"]

    assert failing
    assert not any(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/beta.c"
        for result in failing
    )
    reviewed = [r for r in document["runs"][0]["results"] if r["kind"] == "review"]
    assert any("missing_file" in r["message"]["text"] for r in reviewed)


def test_a_finding_citing_a_file_that_never_existed_is_rejected(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    """The fabricated version of the same failure, from the same gate."""
    root = write_demo_repo(tmp_path / "demo")
    invented = make_finding(provenance, path="src/does-not-exist.c", start_line=4)

    sections = _gate(root, [invented])

    assert sections.confirmed == []
    assert sections.needs_review[0].confidence_reason is ReviewReason.MISSING_FILE
    assert "src/does-not-exist.c" in sections.unresolved[invented.finding_id]


def test_a_finding_naming_a_symbol_that_is_not_there_is_rejected(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    """A plausible function name in a real file is the easiest claim to invent."""
    root = write_demo_repo(tmp_path / "demo")
    store = SourceStore(root, revision="demo-revision")
    region = store.make_region("src/alpha.c", 9, 13)
    symbol = Symbol(name="validate_record_bounds", kind="function")
    finding = make_finding(provenance, region=region, symbol=symbol)
    finding = finding.model_copy(
        update={"evidence": [make_evidence(provenance, region, symbol=symbol)]}
    )

    sections = _gate(root, [finding])

    assert sections.confirmed == []
    assert sections.needs_review[0].confidence_reason is ReviewReason.SYMBOL_UNRESOLVED
    assert "validate_record_bounds" in sections.unresolved[finding.finding_id]


def test_a_symbol_that_really_is_there_still_passes(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    """A gate that rejected everything would pass the tests above vacuously."""
    root = write_demo_repo(tmp_path / "demo")
    store = SourceStore(root, revision="demo-revision")
    region = store.make_region("src/alpha.c", 9, 13)
    symbol = Symbol(name="copy_name", kind="function")
    finding = make_finding(provenance, region=region, symbol=symbol)
    finding = finding.model_copy(
        update={"evidence": [make_evidence(provenance, region, symbol=symbol)]}
    )

    sections = _gate(root, [finding])
    assert [f.finding_id for f in sections.confirmed] == [finding.finding_id]
    assert sections.unresolved == {}


def test_an_untouched_tree_confirms_everything_it_should(tmp_path: Path) -> None:
    """The control case: nothing is moved when nothing changed."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    assert sections.unresolved == {}
    assert sections.confirmed_count == 5

"""Part 08 section tests: the evidence gate and the total order (AC-08-5, 12).

Everything here is about the moment a finding stops being a candidate. The
gate is the only route into the confirmed list, so these tests are what make
"a report cannot contain an unverified confirmed finding" a property of the
code rather than of the caller's discipline.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import REASON_FOR_STATUS, CitationResolver, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.finding_policy.ranking import severity_of
from caudit.model.evidence import Provenance
from caudit.model.finding import Confidence, ReviewReason, Severity
from caudit.report.sections import (
    ReportSections,
    build_sections,
    citations_of,
    sort_findings,
)
from tests.conftest import (
    DEMO_DIAGNOSTICS,
    demo_coverage,
    demo_sections,
    make_finding,
    write_demo_repo,
)


def _resolver(root: Path) -> CitationResolver:
    store = SourceStore(root, revision="demo-revision")
    return CitationResolver(store, EvidenceBundle(store))


# ------------------------------------------------------------ the gate


def test_a_finding_whose_citations_hold_reaches_the_confirmed_section(
    tmp_path: Path,
) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root, diagnostics=DEMO_DIAGNOSTICS[:1])

    assert sections.confirmed_count == 1
    assert sections.review_count == 0
    assert sections.unresolved == {}
    assert sections.confirmed[0].confidence is Confidence.MEDIUM


def test_a_finding_whose_file_vanished_is_moved_with_its_reason(tmp_path: Path) -> None:
    """AC-08-12: needs-review carrying the resolver's verdict, never confirmed."""
    root = write_demo_repo(tmp_path / "demo")
    store = SourceStore(root, revision="demo-revision")
    from caudit.finding_policy.promotion import promote_candidate
    from tests.conftest import demo_candidates

    findings = [promote_candidate(c, store=store) for c in demo_candidates(store)]
    (root / "src" / "gamma.c").unlink()

    sections = build_sections(findings, resolver=_resolver(root), coverage=demo_coverage())

    moved = [f for f in sections.needs_review if str(f.location.path) == "src/gamma.c"]
    assert len(moved) == 2
    assert not any(str(f.location.path) == "src/gamma.c" for f in sections.confirmed)
    for finding in moved:
        assert finding.confidence is Confidence.REVIEW_REQUIRED
        assert finding.confidence_reason is ReviewReason.MISSING_FILE
        assert "missing_file" in sections.unresolved[finding.finding_id]


def test_an_edited_file_moves_the_finding_with_a_hash_mismatch(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    store = SourceStore(root, revision="demo-revision")
    from caudit.finding_policy.promotion import promote_candidate
    from tests.conftest import demo_candidates

    findings = [promote_candidate(c, store=store) for c in demo_candidates(store)]
    text = (root / "src" / "alpha.c").read_text(encoding="utf-8")
    (root / "src" / "alpha.c").write_text(
        text.replace("strcpy(out->name, src);", "strncpy(out->name, src, 15);"), encoding="utf-8"
    )

    sections = build_sections(findings, resolver=_resolver(root), coverage=demo_coverage())
    moved = next(f for f in sections.needs_review if f.location.start_line == 12)
    assert moved.confidence_reason is ReviewReason.HASH_MISMATCH
    assert "hash_mismatch" in sections.unresolved[moved.finding_id]


def test_a_finding_already_needing_review_is_not_given_a_citation_reason(
    tmp_path: Path,
) -> None:
    """An out-of-family candidate resolves fine; its reason must survive."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)

    unmapped = next(f for f in sections.needs_review if f.location.start_line == 10)
    assert unmapped.confidence_reason is ReviewReason.OUT_OF_SCOPE_FAMILY
    assert unmapped.finding_id not in sections.unresolved


def test_every_resolver_verdict_maps_to_a_blocking_review_reason() -> None:
    """A status with no mapping would silently confirm an unresolved citation."""
    from caudit.model.finding import BLOCKING_REVIEW_REASONS

    assert set(REASON_FOR_STATUS) == set(ResolutionStatus) - {ResolutionStatus.OK}
    assert set(REASON_FOR_STATUS.values()) <= BLOCKING_REVIEW_REASONS


def test_the_gate_cites_the_location_and_every_evidence_region(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    finding = next(f for f in sections.confirmed if f.cwe == "CWE-401")

    citations = citations_of(finding)
    assert citations[0].label == "location"
    assert len(citations) == 1 + len(finding.evidence)
    assert all(citation.path for citation in citations)


# ---------------------------------------------------------- the ordering


def test_findings_sort_most_severe_first_then_by_a_total_key(
    provenance: list[Provenance],
) -> None:
    """T-08-10's premise, under part 12's ranking: no pair is left to chance.

    ``sort_findings`` now delegates to :func:`caudit.finding_policy.ranking.rank_key`,
    so severity comes from the CWE family rather than from ``impact.severity``.
    The integer-family finding sorts last for that reason, and not because this
    test lowered a field a model would have written.
    """
    # Distinct messages, because ``finding_id`` addresses the defect rather
    # than the run: two diagnostics with one message at one path are one
    # finding whatever line each fired on.
    findings = [
        make_finding(provenance, cwe=cwe, path=path, start_line=line, message=message)
        for cwe, path, line, message in (
            ("CWE-190", "src/z.c", 5, "wrap"),
            ("CWE-787", "src/a.c", 9, "overflow past the header"),
            ("CWE-787", "src/a.c", 2, "overflow past the name"),
            ("CWE-125", "src/a.c", 2, "over-read"),
        )
    ]
    ordered = sort_findings(findings)

    assert [severity_of(f) for f in ordered] == [
        Severity.HIGH,
        Severity.HIGH,
        Severity.HIGH,
        Severity.MEDIUM,
    ]
    assert ordered[-1].cwe == "CWE-190"
    # The three out-of-bounds findings agree on all five ranking inputs, so
    # the tie-break is the only thing separating them — and it is total.
    heads = [f.finding_id for f in ordered[:3]]
    assert heads == sorted(heads)
    assert len(set(heads)) == 3


def test_sorting_is_stable_under_any_input_order(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    forward = demo_sections(root, diagnostics=DEMO_DIAGNOSTICS)
    backward = demo_sections(root, diagnostics=tuple(reversed(DEMO_DIAGNOSTICS)))

    assert [f.finding_id for f in forward.confirmed] == [f.finding_id for f in backward.confirmed]
    assert [f.finding_id for f in forward.needs_review] == [
        f.finding_id for f in backward.needs_review
    ]


# --------------------------------------------------------- the separation


def test_a_finding_cannot_be_placed_in_both_sections(provenance: list[Provenance]) -> None:
    finding = make_finding(provenance)
    twin = finding.model_copy(
        update={
            "confidence": Confidence.REVIEW_REQUIRED,
            "confidence_reason": ReviewReason.HASH_MISMATCH,
        }
    )
    with pytest.raises(ValidationError, match="both sections"):
        ReportSections(confirmed=[finding], needs_review=[twin], coverage=demo_coverage())


def test_a_review_required_finding_cannot_sit_in_the_confirmed_list(
    provenance: list[Provenance],
) -> None:
    finding = make_finding(
        provenance,
        confidence=Confidence.REVIEW_REQUIRED,
        confidence_reason=ReviewReason.ANALYZER_ONLY,
    )
    with pytest.raises(ValidationError, match="confirmed section"):
        ReportSections(confirmed=[finding], coverage=demo_coverage())


def test_a_confirmed_finding_cannot_sit_in_the_review_list(provenance: list[Provenance]) -> None:
    with pytest.raises(ValidationError, match="needs-review section"):
        ReportSections(needs_review=[make_finding(provenance)], coverage=demo_coverage())


def test_region_hashes_cover_both_sections(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    hashes = sections.region_hashes()

    assert len(hashes) == sections.confirmed_count + sections.review_count
    assert list(hashes) == sorted(hashes)
    for finding in [*sections.confirmed, *sections.needs_review]:
        assert hashes[finding.finding_id] == finding.location.sha256

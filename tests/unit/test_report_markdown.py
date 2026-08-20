"""Part 08 Markdown tests: T-08-06, T-08-07, T-08-14 (AC-08-5, 6, 10).

The counts asserted here are the same ones the golden snapshot contains. That
is deliberate: re-recording ``tests/golden/report/report.md`` after an
unintended change breaks this module too, which is the mitigation the plan's
risk section asks for.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from caudit.intake.plan import ExclusionReason
from caudit.model.evidence import Provenance
from caudit.model.finding import Limitation, LimitationKind
from caudit.report.markdown import SEPARATION_NOTICE, render_markdown
from caudit.report.sarif import build_sarif
from caudit.report.sections import ReportSections, build_sections
from tests.conftest import (
    demo_coverage,
    demo_manifest,
    demo_sections,
    make_finding,
    write_demo_repo,
)

#: Four excluded targets and a coverage ratio of 0.82, as T-08-07 specifies.
EXCLUDED: list[tuple[PurePosixPath, ExclusionReason]] = [
    (PurePosixPath("third_party/zlib/inflate.c"), ExclusionReason.THIRD_PARTY),
    (PurePosixPath("build/generated/parser.c"), ExclusionReason.GENERATED),
    (PurePosixPath("src/huge.c"), ExclusionReason.TOO_LARGE),
    (PurePosixPath("tools/aux.cxx"), ExclusionReason.NOT_SELECTED),
]

PARTIAL_COVERAGE = demo_coverage(
    tus_in_database=22,
    tus_selected=14,
    source_files_in_tree=17,
    source_files_covered=14,
    coverage_ratio=0.82,
)


# ---------------------------------------------------------------- T-08-06


def _mixed_sections(provenance: list[Provenance]) -> ReportSections:
    """Three confirmed findings and two needing review, and nothing else."""
    from caudit.model.finding import Confidence, ReviewReason

    confirmed = [
        make_finding(provenance, cwe=cwe, path=path, start_line=line, message=message)
        for cwe, path, line, message in (
            ("CWE-787", "src/a.c", 11, "unbounded copy into a fixed buffer"),
            ("CWE-476", "src/b.c", 21, "dereference of a null pointer"),
            ("CWE-416", "src/c.c", 31, "use of memory after it is released"),
        )
    ]
    review = [
        make_finding(
            provenance,
            cwe=cwe,
            path=path,
            start_line=line,
            message=message,
            confidence=Confidence.REVIEW_REQUIRED,
            confidence_reason=ReviewReason.ANALYZER_ONLY,
        )
        for cwe, path, line, message in (
            ("CWE-190", "src/d.c", 41, "loop bound may wrap"),
            ("CWE-772", "src/e.c", 51, "handle is not released on the error path"),
        )
    ]
    return ReportSections(confirmed=confirmed, needs_review=review, coverage=demo_coverage())


def test_both_counts_appear_and_no_artifact_states_their_sum(
    tmp_path: Path, provenance: list[Provenance]
) -> None:
    """T-08-06: 3 and 2 are both present; 5 as a finding total is nowhere."""
    sections = _mixed_sections(provenance)
    root = write_demo_repo(tmp_path / "demo")
    text = render_markdown(sections, demo_manifest(root, sections))

    assert "## Confirmed findings (3)" in text
    assert "## Needs review (2)" in text
    assert "| Confirmed findings | 3 |" in text
    assert "| Items needing review | 2 |" in text
    assert SEPARATION_NOTICE in text

    # No total, under any of the words a total is written with.
    assert not re.search(r"\b5\s+(findings?|results?|issues?|items?|total)\b", text, re.I)
    assert "Total" not in text
    assert "total" not in text.lower().replace("totally", "")


def test_the_sections_model_offers_no_way_to_add_the_two_counts() -> None:
    """The rule is enforced by absence, not by every caller remembering it."""
    names = set(dir(ReportSections))
    assert {"confirmed_count", "review_count"} <= names
    assert not {"total", "total_count", "findings_total", "all_findings"} & names


# ---------------------------------------------------------------- T-08-07


def test_coverage_and_excluded_targets_reach_both_artifacts(tmp_path: Path) -> None:
    """T-08-07, AC-08-6: four exclusions and a 0.82 ratio, in Markdown and SARIF."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root, coverage=PARTIAL_COVERAGE, excluded=EXCLUDED)
    manifest = demo_manifest(root, sections)

    text = render_markdown(sections, manifest)
    assert "0.82" in text
    assert "## Excluded from the scan" in text
    for path, reason in EXCLUDED:
        assert str(path) in text
        assert str(reason) in text
    assert "Incomplete" in text

    notes = [
        note["message"]["text"]
        for note in build_sarif(sections, manifest)["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ]
    ]
    assert any("0.82" in note for note in notes)
    for path, reason in EXCLUDED:
        assert any(str(path) in note and str(reason) in note for note in notes), path


def test_limitations_reach_both_artifacts(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    limitation = Limitation(
        kind=LimitationKind.ANALYZER_FAILED,
        detail="clang-tidy timed out after 300s on this unit",
        affects="src/huge.c",
    )
    sections = demo_sections(root, limitations=[limitation])
    manifest = demo_manifest(root, sections)

    text = render_markdown(sections, manifest)
    assert "analyzer_failed" in text
    assert "timed out" in text
    assert "A blind spot is not a clean result" in text

    notes = [
        note["message"]["text"]
        for note in build_sarif(sections, manifest)["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ]
    ]
    assert any("analyzer_failed" in note and "src/huge.c" in note for note in notes)


# ---------------------------------------------------------------- T-08-14


def test_an_empty_run_renders_a_report_that_does_not_read_as_clean(tmp_path: Path) -> None:
    """T-08-14, AC-08-10: no findings, coverage still shown, no false comfort."""
    root = write_demo_repo(tmp_path / "demo")
    sections = ReportSections(coverage=PARTIAL_COVERAGE, excluded=EXCLUDED)
    text = render_markdown(sections, demo_manifest(root, sections))

    assert "## Confirmed findings (0)" in text
    assert "## Needs review (0)" in text
    assert "No confirmed findings." in text
    assert "clean bill of health" in text
    # Coverage is rendered even though there is nothing to attribute to it.
    assert "## Coverage" in text
    assert "0.82" in text


def test_a_complete_empty_run_still_renders_coverage(tmp_path: Path) -> None:
    """AC-08-6: rendered even when complete, so nothing has to be inferred."""
    root = write_demo_repo(tmp_path / "demo")
    sections = ReportSections(coverage=demo_coverage())
    text = render_markdown(sections, demo_manifest(root, sections))

    assert "## Coverage" in text
    assert "Complete." in text
    assert "## Limitations" in text
    assert "None recorded" in text


def test_a_run_note_is_rendered_before_the_findings(tmp_path: Path) -> None:
    """ "No analyzer ran" has to be read before a count of zero is believed."""
    root = write_demo_repo(tmp_path / "demo")
    sections = build_sections(
        [],
        resolver=_null_resolver(root),
        coverage=demo_coverage(),
        notes=["No analyzer ran. This report is not a clean result."],
    )
    text = render_markdown(sections, demo_manifest(root, sections))

    assert text.index("No analyzer ran") < text.index("## Confirmed findings")


def _null_resolver(root: Path):  # type: ignore[no-untyped-def]
    from caudit.evidence.bundle import EvidenceBundle
    from caudit.evidence.resolver import CitationResolver
    from caudit.evidence.store import SourceStore

    store = SourceStore(root, revision="demo-revision")
    return CitationResolver(store, EvidenceBundle(store))

"""Baseline candidate sources and candidate→finding promotion (part 04).

The Clang diagnostic parser is exercised against captured text rather than a
live toolchain: the parsing is where the bugs are, and it does not need a
compiler to test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.baseline import (
    RULE_CWE_MAP,
    ClangBaselineSource,
    RecordedCandidateSource,
    promote_candidate,
)
from caudit.eval.case import BenchmarkCase
from caudit.evidence.store import SourceStore
from caudit.model.cwe import WeaknessFamily, family_of
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import Confidence, Exploitability, Reachability, ReviewReason

CLANG_TIDY_OUTPUT = """\
{root}/src/copy_name.c:17:5: warning: Call to function 'strcpy' is insecure \
[clang-analyzer-security.insecureAPI.strcpy]
{root}/src/copy_name.c:17:5: note: Call to function 'strcpy' is insecure
{root}/src/copy_name.c:18:5: warning: something unmapped happens here [bugprone-unmapped]
/elsewhere/other.c:3:1: warning: outside the case root [clang-analyzer-core.NullDereference]
not a diagnostic line at all
"""


@pytest.fixture
def case() -> BenchmarkCase:
    return MiniSuite().load("oob-write-stack-copy")


@pytest.fixture
def case_store(case: BenchmarkCase) -> SourceStore:
    return SourceStore(case.root, revision="test")


def test_diagnostic_parser_keeps_warnings_and_drops_notes(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    output = CLANG_TIDY_OUTPUT.format(root=case.root)
    candidates = ClangBaselineSource._parse(
        output, case, case_store, Producer.CLANG_TIDY, "clang-tidy", "18.1.8"
    )
    lines = sorted(c.region.start_line for c in candidates)
    assert lines == [17, 18], "notes are context, not candidates"

    strcpy = next(c for c in candidates if c.region.start_line == 17)
    assert strcpy.suggested_cwe == ["CWE-787"]
    assert strcpy.provenance[0].rule_id == "clang-analyzer-security.insecureAPI.strcpy"
    assert strcpy.provenance[0].tool_version == "18.1.8"


def test_diagnostic_parser_ignores_paths_outside_the_case(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    output = CLANG_TIDY_OUTPUT.format(root=case.root)
    candidates = ClangBaselineSource._parse(
        output, case, case_store, Producer.CLANG_TIDY, "clang-tidy", "18.1.8"
    )
    assert all("elsewhere" not in str(c.region.path) for c in candidates)


def test_unmapped_rule_produces_a_candidate_with_no_cwe(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    """A rule with no accurate mapping is kept, not dropped or approximated."""
    output = CLANG_TIDY_OUTPUT.format(root=case.root)
    candidates = ClangBaselineSource._parse(
        output, case, case_store, Producer.CLANG_TIDY, "clang-tidy", "18.1.8"
    )
    unmapped = next(c for c in candidates if c.region.start_line == 18)
    assert unmapped.suggested_cwe == []
    assert unmapped.out_of_scope is True


def test_every_mapped_rule_points_at_an_allowlisted_or_known_cwe() -> None:
    """A mapping table entry that no family recognises would score nowhere."""
    unknown = {
        rule: [cwe for cwe in cwes if family_of(cwe) is None] for rule, cwes in RULE_CWE_MAP.items()
    }
    unmapped = {rule: cwes for rule, cwes in unknown.items() if cwes}
    # CWE-252 (unchecked return value) is deliberately out of the MVP's
    # families; anything else would be an error in the table.
    assert unmapped == {"cert-err33-c": ["CWE-252"]}


def test_promotion_never_infers_reachability_or_exploitability(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    candidates = RecordedCandidateSource().candidates_for(case, case_store)
    assert candidates
    finding = promote_candidate(candidates[0], store=case_store)
    assert finding.reachability is Reachability.UNKNOWN
    assert finding.exploitability is Exploitability.UNKNOWN
    assert finding.confidence is Confidence.MEDIUM
    assert finding.confidence_reason is ReviewReason.ANALYZER_ONLY
    assert finding.family is WeaknessFamily.OUT_OF_BOUNDS


def test_promotion_says_which_fields_it_did_not_assess(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    """Honest text beats a plausible guess in every one of these fields."""
    candidate = RecordedCandidateSource().candidates_for(case, case_store)[0]
    finding = promote_candidate(candidate, store=case_store)
    maintainability = finding.maintainability_impact
    for value in (
        maintainability.ownership,
        maintainability.complexity,
        maintainability.coupling,
        maintainability.regression_risk,
    ):
        assert "Not assessed" in value
    assert "not established" in finding.preconditions[0]
    assert any(
        limitation.kind.value == "no_evidence_expansion" for limitation in finding.limitations
    )


def test_promotion_routes_an_unmappable_candidate_to_review_required(
    case: BenchmarkCase, case_store: SourceStore, tmp_path: Path
) -> None:
    recording = {
        "diagnostics": [
            {
                "path": "src/copy_name.c",
                "line": 18,
                "message": "some diagnostic with no accurate CWE",
                "rule_id": "bugprone-unmapped",
                "tool_name": "clang-tidy",
                "tool_version": "18.1.8",
                "producer": "clang_tidy",
                "cwe": [],
            }
        ]
    }
    scratch = tmp_path / "case"
    scratch.mkdir()
    (scratch / "src").mkdir()
    (scratch / "src" / "copy_name.c").write_bytes((case.root / "src" / "copy_name.c").read_bytes())
    (scratch / "recording.json").write_text(json.dumps(recording), encoding="utf-8")

    scratch_case = case.model_copy(update={"root": scratch})
    store = SourceStore(scratch, revision="test")
    candidates = RecordedCandidateSource("recording.json").candidates_for(scratch_case, store)
    finding = promote_candidate(candidates[0], store=store)
    assert finding.confidence is Confidence.REVIEW_REQUIRED
    assert finding.confidence_reason is ReviewReason.OUT_OF_SCOPE_FAMILY
    assert "provisional" in finding.cwe_rationale
    assert not finding.is_confirmed


def test_promotion_flags_a_region_that_changed_under_it(
    case: BenchmarkCase, tmp_path: Path
) -> None:
    """A quotation that no longer matches the tree cannot be confirmed."""
    scratch = tmp_path / "case"
    (scratch / "src").mkdir(parents=True)
    source = scratch / "src" / "copy_name.c"
    source.write_bytes((case.root / "src" / "copy_name.c").read_bytes())
    (scratch / "baseline-candidates.json").write_bytes(
        (case.root / "baseline-candidates.json").read_bytes()
    )

    scratch_case = case.model_copy(update={"root": scratch})
    store = SourceStore(scratch, revision="test")
    candidate = RecordedCandidateSource().candidates_for(scratch_case, store)[0]

    source.write_bytes(b"/* rewritten */\n" * 40)
    fresh_store = SourceStore(scratch, revision="test")
    finding = promote_candidate(candidate, store=fresh_store)
    assert finding.confidence is Confidence.REVIEW_REQUIRED
    assert finding.confidence_reason is ReviewReason.HASH_MISMATCH


def test_symbol_without_a_containing_region_is_not_reported(
    case: BenchmarkCase, tmp_path: Path
) -> None:
    """An unprovable attribution becomes a limitation, not a claim.

    The recording is written here rather than borrowed from a committed
    fixture and edited. The shape under test is "names a symbol, proves no
    span", and which committed case happens to carry a symbol is an accident
    of what the analyzers resolved on the recording machine — this test broke
    once already when a re-recording produced candidates with no symbol at
    all, having silently stopped exercising its own subject before that.
    """
    scratch = tmp_path / "case"
    (scratch / "src").mkdir(parents=True)
    (scratch / "src" / "copy_name.c").write_bytes((case.root / "src" / "copy_name.c").read_bytes())
    recording = {
        "diagnostics": [
            {
                "path": "src/copy_name.c",
                "line": 17,
                "end_line": 17,
                "message": "Call to function 'strcpy' is insecure",
                "rule_id": "clang-analyzer-security.insecureAPI.strcpy",
                "tool_name": "clang-static-analyzer",
                "tool_version": "18.1.3",
                "producer": "csa",
                "cwe": ["CWE-787"],
                # Named, but with no span committed alongside it.
                "symbol": "copy_name",
            }
        ]
    }
    (scratch / "baseline-candidates.json").write_text(json.dumps(recording), encoding="utf-8")

    scratch_case = case.model_copy(update={"root": scratch})
    store = SourceStore(scratch, revision="test")
    candidate = RecordedCandidateSource().candidates_for(scratch_case, store)[0]
    assert candidate.symbol is not None, "the fixture under test must name a symbol"
    assert candidate.enclosing_region is None

    finding = promote_candidate(candidate, store=store)
    assert finding.symbol is None
    assert any("no region proves" in limitation.detail for limitation in finding.limitations)


def test_recorded_source_returns_nothing_when_there_is_no_recording(
    tmp_path: Path, case: BenchmarkCase
) -> None:
    empty = case.model_copy(update={"root": tmp_path})
    store = SourceStore(tmp_path, revision="test")
    assert RecordedCandidateSource().candidates_for(empty, store) == ()


def test_recorded_source_skips_a_diagnostic_pointing_outside_the_file(
    case: BenchmarkCase, tmp_path: Path
) -> None:
    scratch = tmp_path / "case"
    (scratch / "src").mkdir(parents=True)
    (scratch / "src" / "copy_name.c").write_bytes(b"int x = 1;\n")
    (scratch / "baseline-candidates.json").write_text(
        json.dumps(
            {
                "diagnostics": [
                    {
                        "path": "src/copy_name.c",
                        "line": 900,
                        "message": "past the end of the file",
                        "rule_id": "r",
                        "tool_name": "clang-tidy",
                        "tool_version": "18.1.8",
                        "producer": "clang_tidy",
                        "cwe": ["CWE-787"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    scratch_case = case.model_copy(update={"root": scratch})
    store = SourceStore(scratch, revision="test")
    assert RecordedCandidateSource().candidates_for(scratch_case, store) == []


def test_recorded_source_reports_the_versions_it_replayed(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    source = RecordedCandidateSource()
    source.candidates_for(case, case_store)
    versions = source.tool_versions()
    assert versions
    # The committed fixtures are captures from a real toolchain as of
    # 2026-08-15, so they carry the versions that produced them. `unrecorded`
    # is what an authored expectation says, and one appearing here means a
    # hand-written recording has been committed over a captured one.
    assert "unrecorded" not in set(versions.values())
    for version in versions.values():
        assert version[0].isdigit(), f"{version!r} is not a real tool version"


def test_candidate_merge_preserves_every_provenance_entry(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    candidate = RecordedCandidateSource().candidates_for(case, case_store)[0]
    # Whichever tool the committed recording came from, the merge has to keep
    # it alongside the second one. Naming both literally would tie this test to
    # which analyzer happened to win the dedup on the recording machine, which
    # is exactly what changed when the fixtures became real captures.
    original_tool = candidate.provenance[0].tool_name
    other = candidate.model_copy(
        update={
            "provenance": [
                Provenance(
                    producer=Producer.CSA,
                    tool_name="some-other-analyzer",
                    tool_version="18.1.8",
                    rule_id="clang-analyzer-unix.cstring.OutOfBounds",
                )
            ],
            "suggested_cwe": ["CWE-125"],
        }
    )
    merged = candidate.merged_with(other)
    assert len(merged.provenance) == 2
    assert merged.suggested_cwe == ["CWE-787", "CWE-125"]
    assert {p.tool_name for p in merged.provenance} == {original_tool, "some-other-analyzer"}
    assert original_tool != "some-other-analyzer", "the two sides must be distinguishable"


def test_candidates_with_different_fingerprints_refuse_to_merge(
    case: BenchmarkCase, case_store: SourceStore
) -> None:
    candidate = RecordedCandidateSource().candidates_for(case, case_store)[0]
    unrelated = candidate.model_copy(update={"fingerprint": "fp-something-else"})
    with pytest.raises(ValueError, match="different fingerprints"):
        candidate.merged_with(unrelated)


def test_candidate_families_are_deduplicated(case: BenchmarkCase, case_store: SourceStore) -> None:
    candidate = RecordedCandidateSource().candidates_for(case, case_store)[0]
    widened = candidate.model_copy(update={"suggested_cwe": ["CWE-787", "CWE-121", "CWE-9999"]})
    assert widened.families == [WeaknessFamily.OUT_OF_BOUNDS]
    assert widened.out_of_scope is False
    assert widened.normalized_message

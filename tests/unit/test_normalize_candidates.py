"""Part 07 normalization tests: AC-07-2, AC-07-3, AC-07-8, AC-07-9.

Where a parsed diagnostic becomes a citable candidate. The assertions that
matter here are the ones part 11 will later depend on: the region hashes
against the bytes on disk, the symbol is only claimed when a region proves it,
and the analyzer's own words survive.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.analyzers.csa import parse_sarif
from caudit.analyzers.diagnostics import parse_text_diagnostics
from caudit.analyzers.normalize import Normalizer, RawDiagnostic, RawNote, relative_to_repo
from caudit.analyzers.profile import load_profile
from caudit.analyzers.tidy import parse_export_fixes
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import Citation, CitationResolver, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceKind, Producer
from tests.conftest import analyzer_fixture


@pytest.fixture
def normalizer(store: SourceStore) -> Normalizer:
    return Normalizer(store=store, profile=load_profile(), index=None)


def _diagnostic(**overrides: object) -> RawDiagnostic:
    fields: dict[str, object] = {
        "producer": Producer.CLANG_TIDY,
        "tool_name": "clang-tidy",
        "tool_version": "18.1.8",
        "rule_id": "clang-analyzer-security.insecureAPI.strcpy",
        "message": "Call to function 'strcpy' is insecure",
        "path": "src/main.c",
        "line": 5,
    }
    fields.update(overrides)
    return RawDiagnostic(**fields)  # type: ignore[arg-type]


# ----------------------------------------------------------------- regions


def test_every_candidate_region_resolves_through_part_three(
    normalizer: Normalizer, store: SourceStore, repo: Path
) -> None:
    """T-07-18/AC-07-9: a citation built here holds when part 11 checks it."""
    candidates = normalizer.to_candidates([_diagnostic()], base=repo)
    resolver = CitationResolver(store, EvidenceBundle(store))

    assert candidates
    for candidate in candidates:
        resolution = resolver.resolve(Citation.from_region(candidate.region))
        assert resolution.status is ResolutionStatus.OK, resolution.detail
        assert resolution.observed == candidate.region.sha256


def test_the_region_hash_is_computed_from_the_bytes_on_disk(
    normalizer: Normalizer, store: SourceStore, repo: Path
) -> None:
    candidate = normalizer.to_candidates([_diagnostic()], base=repo)[0]
    assert candidate.region.sha256 == store.hash_region(candidate.region)
    assert b"strcpy" in store.read_region(candidate.region)


def test_a_diagnostic_outside_the_repository_produces_no_candidate(
    normalizer: Normalizer, repo: Path
) -> None:
    """A system header is not part of the scanned revision."""
    candidates = normalizer.to_candidates(
        [_diagnostic(path="/usr/include/string.h", line=141)], base=repo
    )
    assert candidates == []
    assert normalizer.stats.outside_repo == 1
    assert "/usr/include/string.h" in normalizer.stats.paths_outside_repo


def test_a_line_past_the_end_of_the_file_produces_no_candidate(
    normalizer: Normalizer, repo: Path
) -> None:
    """Better no candidate than one whose citation cannot resolve."""
    assert normalizer.to_candidates([_diagnostic(line=9999)], base=repo) == []
    assert normalizer.stats.unreadable_region == 1


def test_relative_to_repo_rejects_a_path_that_escapes_the_root(tmp_path: Path) -> None:
    assert relative_to_repo("../outside.c", tmp_path, base=tmp_path) is None
    assert relative_to_repo("", tmp_path) is None


# -------------------------------------------------------------- provenance


def test_provenance_records_the_tool_the_version_and_the_rule(
    normalizer: Normalizer, repo: Path
) -> None:
    candidate = normalizer.to_candidates([_diagnostic()], base=repo)[0]
    entry = candidate.provenance[0]

    assert entry.producer is Producer.CLANG_TIDY
    assert entry.tool_name == "clang-tidy"
    assert entry.tool_version == "18.1.8"
    assert entry.rule_id == "clang-analyzer-security.insecureAPI.strcpy"


def test_the_analyzers_own_text_is_preserved_verbatim(normalizer: Normalizer, repo: Path) -> None:
    """Paraphrasing at intake would make provenance unverifiable later."""
    message = "Call to function 'strcpy' is insecure as it does not provide bounding"
    candidate = normalizer.to_candidates([_diagnostic(message=message)], base=repo)[0]

    assert candidate.message == message
    assert candidate.normalized_message != message  # derived, not stored


def test_notes_and_fixes_travel_in_the_provenance_detail(
    normalizer: Normalizer, repo: Path
) -> None:
    """T-07-09: the fix is recorded as text, and no file is touched."""
    diagnostic = _diagnostic(
        notes=(RawNote(path="src/main.c", line=3, message="declared here"),),
        fix="src/main.c@68+6 -> 'strlcpy'",
    )
    candidate = normalizer.to_candidates([diagnostic], base=repo)[0]
    detail = candidate.provenance[0].detail or ""

    assert "severity=warning" in detail
    assert "note src/main.c:3: declared here" in detail
    assert "recorded, not applied" in detail
    assert "strlcpy" in detail


# ---------------------------------------------------------------- evidence


def test_control_flow_steps_become_ordered_evidence(normalizer: Normalizer, repo: Path) -> None:
    """AC-07-2: four steps in, four ordered ``control_flow_step`` items out."""
    text = analyzer_fixture("csa", "four-step-flow.sarif").read_text(encoding="utf-8")
    parsed = parse_sarif(text, tool_version="18.1.8")
    candidate = normalizer.to_candidates(parsed, base=repo)[0]

    steps = [item for item in candidate.evidence if item.kind is EvidenceKind.CONTROL_FLOW_STEP]
    assert len(steps) == 4
    assert [item.region.start_line for item in steps] == [1, 3, 4, 5]


def test_a_flow_step_outside_the_tree_is_skipped_but_its_text_survives(
    normalizer: Normalizer, repo: Path
) -> None:
    diagnostic = _diagnostic(
        flow=(
            RawNote(
                path="/usr/include/stdlib.h",
                line=1,
                message="allocated here",
                kind=EvidenceKind.CONTROL_FLOW_STEP,
            ),
            RawNote(
                path="src/main.c", line=5, message="used here", kind=EvidenceKind.CONTROL_FLOW_STEP
            ),
        )
    )
    candidate = normalizer.to_candidates([diagnostic], base=repo)[0]

    assert len(candidate.evidence) == 1
    assert "allocated here" in (candidate.provenance[0].detail or "")


def test_tidy_notes_do_not_become_separate_candidates(
    normalizer: Normalizer, repo: Path, tmp_path: Path
) -> None:
    """T-07-08 at the candidate level: one defect, one candidate."""
    template = analyzer_fixture("tidy", "notes-and-fix.yaml").read_text(encoding="utf-8")
    parsed = parse_export_fixes(template, tool_version="18.1.8")
    # The fixture's offsets address the `repo` fixture's src/main.c, and the
    # normalizer needs lines, so convert exactly as TidyAnalyzer does.
    store = normalizer.store
    resolved = [
        RawDiagnostic(
            **{
                **item.__dict__,
                "line": store.byte_to_line("src/main.c", item.line),
                "notes": tuple(
                    RawNote(
                        path=note.path,
                        line=store.byte_to_line("src/main.c", note.line),
                        message=note.message,
                    )
                    for note in item.notes
                ),
            }
        )
        for item in parsed
    ]
    candidates = normalizer.to_candidates(resolved, base=repo)

    assert len(candidates) == 1
    assert candidates[0].region.start_line == 5
    assert len(candidates[0].evidence) == 2


# ------------------------------------------------------------------- CWEs


def test_a_mapped_rule_carries_its_cwe_and_an_unmapped_one_carries_none(
    normalizer: Normalizer, repo: Path
) -> None:
    """AC-07-8: unmapped is a candidate with no CWE, never a dropped candidate."""
    mapped, unmapped = normalizer.to_candidates(
        [
            _diagnostic(rule_id="clang-analyzer-security.insecureAPI.strcpy"),
            _diagnostic(rule_id="bugprone-future-check-2030", message="something new"),
        ],
        base=repo,
    )

    assert mapped.suggested_cwe == ["CWE-787"]
    assert mapped.out_of_scope is False
    assert unmapped.suggested_cwe == []
    assert unmapped.out_of_scope is True


def test_a_compile_diagnostic_maps_through_its_warning_flag(
    normalizer: Normalizer, repo: Path
) -> None:
    """One warning, one CWE, whichever producer surfaced it."""
    text = "src/main.c:5:5: warning: format string is not a literal [-Wformat-security]\n"
    parsed = parse_text_diagnostics(text, tool_version="18.1.8")
    candidate = normalizer.to_candidates(parsed, base=repo)[0]

    assert candidate.suggested_cwe == ["CWE-134"]
    assert candidate.provenance[0].producer is Producer.CLANG_DIAGNOSTIC


# ----------------------------------------------------------------- symbols


def test_no_symbol_is_claimed_without_an_index_to_prove_it(
    normalizer: Normalizer, repo: Path
) -> None:
    """A symbol with no region containing it is an assertion, not evidence."""
    candidate: Candidate = normalizer.to_candidates([_diagnostic()], base=repo)[0]
    assert candidate.symbol is None
    assert candidate.enclosing_region is None

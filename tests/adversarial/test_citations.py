"""Part 03 adversarial citation tests: T-03-05 … T-03-12, T-03-17.

Each test tries to get an unverifiable claim past the resolver and asserts
the specific reason it is caught. The reason matters as much as the refusal:
part 11 routes on it and part 08 prints it, so collapsing two causes into one
status would lose information a reader needs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import Citation, CitationResolver, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.model.evidence import EvidenceKind, Provenance

#: Every status must be produced by at least one test in this module.
PRODUCED: dict[ResolutionStatus, str] = {}


def _record(status: ResolutionStatus, test_name: str) -> None:
    PRODUCED.setdefault(status, test_name)


def test_missing_file(resolver: CitationResolver) -> None:
    """T-03-05."""
    resolution = resolver.resolve(Citation(path="src/does_not_exist.c", start_line=1, end_line=1))
    assert resolution.status is ResolutionStatus.MISSING_FILE
    assert "src/does_not_exist.c" in resolution.detail
    _record(resolution.status, "missing_file")


def test_line_past_end_of_file(resolver: CitationResolver, store: SourceStore) -> None:
    """T-03-06: observed reports the real line count."""
    resolution = resolver.resolve(Citation(path="src/main.c", start_line=5000, end_line=5000))
    assert resolution.status is ResolutionStatus.LINE_OUT_OF_RANGE
    assert resolution.observed == str(store.line_count("src/main.c"))
    assert "5000" in resolution.detail
    _record(resolution.status, "line_out_of_range")


def test_inverted_and_negative_ranges(resolver: CitationResolver) -> None:
    """T-03-07: both shapes fail as BYTE_RANGE_INVALID."""
    inverted = resolver.resolve(Citation(path="src/main.c", start_line=5, end_line=2))
    assert inverted.status is ResolutionStatus.BYTE_RANGE_INVALID
    assert "precedes" in inverted.detail

    negative = resolver.resolve(
        Citation(path="src/main.c", start_line=1, end_line=1, start_byte=-4, end_byte=8)
    )
    assert negative.status is ResolutionStatus.BYTE_RANGE_INVALID
    assert "negative" in negative.detail
    _record(inverted.status, "byte_range_invalid")


def test_byte_range_past_end_of_file(resolver: CitationResolver) -> None:
    resolution = resolver.resolve(
        Citation(path="src/main.c", start_line=1, end_line=1, start_byte=0, end_byte=10_000)
    )
    assert resolution.status is ResolutionStatus.BYTE_RANGE_INVALID


def test_stale_hash_after_the_file_changes(
    repo: Path, store: SourceStore, bundle: EvidenceBundle, provenance: list[Provenance]
) -> None:
    """T-03-08: the resolver reports the new hash rather than quoting it."""
    region = store.make_region("src/main.c", 3, 5)
    resolver = CitationResolver(store, bundle)
    assert resolver.resolve(Citation.from_region(region)).status is ResolutionStatus.OK

    (repo / "src" / "main.c").write_bytes(
        b"#include <string.h>\n\nvoid copy_in(char *dst, const char *src)\n{\n"
        b"    strncpy(dst, src, 15);\n}\n"
    )
    resolution = resolver.resolve(Citation.from_region(region))
    assert resolution.status is ResolutionStatus.HASH_MISMATCH
    assert resolution.observed is not None
    assert resolution.observed != region.sha256
    assert "changed since it was cited" in resolution.detail
    _record(resolution.status, "hash_mismatch")


def test_symbol_off_by_one_region(store: SourceStore, bundle: EvidenceBundle) -> None:
    """T-03-09: the symbol is on line 3, the region claims lines 4-6."""
    resolver = CitationResolver(store, bundle)
    region = store.make_region("src/main.c", 4, 6)
    resolution = resolver.resolve(Citation.from_region(region, symbol="copy_in"))
    assert resolution.status is ResolutionStatus.SYMBOL_NOT_FOUND
    assert "copy_in" in resolution.detail

    # And the correct region resolves, so this is not a blanket refusal.
    correct = store.make_region("src/main.c", 3, 5)
    assert (
        resolver.resolve(Citation.from_region(correct, symbol="copy_in")).status
        is ResolutionStatus.OK
    )
    _record(resolution.status, "symbol_not_found")


def test_symbol_match_is_whole_identifier_only(store: SourceStore, bundle: EvidenceBundle) -> None:
    """`copy` must not match inside `copy_in`."""
    resolver = CitationResolver(store, bundle)
    region = store.make_region("src/main.c", 3, 5)
    assert (
        resolver.resolve(Citation.from_region(region, symbol="copy")).status
        is ResolutionStatus.SYMBOL_NOT_FOUND
    )


def test_invented_evidence_id_fails_without_touching_the_filesystem(
    store: SourceStore, bundle: EvidenceBundle, provenance: list[Provenance]
) -> None:
    """T-03-10: an id the bundle never issued is refused before any I/O."""
    region = store.make_region("src/main.c", 3, 5)
    bundle.add_region(region, EvidenceKind.PRIMARY_CODE, provenance)
    resolver = CitationResolver(store, bundle)

    store.stats.reset()
    resolution = resolver.resolve(Citation.from_evidence("ev-1234567890abcdef"))
    assert resolution.status is ResolutionStatus.UNKNOWN_EVIDENCE_ID
    assert store.stats.disk_reads == 0
    assert store.stats.stat_calls == 0
    assert "never issued" in resolution.detail
    _record(resolution.status, "unknown_evidence_id")


def test_evidence_id_that_looks_plausible_still_fails(
    store: SourceStore, bundle: EvidenceBundle, provenance: list[Provenance]
) -> None:
    """A content address for a real region that was never handed out."""
    from caudit.model.ids import evidence_id as compute_id

    issued = store.make_region("src/main.c", 3, 5)
    bundle.add_region(issued, EvidenceKind.PRIMARY_CODE, provenance)
    never_issued = store.make_region("src/main.c", 1, 2)
    plausible = compute_id(never_issued, str(EvidenceKind.PRIMARY_CODE))

    resolver = CitationResolver(store, bundle)
    store.stats.reset()
    resolution = resolver.resolve(Citation.from_evidence(plausible))
    assert resolution.status is ResolutionStatus.UNKNOWN_EVIDENCE_ID
    assert store.stats.disk_reads == 0


@pytest.mark.parametrize("path", ["../../etc/passwd", "/etc/passwd", "src/../../outside.c"])
def test_paths_outside_the_repository_are_refused(resolver: CitationResolver, path: str) -> None:
    """T-03-11."""
    resolution = resolver.resolve(Citation(path=path, start_line=1, end_line=1))
    assert resolution.status is ResolutionStatus.OUTSIDE_REPO_ROOT
    _record(resolution.status, "outside_repo_root")


def test_symlink_escaping_the_repository_is_caught_after_realpath(
    repo: Path, store: SourceStore, bundle: EvidenceBundle
) -> None:
    """T-03-12: the path itself is clean; only realpath reveals the escape."""
    outside = repo.parent / "outside-secret.txt"
    outside.write_text("secret\n", encoding="utf-8")
    link = repo / "src" / "link.c"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform guard
        pytest.skip("symlinks are not available here")

    resolver = CitationResolver(store, bundle)
    resolution = resolver.resolve(Citation(path="src/link.c", start_line=1, end_line=1))
    assert resolution.status is ResolutionStatus.OUTSIDE_REPO_ROOT
    assert ".." not in "src/link.c"  # nothing about the literal path was suspicious


def test_excluded_file_is_not_citable(tmp_path: Path, provenance: list[Provenance]) -> None:
    """T-03-13 through the resolver: exclusion beats existence."""
    (tmp_path / "third_party").mkdir()
    (tmp_path / "third_party" / "dep.c").write_bytes(b"int x = 1;\n")
    store = SourceStore(tmp_path, revision="r", exclude_globs=["third_party/**"])
    resolver = CitationResolver(store, EvidenceBundle(store))
    resolution = resolver.resolve(Citation(path="third_party/dep.c", start_line=1, end_line=1))
    assert resolution.status is ResolutionStatus.EXCLUDED_FILE
    assert resolution.observed == "third_party/**"
    _record(resolution.status, "excluded_file")


def test_file_above_the_cap_resolves_as_too_large(tmp_path: Path) -> None:
    """T-03-14 through the resolver."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "big.c").write_bytes(b"x" * 4096)
    store = SourceStore(tmp_path, revision="r", max_file_bytes=1024)
    resolver = CitationResolver(store, EvidenceBundle(store))
    resolution = resolver.resolve(Citation(path="src/big.c", start_line=1, end_line=1))
    assert resolution.status is ResolutionStatus.FILE_TOO_LARGE
    assert resolution.observed == "4096"
    _record(resolution.status, "file_too_large")


def test_valid_citation_resolves(
    store: SourceStore, bundle: EvidenceBundle, provenance: list[Provenance]
) -> None:
    region = store.make_region("src/main.c", 3, 5)
    evidence_id = bundle.add_region(region, EvidenceKind.PRIMARY_CODE, provenance)
    resolver = CitationResolver(store, bundle)
    resolution = resolver.resolve(Citation.from_evidence(evidence_id, symbol="copy_in"))
    assert resolution.status is ResolutionStatus.OK
    assert resolution.ok
    assert resolution.region is not None
    assert resolution.region.sha256 == region.sha256
    _record(resolution.status, "ok")


def test_empty_citation_is_refused(resolver: CitationResolver) -> None:
    resolution = resolver.resolve(Citation())
    assert resolution.status is ResolutionStatus.BYTE_RANGE_INVALID
    assert "neither an evidence id nor a path" in resolution.detail


def test_resolution_rate_helper() -> None:
    assert CitationResolver.resolution_rate([]) == 1.0


def test_every_resolution_status_is_exercised() -> None:
    """T-03-17: enumerated check, so a new status cannot arrive untested."""
    missing = set(ResolutionStatus) - set(PRODUCED)
    assert not missing, f"no test produces: {sorted(str(s) for s in missing)}"


def test_every_produced_resolution_carries_a_detail(
    store: SourceStore, bundle: EvidenceBundle
) -> None:
    """AC-03-2: each status names what was expected versus observed."""
    resolver = CitationResolver(store, bundle)
    for citation in (
        Citation(path="src/nope.c", start_line=1, end_line=1),
        Citation(path="src/main.c", start_line=900, end_line=901),
        Citation(path="src/main.c", start_line=9, end_line=2),
        Citation(path="../x.c", start_line=1, end_line=1),
        Citation.from_evidence("ev-nope"),
    ):
        resolution = resolver.resolve(citation)
        assert resolution.detail, f"{resolution.status} produced no detail"

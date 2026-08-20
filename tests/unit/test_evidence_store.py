"""Part 03 store tests: T-03-01 … T-03-04, T-03-13 … T-03-16.

The independent read in T-03-01 is deliberately written a different way from
the implementation — raw ``open`` plus ``seek``, no shared helper — so a bug
in the byte mapping cannot cancel itself out.
"""

from __future__ import annotations

import hashlib
import random
import shutil
from pathlib import Path

import pytest

from caudit.errors import RegionError
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.filters import PathFilter, glob_to_regex
from caudit.evidence.hashing import EMPTY_SHA256, hash_bytes, hashes_match
from caudit.evidence.resolver import Citation, CitationResolver, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.model.evidence import EvidenceKind, Provenance
from caudit.model.finding import LimitationKind
from tests.conftest import FIXTURE_ROOT

ENCODING_FIXTURES = ("lf.c", "crlf.c", "tabs.c", "latin1.c")


@pytest.fixture
def encoding_repo(tmp_path: Path) -> Path:
    shutil.copytree(FIXTURE_ROOT / "encoding", tmp_path / "src")
    return tmp_path


@pytest.fixture
def encoding_store(encoding_repo: Path) -> SourceStore:
    return SourceStore(encoding_repo, revision="fixture", max_file_bytes=1_000_000)


def _independent_read(path: Path, start: int, end: int) -> bytes:
    """A second implementation of "give me these bytes", on purpose."""
    with path.open("rb") as handle:
        handle.seek(start)
        return handle.read(end - start)


@pytest.mark.parametrize("name", ENCODING_FIXTURES)
def test_read_region_matches_an_independent_read(
    name: str, encoding_repo: Path, encoding_store: SourceStore
) -> None:
    """T-03-01: 20 random regions per fixture, byte for byte."""
    disk_path = encoding_repo / "src" / name
    line_count = encoding_store.line_count(f"src/{name}")
    rng = random.Random(f"seed-{name}")
    for _ in range(20):
        start = rng.randint(1, line_count)
        end = rng.randint(start, line_count)
        region = encoding_store.make_region(f"src/{name}", start, end)
        assert encoding_store.read_region(region) == _independent_read(
            disk_path, region.start_byte, region.end_byte
        )
        assert (
            region.sha256
            == hashlib.sha256(
                _independent_read(disk_path, region.start_byte, region.end_byte)
            ).hexdigest()
        )


def test_file_without_trailing_newline_still_has_a_final_line(
    encoding_repo: Path, encoding_store: SourceStore
) -> None:
    """T-03-02: the last line is readable and its range ends at EOF."""
    name = "src/no_trailing_newline.c"
    assert encoding_store.line_count(name) == 3
    region = encoding_store.make_region(name, 3, 3)
    data = encoding_store.read_region(region)
    assert data == b"int c = 3;"
    assert region.end_byte == (encoding_repo / "src" / "no_trailing_newline.c").stat().st_size


def test_crlf_regions_include_the_carriage_return(
    encoding_store: SourceStore,
) -> None:
    """T-03-03: lines 3-5 keep the \\r, and hash differently from the LF twin."""
    crlf = encoding_store.make_region("src/crlf.c", 3, 5)
    lf = encoding_store.make_region("src/lf.c", 3, 5)
    body = encoding_store.read_region(crlf)
    assert b"\r\n" in body
    assert body.count(b"\r") == 3
    assert crlf.sha256 != lf.sha256
    assert encoding_store.read_region(lf).replace(b"\n", b"\r\n") == body


def test_tab_indentation_hashes_differently_from_spaces(
    encoding_store: SourceStore,
) -> None:
    """No whitespace normalisation: in C a tab can matter."""
    tabs = encoding_store.make_region("src/tabs.c", 5, 5)
    lf = encoding_store.make_region("src/lf.c", 5, 5)
    assert tabs.sha256 != lf.sha256


def test_non_utf8_bytes_hash_verbatim_and_display_without_raising(
    encoding_store: SourceStore,
) -> None:
    """T-03-04: a 0x80 byte survives hashing; the display path is lossy-safe."""
    region = encoding_store.make_region("src/latin1.c", 2, 2)
    data = encoding_store.read_region(region)
    assert b"\x80" in data
    assert region.sha256 == hash_bytes(data)
    rendered = encoding_store.decode_for_display(data)
    assert "�" in rendered  # replacement character, not an exception


def test_empty_file_has_one_empty_line(encoding_store: SourceStore) -> None:
    assert encoding_store.line_count("src/empty.c") == 1
    region = encoding_store.make_region("src/empty.c", 1, 1)
    assert encoding_store.read_region(region) == b""
    assert region.sha256 == EMPTY_SHA256


def test_line_and_byte_round_trip_exactly(encoding_store: SourceStore) -> None:
    """T-03-08 (line/byte half): every line maps back to itself."""
    for name in (*ENCODING_FIXTURES, "no_trailing_newline.c"):
        path = f"src/{name}"
        for line in range(1, encoding_store.line_count(path) + 1):
            start, end = encoding_store.line_span_to_bytes(path, line, line)
            assert encoding_store.byte_to_line(path, start) == line
            if end > start:
                assert encoding_store.byte_to_line(path, end - 1) == line


def test_regions_tile_the_file_without_gaps(encoding_store: SourceStore) -> None:
    path = "src/lf.c"
    count = encoding_store.line_count(path)
    joined = b"".join(
        encoding_store.read_region(encoding_store.make_region(path, line, line))
        for line in range(1, count + 1)
    )
    whole = encoding_store.read_region(encoding_store.make_region(path, 1, count))
    assert joined == whole


def test_invalid_line_spans_raise_rather_than_truncate(
    encoding_store: SourceStore,
) -> None:
    with pytest.raises(RegionError, match="invalid line span"):
        encoding_store.line_span_to_bytes("src/lf.c", 0, 3)
    with pytest.raises(RegionError, match="invalid line span"):
        encoding_store.line_span_to_bytes("src/lf.c", 5, 2)
    with pytest.raises(RegionError, match="lines"):
        encoding_store.line_span_to_bytes("src/lf.c", 1, 9999)


def test_enclosing_lines_clamps_to_the_file(encoding_store: SourceStore) -> None:
    region = encoding_store.enclosing_lines("src/lf.c", line=2, before=10, after=500)
    assert region.start_line == 1
    assert region.end_line == encoding_store.line_count("src/lf.c")
    # Within the file, the window is exactly as requested.
    inner = encoding_store.enclosing_lines("src/lf.c", line=6, before=2, after=2)
    assert (inner.start_line, inner.end_line) == (4, 8)
    with pytest.raises(RegionError):
        encoding_store.enclosing_lines("src/lf.c", line=999, before=1, after=1)


def test_file_above_the_cap_is_refused_and_recorded_as_a_limitation(
    tmp_path: Path,
) -> None:
    """T-03-14."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "big.c").write_bytes(b"x" * 5000)
    store = SourceStore(tmp_path, revision="r", max_file_bytes=1000)
    with pytest.raises(RegionError, match="above the"):
        store.load("src/big.c")
    kinds = [limitation.kind for limitation in store.limitations]
    assert LimitationKind.FILE_TOO_LARGE in kinds


def test_excluded_file_is_recognised_even_though_it_exists(tmp_path: Path) -> None:
    """T-03-13: exclusion is not cosmetic."""
    (tmp_path / "third_party").mkdir()
    (tmp_path / "third_party" / "dep.c").write_bytes(b"int x;\n")
    store = SourceStore(tmp_path, revision="r", exclude_globs=["third_party/**"])
    assert store.is_excluded("third_party/dep.c")
    assert store.exclusion_pattern("third_party/dep.c") == "third_party/**"
    assert not store.is_excluded("src/app.c")


def test_cache_avoids_a_second_disk_read(encoding_store: SourceStore) -> None:
    encoding_store.load("src/lf.c")
    assert encoding_store.stats.disk_reads == 1
    encoding_store.load("src/lf.c")
    assert encoding_store.stats.disk_reads == 1
    assert encoding_store.stats.cache_hits == 1


def test_cache_is_invalidated_when_the_file_changes(
    encoding_repo: Path, encoding_store: SourceStore
) -> None:
    first = encoding_store.make_region("src/lf.c", 5, 5)
    (encoding_repo / "src" / "lf.c").write_bytes(b"int changed = 1;\n" * 20)
    second = encoding_store.make_region("src/lf.c", 5, 5)
    assert first.sha256 != second.sha256
    assert encoding_store.stats.disk_reads == 2


def test_zoom_returns_byte_identical_originals(
    encoding_store: SourceStore, provenance: list[Provenance]
) -> None:
    """T-03-15: this is what makes compression reversible in part 09."""
    bundle = EvidenceBundle(encoding_store)
    ids = []
    originals = {}
    for name, start, end in (("lf.c", 1, 3), ("crlf.c", 2, 4), ("latin1.c", 1, 2)):
        region = encoding_store.make_region(f"src/{name}", start, end)
        evidence_id = bundle.add_region(region, EvidenceKind.PRIMARY_CODE, provenance)
        ids.append(evidence_id)
        originals[evidence_id] = encoding_store.read_region(region)
    for evidence_id in ids:
        assert bundle.zoom(evidence_id) == originals[evidence_id]
        assert bundle.verify(evidence_id)
    assert len(bundle) == 3
    assert set(bundle.ids()) == set(ids)


def test_zoom_of_an_unissued_id_raises(encoding_store: SourceStore) -> None:
    bundle = EvidenceBundle(encoding_store)
    with pytest.raises(KeyError):
        bundle.zoom("ev-neverissued00")
    assert "ev-neverissued00" not in bundle
    assert bundle.get("ev-neverissued00") is None


def test_resolution_is_deterministic_over_100_shuffled_repeats(
    encoding_store: SourceStore, provenance: list[Provenance]
) -> None:
    """T-03-16: identical status and detail every time."""
    bundle = EvidenceBundle(encoding_store)
    region = encoding_store.make_region("src/lf.c", 3, 6)
    evidence_id = bundle.add_region(region, EvidenceKind.PRIMARY_CODE, provenance)
    resolver = CitationResolver(encoding_store, bundle)

    citations = [
        Citation.from_evidence(evidence_id),
        Citation.from_region(region, symbol="add"),
        Citation(path="src/missing.c", start_line=1, end_line=1),
    ]
    rng = random.Random(7)
    baseline = [(r.status, r.detail) for r in resolver.resolve_all(citations)]
    for _ in range(100):
        shuffled = citations[:]
        rng.shuffle(shuffled)
        by_citation = {
            c: (r.status, r.detail)
            for c, r in zip(shuffled, resolver.resolve_all(shuffled), strict=True)
        }
        assert [by_citation[c] for c in citations] == baseline


def test_hashes_match_is_case_insensitive() -> None:
    assert hashes_match("a" * 64, "A" * 64)
    assert not hashes_match("a" * 64, "b" * 64)


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("third_party/**", "third_party/a/b.c", True),
        ("third_party/**", "src/third_party.c", False),
        ("**/node_modules/**", "a/b/node_modules/x.js", True),
        ("**/node_modules/**", "node_modules/x.js", True),
        ("**/*.pb.cc", "gen/proto/a.pb.cc", True),
        ("*.c", "src/a.c", False),  # '*' must not cross a separator
        ("src/*.c", "src/a.c", True),
        ("src/?.c", "src/a.c", True),
        ("src/?.c", "src/ab.c", False),
    ],
)
def test_glob_semantics(pattern: str, path: str, expected: bool) -> None:
    assert bool(glob_to_regex(pattern).match(path)) is expected
    assert PathFilter([pattern]).is_excluded(path) is expected


def test_resolution_status_enum_values_are_stable() -> None:
    """These strings appear in reports and in part 11's routing."""
    assert ResolutionStatus.OK.value == "ok"
    assert ResolutionStatus.HASH_MISMATCH.value == "hash_mismatch"

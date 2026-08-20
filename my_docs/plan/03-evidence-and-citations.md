# Part 03 — Evidence store and citation resolution

## Goal

Build the component that makes the spec's core principle enforceable: *use AI to connect and explain evidence, not to invent it.* Every quotation of source is read from disk at a known revision, hashed, and addressed by content. Every citation is resolved back against that store, and resolution failures carry a typed reason.

This is the smallest part of the system with the largest consequence. If it is right, no downstream component can report a claim about code that does not exist.

## Depends on / Unlocks

- **Depends on:** 02.
- **Unlocks:** 04, 09, 11.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/evidence/store.py` | `SourceStore` — revision-pinned reads, byte↔line mapping, caching |
| `src/caudit/evidence/hashing.py` | Region hashing, normalization rules |
| `src/caudit/evidence/resolver.py` | `CitationResolver` v1 and `Resolution` |
| `src/caudit/evidence/bundle.py` | `EvidenceBundle` — the set handed to a model, and the only thing citable |
| `tests/unit/test_evidence_*.py`, `tests/adversarial/test_citations.py`, `tests/fixtures/encoding/` | This part's tests |

## Interfaces

```python
class SourceStore:
    def __init__(self, repo_root: Path, revision: str, max_file_bytes: int) -> None: ...
    def read_region(self, region: SourceRegion) -> bytes:
        """Exact bytes. Raises RegionError rather than returning a truncated read."""
    def line_span_to_bytes(self, path: PurePosixPath, start: int, end: int) -> tuple[int, int]: ...
    def hash_region(self, region: SourceRegion) -> str: ...
    def enclosing_lines(self, path: PurePosixPath, line: int, before: int, after: int) -> SourceRegion: ...

class ResolutionStatus(StrEnum):
    OK = "ok"
    MISSING_FILE = "missing_file"
    OUTSIDE_REPO_ROOT = "outside_repo_root"
    EXCLUDED_FILE = "excluded_file"
    LINE_OUT_OF_RANGE = "line_out_of_range"
    BYTE_RANGE_INVALID = "byte_range_invalid"
    HASH_MISMATCH = "hash_mismatch"
    SYMBOL_NOT_FOUND = "symbol_not_found"        # v1: textual; v2 (part 06): index-backed
    UNKNOWN_EVIDENCE_ID = "unknown_evidence_id"
    FILE_TOO_LARGE = "file_too_large"

@dataclass(frozen=True)
class Resolution:
    status: ResolutionStatus
    citation: Citation
    detail: str                    # human-readable, safe to put in a report
    observed: str | None           # e.g. actual hash, actual line count

class CitationResolver:
    def __init__(self, store: SourceStore, bundle: EvidenceBundle) -> None: ...
    def resolve(self, citation: Citation) -> Resolution: ...
    def resolve_all(self, citations: Iterable[Citation]) -> list[Resolution]: ...

class EvidenceBundle:
    """The closed world a model is allowed to cite."""
    def add(self, item: EvidenceItem) -> str: ...          # returns evidence_id
    def get(self, evidence_id: str) -> EvidenceItem | None: ...
    def zoom(self, evidence_id: str) -> bytes:             # exact original bytes
        ...
```

## Invariants

- **The resolver returns a reason, never a bool.** Part 11 routes on the reason and part 08 prints it. A boolean would collapse "the file does not exist" and "the file changed since the scan" into one indistinguishable failure.
- **Evidence IDs are content-addressed.** `evidence_id = sha256(kind || path || byte_range || content_hash)`. A model can only cite an ID it was given; an invented ID fails as `UNKNOWN_EVIDENCE_ID` before any file access happens.
- **Hashes are over exact bytes.** No whitespace normalization, no line-ending normalization, no encoding conversion. Two files that differ by a single tab are different evidence, because in C they can be.
- **Reads are pinned to the scanned revision.** If the working tree changes mid-run, resolution fails with `HASH_MISMATCH` rather than quietly quoting new content.
- **Path containment is checked after resolution**, using the real path, so symlinks that escape the repository root are caught (`OUTSIDE_REPO_ROOT`), not just literal `..` segments.
- **Excluded files are not citable.** A file filtered out as third-party or generated (part 05) resolves as `EXCLUDED_FILE` even though it exists on disk — otherwise exclusion is cosmetic.

## Encoding and offset rules

C and C++ sources are not reliably UTF-8, and offsets are where this kind of code goes wrong quietly:

- Files are handled as **bytes**. Line splitting is on `\n`; a preceding `\r` belongs to the line's bytes, so CRLF files produce correct byte ranges.
- Line numbers are 1-based inclusive on both ends, matching Clang and SARIF. Byte ranges are half-open `[start, end)`. Both are stored so a mismatch between them is detectable.
- A file with no trailing newline still has a final line.
- Invalid UTF-8 is preserved verbatim; decoding for display uses `errors="replace"` and never feeds the hash.
- Files above `max_file_bytes` resolve as `FILE_TOO_LARGE` and are recorded as a `Limitation`, not skipped silently.

## Acceptance criteria

- **AC-03-1** `read_region` returns exactly the bytes in the region, verified against an independent `dd`-style read, for LF, CRLF, tab-indented, and non-UTF-8 fixtures.
- **AC-03-2** Every `ResolutionStatus` is produced by at least one test, and each carries a `detail` naming what was expected versus observed.
- **AC-03-3** A citation to a file that does not exist, a line past EOF, an inverted or negative byte range, or a stale hash never returns `OK`.
- **AC-03-4** A citation to an `evidence_id` not in the bundle fails without touching the filesystem.
- **AC-03-5** A symlink inside the repository pointing outside it resolves as `OUTSIDE_REPO_ROOT`.
- **AC-03-6** `zoom(evidence_id)` returns bytes identical to the original region — this is what makes compression reversible in part 09.
- **AC-03-7** Resolution is deterministic: the same citation against the same revision always yields the same status and detail.
- **AC-03-8** Line/byte round-tripping is exact for all fixture encodings, including a file whose last line lacks a newline.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-03-01 | unit | `lf.c`, `crlf.c`, `tabs.c`, `latin1.c` | `read_region` bytes equal an independent read for 20 random regions each | AC-03-1, AC-03-8 |
| T-03-02 | unit | File without trailing newline | Last line readable; byte range ends at EOF | AC-03-8 |
| T-03-03 | unit | `crlf.c` | Region for lines 3–5 includes the `\r` bytes; hash differs from the LF twin | AC-03-1 |
| T-03-04 | unit | `latin1.c` with a 0x80 byte | Hash computed over raw bytes; display path does not raise | AC-03-1 |
| T-03-05 | adversarial | Citation to `src/does_not_exist.c` | `MISSING_FILE`, detail names the path | AC-03-2, AC-03-3 |
| T-03-06 | adversarial | Citation to line 5000 of a 40-line file | `LINE_OUT_OF_RANGE`, observed reports 40 | AC-03-2, AC-03-3 |
| T-03-07 | adversarial | `end_line` < `start_line`; negative `start_byte` | `BYTE_RANGE_INVALID` for both | AC-03-3 |
| T-03-08 | adversarial | Region hashed, file then modified, citation resolved | `HASH_MISMATCH`, observed carries the new hash | AC-03-2, AC-03-3 |
| T-03-09 | adversarial | Off-by-one: region claims lines 10–12, symbol actually on 13 | `SYMBOL_NOT_FOUND` | AC-03-2, AC-03-3 |
| T-03-10 | adversarial | `evidence_id` of a plausible but never-issued region | `UNKNOWN_EVIDENCE_ID`; filesystem access counter is zero | AC-03-4 |
| T-03-11 | adversarial | `../../etc/passwd` and an absolute path | `OUTSIDE_REPO_ROOT` (model layer also rejects, per T-02-14) | AC-03-5 |
| T-03-12 | adversarial | Symlink `src/link.c` → `/etc/hosts` | `OUTSIDE_REPO_ROOT` after realpath | AC-03-5 |
| T-03-13 | unit | File matched by an exclusion glob | `EXCLUDED_FILE`, not `OK` | AC-03-2 |
| T-03-14 | unit | File larger than `max_file_bytes` | `FILE_TOO_LARGE`, `Limitation` recorded | AC-03-2 |
| T-03-15 | unit | Bundle with three items | `zoom` returns byte-identical original for each | AC-03-6 |
| T-03-16 | unit | Same citation resolved 100 times, shuffled order | Identical status and detail every time | AC-03-7 |
| T-03-17 | unit | — | Every `ResolutionStatus` member appears in at least one test above (enumerated check) | AC-03-2 |
| T-03-18 | perf | 2000-file fixture tree | Region reads use the cache; wall time under the recorded budget | — |

## Out of scope and risks

- Symbol resolution here is textual: it checks that the named identifier appears within the cited region. Index-backed symbol and call-edge resolution arrives in part 06 and upgrades the same `ResolutionStatus` values.
- **Risk:** textual symbol matching produces false `OK` results (a comment mentioning the name). Accepted for v1 because part 06 replaces it before any LLM output is verified in part 11; recorded here so the weakness is not forgotten.
- **Risk:** hashing every region on large repositories is expensive. Mitigation: cache by `(path, mtime, size)` with content verification on hit; T-03-18 tracks the budget.

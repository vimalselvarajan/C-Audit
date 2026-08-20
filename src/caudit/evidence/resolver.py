"""Citation resolution, version 1.

The resolver returns a **reason**, never a bool. Part 11 routes on the
reason and part 08 prints it; a boolean would collapse "the file does not
exist" and "the file changed since the scan" into one indistinguishable
failure, and those two demand different responses from a reader.

A :class:`Citation` holds raw, unvalidated primitives on purpose. This is a
trust boundary: the thing being resolved may have been produced by a model,
so it must be possible to *represent* an absolute path or an inverted range
long enough to reject it with a specific reason. The model layer rejects the
same shapes at construction (part 02); both checks are wanted.

Symbol resolution here is textual — it checks that the named identifier
appears within the cited region. That accepts a comment mentioning the name,
which part 06 fixes with an index-backed check against the same
``ResolutionStatus`` values.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath

from caudit.errors import RegionError
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.hashing import hash_bytes, hashes_match
from caudit.evidence.store import SourceStore
from caudit.model.finding import ReviewReason
from caudit.model.source import SourceRegion, normalize_repo_path

__all__ = [
    "REASON_FOR_STATUS",
    "Citation",
    "CitationResolver",
    "Resolution",
    "ResolutionStatus",
]


class ResolutionStatus(StrEnum):
    """Why a citation did or did not resolve."""

    OK = "ok"
    MISSING_FILE = "missing_file"
    OUTSIDE_REPO_ROOT = "outside_repo_root"
    EXCLUDED_FILE = "excluded_file"
    LINE_OUT_OF_RANGE = "line_out_of_range"
    BYTE_RANGE_INVALID = "byte_range_invalid"
    HASH_MISMATCH = "hash_mismatch"
    SYMBOL_NOT_FOUND = "symbol_not_found"
    UNKNOWN_EVIDENCE_ID = "unknown_evidence_id"
    FILE_TOO_LARGE = "file_too_large"


#: Resolver verdict → the review reason a reader sees. Coarser on purpose:
#: parts 08 and 11 both route on :class:`~caudit.model.finding.ReviewReason`,
#: and three different ways for a region to be unreadable are one decision to a
#: router. The exact status travels alongside in the
#: :class:`Resolution`, so nothing is lost.
#:
#: It lives here rather than in either consumer because it is a property of
#: :class:`ResolutionStatus`. Two copies of a routing table is how a router
#: develops a bug that only one of its callers has.
REASON_FOR_STATUS: dict[ResolutionStatus, ReviewReason] = {
    ResolutionStatus.MISSING_FILE: ReviewReason.MISSING_FILE,
    ResolutionStatus.HASH_MISMATCH: ReviewReason.HASH_MISMATCH,
    # A line past the end of the file is not a file that changed. Reporting it
    # as a hash mismatch would send a reader looking for an edit; the citation
    # simply does not name anything.
    ResolutionStatus.LINE_OUT_OF_RANGE: ReviewReason.CITATION_UNRESOLVED,
    ResolutionStatus.SYMBOL_NOT_FOUND: ReviewReason.SYMBOL_UNRESOLVED,
    ResolutionStatus.OUTSIDE_REPO_ROOT: ReviewReason.EVIDENCE_UNAVAILABLE,
    ResolutionStatus.EXCLUDED_FILE: ReviewReason.EVIDENCE_UNAVAILABLE,
    ResolutionStatus.FILE_TOO_LARGE: ReviewReason.EVIDENCE_UNAVAILABLE,
    ResolutionStatus.BYTE_RANGE_INVALID: ReviewReason.SCHEMA_VIOLATION,
    ResolutionStatus.UNKNOWN_EVIDENCE_ID: ReviewReason.SCHEMA_VIOLATION,
}


@dataclass(frozen=True)
class Citation:
    """A claim that points at source.

    Either an ``evidence_id`` issued by a bundle, or a raw location. Raw
    fields are deliberately untyped-ish (``path`` is ``str``) so that hostile
    values survive long enough to be named in a rejection.
    """

    evidence_id: str | None = None
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_byte: int | None = None
    end_byte: int | None = None
    sha256: str | None = None
    symbol: str | None = None
    label: str = ""
    #: A call edge the claim asserts: "``caller`` calls ``callee`` here".
    #: Only an index-backed resolver can check it — see
    #: :attr:`CitationResolver.verifies_call_edges`, which a caller should
    #: assert before treating an unflagged edge as verified.
    caller: str | None = None
    callee: str | None = None

    @classmethod
    def from_region(
        cls, region: SourceRegion, symbol: str | None = None, label: str = ""
    ) -> Citation:
        return cls(
            path=str(region.path),
            start_line=region.start_line,
            end_line=region.end_line,
            start_byte=region.start_byte,
            end_byte=region.end_byte,
            sha256=region.sha256,
            symbol=symbol,
            label=label,
        )

    @classmethod
    def from_evidence(
        cls, evidence_id: str, symbol: str | None = None, label: str = ""
    ) -> Citation:
        return cls(evidence_id=evidence_id, symbol=symbol, label=label)

    def describe(self) -> str:
        if self.evidence_id:
            return self.evidence_id
        if self.path is None:
            return "<empty citation>"
        if self.start_line is None:
            return self.path
        if self.end_line is None or self.end_line == self.start_line:
            return f"{self.path}:{self.start_line}"
        return f"{self.path}:{self.start_line}-{self.end_line}"


@dataclass(frozen=True)
class Resolution:
    """The verdict on one citation, with what was expected versus observed."""

    status: ResolutionStatus
    citation: Citation
    detail: str
    observed: str | None = None
    region: SourceRegion | None = field(default=None, compare=False)

    @property
    def ok(self) -> bool:
        return self.status is ResolutionStatus.OK


class CitationResolver:
    """Resolves citations against one revision and one bundle."""

    #: False here: v1 has no call graph, so a citation asserting a call edge
    #: passes through unchecked. Part 06's resolver sets it True. Part 11
    #: asserts it before letting an edge claim count as verified.
    verifies_call_edges: bool = False

    def __init__(self, store: SourceStore, bundle: EvidenceBundle) -> None:
        self._store = store
        self._bundle = bundle

    # ---------------------------------------------------------------- public

    def resolve(self, citation: Citation) -> Resolution:
        """Resolve one citation. Deterministic: same input, same verdict."""
        if citation.evidence_id is not None:
            return self._resolve_by_evidence_id(citation)
        return self._resolve_raw(citation)

    def resolve_all(self, citations: Iterable[Citation]) -> list[Resolution]:
        return [self.resolve(citation) for citation in citations]

    @staticmethod
    def resolution_rate(resolutions: Sequence[Resolution]) -> float:
        """Fraction that resolved. An empty set resolves vacuously (1.0)."""
        if not resolutions:
            return 1.0
        return sum(1 for r in resolutions if r.ok) / len(resolutions)

    # --------------------------------------------------------------- private

    def _resolve_by_evidence_id(self, citation: Citation) -> Resolution:
        """An id the bundle never issued fails before any file is opened."""
        evidence_id = citation.evidence_id or ""
        item = self._bundle.get(evidence_id)
        if item is None:
            return Resolution(
                status=ResolutionStatus.UNKNOWN_EVIDENCE_ID,
                citation=citation,
                detail=(
                    f"evidence id {evidence_id!r} was never issued for this run; a "
                    "model may only cite ids it was given"
                ),
                observed=f"{len(self._bundle)} ids in bundle",
            )
        expanded = Citation(
            path=str(item.region.path),
            start_line=item.region.start_line,
            end_line=item.region.end_line,
            start_byte=item.region.start_byte,
            end_byte=item.region.end_byte,
            sha256=item.region.sha256,
            symbol=citation.symbol or (item.symbol.name if item.symbol else None),
            label=citation.label,
        )
        resolved = self._resolve_raw(expanded)
        return Resolution(
            status=resolved.status,
            citation=citation,
            detail=resolved.detail,
            observed=resolved.observed,
            region=resolved.region,
        )

    def _resolve_raw(self, citation: Citation) -> Resolution:
        if citation.path is None:
            return Resolution(
                status=ResolutionStatus.BYTE_RANGE_INVALID,
                citation=citation,
                detail="citation names neither an evidence id nor a path",
            )

        # 1. Containment. Checked before anything touches the filesystem.
        try:
            relative = normalize_repo_path(citation.path)
        except ValueError as exc:
            return Resolution(
                status=ResolutionStatus.OUTSIDE_REPO_ROOT,
                citation=citation,
                detail=f"path is not repository-relative: {exc}",
                observed=citation.path,
            )
        real = self._store.real_path(relative)
        if real is None:
            return Resolution(
                status=ResolutionStatus.OUTSIDE_REPO_ROOT,
                citation=citation,
                detail=(f"{relative} resolves outside the repository root {self._store.repo_root}"),
                observed=str(relative),
            )

        # 2. Structural validity of the range itself.
        invalid = self._range_problem(citation)
        if invalid is not None:
            return Resolution(
                status=ResolutionStatus.BYTE_RANGE_INVALID,
                citation=citation,
                detail=invalid,
                observed=(
                    f"lines {citation.start_line}-{citation.end_line}, "
                    f"bytes {citation.start_byte}-{citation.end_byte}"
                ),
            )

        # 3. Exclusion beats existence: an excluded file is not citable even
        #    though it is sitting right there on disk.
        pattern = self._store.exclusion_pattern(relative)
        if pattern is not None:
            return Resolution(
                status=ResolutionStatus.EXCLUDED_FILE,
                citation=citation,
                detail=f"{relative} is excluded by the filter '{pattern}' and is not citable",
                observed=pattern,
            )

        if not real.is_file():
            return Resolution(
                status=ResolutionStatus.MISSING_FILE,
                citation=citation,
                detail=f"{relative} does not exist at revision {self._store.revision}",
                observed=str(relative),
            )

        size = real.stat().st_size
        if size > self._store.max_file_bytes:
            return Resolution(
                status=ResolutionStatus.FILE_TOO_LARGE,
                citation=citation,
                detail=(
                    f"{relative} is {size} bytes, above the "
                    f"{self._store.max_file_bytes}-byte cap; recorded as a limitation"
                ),
                observed=str(size),
            )

        # 4. Lines within the file.
        try:
            line_count = self._store.line_count(relative)
        except RegionError as exc:  # pragma: no cover - covered by the size guard
            return Resolution(
                status=ResolutionStatus.MISSING_FILE,
                citation=citation,
                detail=str(exc),
                observed=str(relative),
            )
        start_line = citation.start_line or 1
        end_line = citation.end_line or start_line
        if end_line > line_count:
            return Resolution(
                status=ResolutionStatus.LINE_OUT_OF_RANGE,
                citation=citation,
                detail=(f"{relative} has {line_count} lines; citation names line {end_line}"),
                observed=str(line_count),
            )

        # 5. Byte range against the real file, then the hash.
        expected_start, expected_end = self._store.line_span_to_bytes(
            relative, start_line, end_line
        )
        start_byte = citation.start_byte if citation.start_byte is not None else expected_start
        end_byte = citation.end_byte if citation.end_byte is not None else expected_end
        file_size = self._store.load(relative).size
        if end_byte > file_size:
            return Resolution(
                status=ResolutionStatus.BYTE_RANGE_INVALID,
                citation=citation,
                detail=(f"byte range ends at {end_byte} but {relative} is {file_size} bytes"),
                observed=str(file_size),
            )

        # The placeholder hash keeps the model valid; the real one is computed
        # from disk immediately below. A malformed hash in the citation is
        # compared as text, so it fails as a mismatch rather than crashing.
        region = SourceRegion(
            path=relative,
            start_line=start_line,
            end_line=end_line,
            start_byte=start_byte,
            end_byte=end_byte,
            sha256=hash_bytes(b""),
        )
        actual = hash_bytes(self._store.read_region(region))
        if citation.sha256 is not None and not hashes_match(citation.sha256, actual):
            return Resolution(
                status=ResolutionStatus.HASH_MISMATCH,
                citation=citation,
                detail=(
                    f"{relative}:{start_line}-{end_line} changed since it was cited "
                    f"(expected {citation.sha256[:12]}…, found {actual[:12]}…)"
                ),
                observed=actual,
            )

        verified = region.model_copy(update={"sha256": actual})

        # 6. Symbol presence.
        problem = self._check_symbol(citation, verified)
        if problem is not None:
            return problem

        return Resolution(
            status=ResolutionStatus.OK,
            citation=citation,
            detail=f"resolved {relative}:{start_line}-{end_line} at revision "
            f"{self._store.revision}",
            observed=actual,
            region=verified,
        )

    def _check_symbol(self, citation: Citation, region: SourceRegion) -> Resolution | None:
        """Is the cited symbol really at the cited region? ``None`` means yes.

        Textual in v1 — the identifier appears somewhere in those bytes — which
        a comment mentioning the name satisfies. Part 06 overrides this with an
        index-backed check that returns the same status values, so part 11 does
        not have to know which resolver ran.
        """
        if not citation.symbol:
            return None
        body = self._store.read_region(region)
        if _contains_identifier(body, citation.symbol):
            return None
        return Resolution(
            status=ResolutionStatus.SYMBOL_NOT_FOUND,
            citation=citation,
            detail=f"symbol {citation.symbol!r} does not appear in {region.describe()}",
            observed=region.describe(),
        )

    @staticmethod
    def _range_problem(citation: Citation) -> str | None:
        """Structural faults, checked before the file is consulted."""
        if citation.start_line is not None and citation.start_line < 1:
            return f"start_line {citation.start_line} is below 1"
        if citation.end_line is not None and citation.end_line < 1:
            return f"end_line {citation.end_line} is below 1"
        if (
            citation.start_line is not None
            and citation.end_line is not None
            and citation.end_line < citation.start_line
        ):
            return f"end_line {citation.end_line} precedes start_line {citation.start_line}"
        if citation.start_byte is not None and citation.start_byte < 0:
            return f"start_byte {citation.start_byte} is negative"
        if citation.end_byte is not None and citation.end_byte < 0:
            return f"end_byte {citation.end_byte} is negative"
        if (
            citation.start_byte is not None
            and citation.end_byte is not None
            and citation.end_byte < citation.start_byte
        ):
            return f"end_byte {citation.end_byte} precedes start_byte {citation.start_byte}"
        return None


def _contains_identifier(body: bytes, symbol: str) -> bool:
    """Whole-identifier match, so ``len`` does not match inside ``length``."""
    needle = symbol.encode("utf-8", errors="ignore")
    if not needle:
        return False
    start = 0
    while True:
        index = body.find(needle, start)
        if index == -1:
            return False
        before_ok = index == 0 or not _is_ident_byte(body[index - 1])
        after = index + len(needle)
        after_ok = after >= len(body) or not _is_ident_byte(body[after])
        if before_ok and after_ok:
            return True
        start = index + 1


def _is_ident_byte(byte: int) -> bool:
    return byte == 0x5F or chr(byte).isalnum()


def relative_path(value: str) -> PurePosixPath:
    """Public helper so callers do not import the model's validator directly."""
    return normalize_repo_path(value)

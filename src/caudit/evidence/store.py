"""Revision-pinned source reads, byte↔line mapping, and caching.

C and C++ sources are not reliably UTF-8, and byte offsets are where this
kind of code goes wrong quietly. The rules, applied everywhere:

* Files are handled as **bytes**. Line splitting is on ``\\n``; a preceding
  ``\\r`` belongs to the line's bytes, so CRLF files produce correct ranges.
* Lines are 1-based inclusive on both ends (Clang and SARIF agree). Byte
  ranges are half-open ``[start, end)`` and *include* the terminating newline
  of the last line, so consecutive regions tile the file exactly.
* A file with no trailing newline still has a final line.
* Invalid UTF-8 is preserved verbatim. Decoding for display uses
  ``errors="replace"`` and never feeds a hash.
* Files above ``max_file_bytes`` are refused, recorded as a limitation, and
  never silently skipped.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from caudit.errors import RegionError
from caudit.evidence.filters import PathFilter
from caudit.evidence.hashing import hash_bytes
from caudit.model.finding import Limitation, LimitationKind
from caudit.model.source import SourceRegion, normalize_repo_path

__all__ = ["FileStats", "SourceStore", "StoreStats"]


@dataclass
class StoreStats:
    """Counters. Tests assert on these to prove no filesystem access happened."""

    disk_reads: int = 0
    cache_hits: int = 0
    stat_calls: int = 0

    def reset(self) -> None:
        self.disk_reads = 0
        self.cache_hits = 0
        self.stat_calls = 0


@dataclass(frozen=True)
class FileStats:
    """Cache key material plus the derived line index."""

    size: int
    mtime_ns: int
    #: Included in the cache key because it moves on any write, closing the
    #: window where a same-size rewrite lands inside one mtime tick.
    ctime_ns: int
    data: bytes
    line_starts: tuple[int, ...] = field(repr=False)

    @property
    def line_count(self) -> int:
        return len(self.line_starts)


def _index_lines(data: bytes) -> tuple[int, ...]:
    """Byte offset of every line start.

    An empty file has one (empty) line. A trailing newline does not create a
    phantom line after it.
    """
    starts = [0]
    position = data.find(b"\n")
    while position != -1 and position + 1 < len(data):
        starts.append(position + 1)
        position = data.find(b"\n", position + 1)
    return tuple(starts)


class SourceStore:
    """Reads files at the scanned revision, exactly."""

    def __init__(
        self,
        repo_root: Path,
        revision: str,
        max_file_bytes: int = 2_000_000,
        *,
        exclude_globs: Iterable[str] = (),
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.revision = revision
        self.max_file_bytes = max_file_bytes
        self.filter = PathFilter(exclude_globs)
        self.stats = StoreStats()
        self._cache: dict[PurePosixPath, FileStats] = {}
        self._limitations: list[Limitation] = []

    # ------------------------------------------------------------- location

    def real_path(self, path: PurePosixPath | str) -> Path | None:
        """The on-disk path, or ``None`` if it escapes the repository root.

        Containment is checked after ``realpath``, so a symlink that points
        outside the tree is caught even though its own path is clean.
        """
        try:
            relative = normalize_repo_path(path)
        except ValueError:
            return None
        candidate = (self.repo_root / Path(*relative.parts)).resolve()
        if candidate != self.repo_root and self.repo_root not in candidate.parents:
            return None
        return candidate

    def is_excluded(self, path: PurePosixPath | str) -> bool:
        return self.filter.is_excluded(path)

    def exclusion_pattern(self, path: PurePosixPath | str) -> str | None:
        return self.filter.matching_pattern(path)

    # ----------------------------------------------------------------- reads

    def load(self, path: PurePosixPath | str) -> FileStats:
        """Read and index a file, honouring the cache and the size cap."""
        relative = normalize_repo_path(path)
        real = self.real_path(relative)
        if real is None:
            raise RegionError(f"path escapes the repository root: {relative}")

        self.stats.stat_calls += 1
        try:
            stat = real.stat()
        except OSError as exc:
            raise RegionError(f"cannot stat {relative}: {exc}") from exc
        if not real.is_file():
            raise RegionError(f"not a regular file: {relative}")

        cached = self._cache.get(relative)
        if cached is not None and (cached.size, cached.mtime_ns, cached.ctime_ns) == (
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
        ):
            self.stats.cache_hits += 1
            return cached

        if stat.st_size > self.max_file_bytes:
            self.record_limitation(
                LimitationKind.FILE_TOO_LARGE,
                f"{relative} is {stat.st_size} bytes, above the {self.max_file_bytes}-byte cap",
                affects=str(relative),
            )
            raise RegionError(
                f"{relative} is {stat.st_size} bytes, above the {self.max_file_bytes}-byte limit"
            )

        self.stats.disk_reads += 1
        data = real.read_bytes()
        entry = FileStats(
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            ctime_ns=stat.st_ctime_ns,
            data=data,
            line_starts=_index_lines(data),
        )
        self._cache[relative] = entry
        return entry

    def exists(self, path: PurePosixPath | str) -> bool:
        real = self.real_path(path)
        self.stats.stat_calls += 1
        return real is not None and real.is_file()

    def file_size(self, path: PurePosixPath | str) -> int:
        real = self.real_path(path)
        if real is None:
            raise RegionError(f"path escapes the repository root: {path}")
        self.stats.stat_calls += 1
        return real.stat().st_size

    def line_count(self, path: PurePosixPath | str) -> int:
        return self.load(path).line_count

    # ---------------------------------------------------------- byte mapping

    def line_span_to_bytes(
        self, path: PurePosixPath | str, start: int, end: int
    ) -> tuple[int, int]:
        """Half-open byte range covering lines ``start``..``end`` inclusive."""
        if start < 1 or end < start:
            raise RegionError(f"invalid line span {start}-{end} for {path}")
        entry = self.load(path)
        if end > entry.line_count:
            raise RegionError(f"{path} has {entry.line_count} lines; requested line {end}")
        start_byte = entry.line_starts[start - 1]
        end_byte = entry.line_starts[end] if end < entry.line_count else len(entry.data)
        return start_byte, end_byte

    def byte_to_line(self, path: PurePosixPath | str, offset: int) -> int:
        """The 1-based line containing ``offset``."""
        entry = self.load(path)
        if offset < 0 or offset > len(entry.data):
            raise RegionError(f"byte offset {offset} outside {path}")
        return bisect_right(entry.line_starts, offset)

    # --------------------------------------------------------------- regions

    def read_region(self, region: SourceRegion) -> bytes:
        """Exact bytes, or :class:`RegionError` — never a truncated read."""
        entry = self.load(region.path)
        if region.end_byte > len(entry.data):
            raise RegionError(
                f"{region.describe()} ends at byte {region.end_byte} but the file is "
                f"{len(entry.data)} bytes"
            )
        return entry.data[region.start_byte : region.end_byte]

    def hash_region(self, region: SourceRegion) -> str:
        """sha256 of the region's current bytes on disk."""
        return hash_bytes(self.read_region(region))

    def make_region(
        self, path: PurePosixPath | str, start_line: int, end_line: int
    ) -> SourceRegion:
        """Build a region for a line span, with its hash filled in from disk."""
        relative = normalize_repo_path(path)
        start_byte, end_byte = self.line_span_to_bytes(relative, start_line, end_line)
        entry = self.load(relative)
        return SourceRegion(
            path=relative,
            start_line=start_line,
            end_line=end_line,
            start_byte=start_byte,
            end_byte=end_byte,
            sha256=hash_bytes(entry.data[start_byte:end_byte]),
        )

    def enclosing_lines(
        self, path: PurePosixPath | str, line: int, before: int, after: int
    ) -> SourceRegion:
        """A region around ``line``, clamped to the file rather than failing."""
        entry = self.load(path)
        start = max(1, line - before)
        end = min(entry.line_count, line + after)
        if line > entry.line_count:
            raise RegionError(f"{path} has {entry.line_count} lines; requested line {line}")
        return self.make_region(path, start, end)

    def decode_for_display(self, data: bytes) -> str:
        """Lossy decode for reports only. Never feeds a hash."""
        return data.decode("utf-8", errors="replace")

    # ----------------------------------------------------------- limitations

    def record_limitation(
        self, kind: LimitationKind, detail: str, affects: str | None = None
    ) -> Limitation:
        limitation = Limitation(kind=kind, detail=detail, affects=affects)
        if limitation not in self._limitations:
            self._limitations.append(limitation)
        return limitation

    @property
    def limitations(self) -> list[Limitation]:
        """Blind spots this store hit. Carried into the report, not dropped."""
        return list(self._limitations)

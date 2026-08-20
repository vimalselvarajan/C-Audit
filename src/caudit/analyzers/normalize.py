"""Analyzer output → :class:`~caudit.model.candidate.Candidate`.

Three analyzers, three native formats, one candidate stream. This module is
the only place that turns a parsed diagnostic into a candidate, so the rules
below hold no matter which tool spoke:

* **Paths are made repository-relative**, and a diagnostic pointing outside the
  tree produces no candidate. A system header is not part of the scanned
  revision and nothing citable can be built from it.
* **Every region is hashed from the bytes on disk** through part 03's store, so
  a candidate's citation resolves by construction rather than by assertion.
* **The analyzer's own text survives verbatim.** ``Candidate.message`` is what
  the tool said; the normalized form is derived on demand. Notes, control-flow
  steps, and suggested fixes are preserved in the provenance detail, because
  paraphrasing at intake would make provenance unverifiable later.
* **A rule the profile does not know is still a candidate**, with
  ``suggested_cwe=[]``. Dropping it would hide a newly added upstream check
  behind an empty report.

Nothing here decides whether a candidate is a real vulnerability.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath

from caudit.analyzers.profile import CheckProfile
from caudit.errors import RegionError
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceItem, EvidenceKind, Producer, Provenance
from caudit.model.source import SourceRegion, Symbol, normalize_repo_path

__all__ = [
    "DiagnosticSeverity",
    "Normalizer",
    "RawDiagnostic",
    "RawNote",
    "relative_to_repo",
]


class DiagnosticSeverity(StrEnum):
    """Severity as the analyzer stated it. Mapped, never inferred."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    REMARK = "remark"

    @classmethod
    def parse(cls, value: str) -> DiagnosticSeverity:
        """Map a tool's own word onto this scale, defaulting to ``warning``.

        SARIF says ``error``/``warning``/``note``/``none``; Clang says
        ``error``/``fatal error``/``warning``/``note``/``remark``. Everything
        that is not recognisably one of those is a warning, which is the
        weakest claim available — an unknown severity must not be promoted.
        """
        text = value.strip().lower()
        if "fatal" in text or text == "error":
            return cls.ERROR
        if text == "note":
            return cls.NOTE
        if text == "remark":
            return cls.REMARK
        return cls.WARNING


@dataclass(frozen=True)
class RawNote:
    """One supporting location an analyzer attached to a diagnostic.

    A note is context, never a candidate of its own: promoting notes would
    report one defect several times and inflate every count downstream.
    """

    path: str
    line: int
    message: str = ""
    column: int = 0
    end_line: int | None = None
    #: ``control_flow_step`` for an ordered SARIF ``codeFlow`` step,
    #: ``supporting_code`` for a plain note.
    kind: EvidenceKind = EvidenceKind.SUPPORTING_CODE

    @property
    def last_line(self) -> int:
        return self.end_line if self.end_line and self.end_line >= self.line else self.line


@dataclass(frozen=True)
class RawDiagnostic:
    """One diagnostic, parsed out of a tool's native format.

    Deliberately primitive: paths are still whatever the tool printed, which
    may be absolute, may point at a system header, and may not exist. The
    normalizer is where those become repository-relative or vanish.
    """

    producer: Producer
    tool_name: str
    tool_version: str
    rule_id: str
    message: str
    path: str
    line: int
    column: int = 0
    end_line: int | None = None
    severity: DiagnosticSeverity = DiagnosticSeverity.WARNING
    #: Plain notes, in the order the tool emitted them.
    notes: tuple[RawNote, ...] = ()
    #: Ordered control-flow steps. Order is the evidence; it is never sorted.
    flow: tuple[RawNote, ...] = ()
    #: A suggested edit, recorded as text. C Audit never applies a fix.
    fix: str | None = None
    #: The translation unit the run covered, for provenance.
    unit: PurePosixPath | None = None

    @property
    def last_line(self) -> int:
        return self.end_line if self.end_line and self.end_line >= self.line else self.line


def relative_to_repo(
    path: str, repo_root: Path, *, base: Path | None = None
) -> PurePosixPath | None:
    """Repository-relative form of a path an analyzer printed, or ``None``.

    ``None`` means "outside the scanned tree" — a system header, a generated
    file in the build directory, an absolute path from another checkout. It is
    not an error: it is the boundary of what can be cited.
    """
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_absolute() and base is not None:
        candidate = base / candidate
    try:
        resolved = candidate.resolve()
        return PurePosixPath(resolved.relative_to(repo_root.resolve()).as_posix())
    except (OSError, ValueError):
        pass
    # A relative path the tool printed against the repository root itself.
    try:
        return normalize_repo_path(path)
    except ValueError:
        return None


@dataclass
class NormalizeStats:
    """What normalization dropped, and why. Read by the caller, not silent."""

    outside_repo: int = 0
    unreadable_region: int = 0
    paths_outside_repo: set[str] = field(default_factory=set)


class Normalizer:
    """Turns parsed diagnostics into candidates against one revision."""

    def __init__(
        self,
        *,
        store: SourceStore,
        profile: CheckProfile,
        index: Index | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self._store = store
        self._profile = profile
        self._index = index
        self._repo_root = repo_root or store.repo_root
        self.stats = NormalizeStats()

    @property
    def store(self) -> SourceStore:
        """The revision-pinned store every region is hashed against."""
        return self._store

    @property
    def repo_root(self) -> Path:
        return self._repo_root

    @property
    def profile(self) -> CheckProfile:
        return self._profile

    # ---------------------------------------------------------------- public

    def to_candidates(
        self, diagnostics: Iterable[RawDiagnostic], *, base: Path | None = None
    ) -> list[Candidate]:
        """Normalize a batch, dropping only what cannot be cited at all."""
        built = [self.to_candidate(item, base=base) for item in diagnostics]
        return [candidate for candidate in built if candidate is not None]

    def to_candidate(
        self, diagnostic: RawDiagnostic, *, base: Path | None = None
    ) -> Candidate | None:
        """One candidate, or ``None`` when its location is not in the tree."""
        relative = relative_to_repo(diagnostic.path, self._repo_root, base=base)
        if relative is None:
            self.stats.outside_repo += 1
            self.stats.paths_outside_repo.add(diagnostic.path)
            return None
        region = self._region(relative, diagnostic.line, diagnostic.last_line)
        if region is None:
            self.stats.unreadable_region += 1
            return None

        provenance = Provenance(
            producer=diagnostic.producer,
            tool_name=diagnostic.tool_name,
            tool_version=diagnostic.tool_version,
            rule_id=diagnostic.rule_id or None,
            detail=_detail(diagnostic),
        )
        symbol, enclosing = self._enclosing(relative, region.start_line)
        return Candidate.create(
            region=region,
            message=diagnostic.message,
            provenance=[provenance],
            suggested_cwe=self._profile.cwe_for(diagnostic.rule_id),
            symbol=symbol,
            enclosing_region=enclosing,
            evidence=self._evidence(diagnostic, provenance, base=base),
        )

    # --------------------------------------------------------------- private

    def _evidence(
        self, diagnostic: RawDiagnostic, provenance: Provenance, *, base: Path | None
    ) -> list[EvidenceItem]:
        """Flow steps first, in order, then plain notes.

        Order is preserved exactly as the analyzer emitted it: a control-flow
        path read out of sequence is a different argument from the one the
        analyzer made.
        """
        items: list[EvidenceItem] = []
        seen: set[str] = set()
        for note in (*diagnostic.flow, *diagnostic.notes):
            relative = relative_to_repo(note.path, self._repo_root, base=base)
            if relative is None:
                continue
            region = self._region(relative, note.line, note.last_line)
            if region is None:
                continue
            item = EvidenceItem.create(kind=note.kind, region=region, provenance=[provenance])
            if item.evidence_id in seen:
                continue
            seen.add(item.evidence_id)
            items.append(item)
        return items

    def _region(self, path: PurePosixPath, start: int, end: int) -> SourceRegion | None:
        """A hashed whole-line region, or ``None`` when the file cannot be read.

        Whole lines, matching part 06's index regions, so a citation resolved
        against one cannot disagree with the other.
        """
        if start < 1:
            return None
        try:
            return self._store.make_region(path, start, max(start, end))
        except (RegionError, ValueError):
            return None

    def _enclosing(
        self, path: PurePosixPath, line: int
    ) -> tuple[Symbol | None, SourceRegion | None]:
        """The containing function, when the index can prove one.

        Both halves or neither: a symbol name with no region that contains it
        is an assertion, and part 02 refuses to treat that as evidence.
        """
        if self._index is None:
            return None, None
        symbol = self._index.enclosing_function(path, line)
        if symbol is None or symbol.definition is None:
            return None, None
        return symbol.as_model_symbol(), symbol.definition


def _detail(diagnostic: RawDiagnostic) -> str:
    """Provenance detail: severity, the tool's notes, and any suggested fix.

    Everything here is the analyzer's own text, kept verbatim. The fix is
    recorded as a string and never applied — the MVP recommends, it does not
    modify code.
    """
    parts = [f"severity={diagnostic.severity.value}"]
    for note in diagnostic.flow:
        parts.append(f"step {note.path}:{note.line}: {note.message}".rstrip(": "))
    for note in diagnostic.notes:
        parts.append(f"note {note.path}:{note.line}: {note.message}".rstrip(": "))
    if diagnostic.fix:
        parts.append(f"suggested fix (recorded, not applied): {diagnostic.fix}")
    return "; ".join(parts)


def sort_diagnostics(diagnostics: Sequence[RawDiagnostic]) -> list[RawDiagnostic]:
    """Total order over raw diagnostics, so parsing order cannot leak out."""
    return sorted(
        diagnostics,
        key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message),
    )

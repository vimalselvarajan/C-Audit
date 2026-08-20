"""The index itself: build it, serialize it, cache it between runs.

Three properties this module exists to guarantee.

**Reproducible.** The same sources and the same arguments produce the same
USRs, the same regions, and the same serialized bytes. Everything is sorted by
a total key, nothing that varies between runs (durations, worker scheduling,
whether an entry came from cache) reaches the snapshot, and a unit's *outcome*
is recorded rather than its provenance.

**Incremental.** A unit is keyed by its arguments and the content of every
in-repository file it read, itself included. An unchanged unit is not
re-parsed; a unit whose header changed is. The include list comes from the
previous parse, which is why it is stored with the entry rather than derived.

**Honest.** A unit that failed, timed out, or crashed is recorded as such and
keeps its limitation. The index knows the difference between "this function
has no callers" and "this function has no callers that could be resolved".
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from caudit.config.loader import Config
from caudit.evidence.hashing import hash_bytes
from caudit.index.graphs import (
    CallEdge,
    CallGraph,
    CallQuery,
    IncludeEdge,
    IncludeGraph,
    MacroExpansion,
    MacroTable,
    ReferenceTable,
)
from caudit.index.limits import LimitationLog
from caudit.index.parser import (
    ParseRequest,
    ParseResult,
    ParseStatus,
    ensure_libclang,
    libclang_version,
    parse_request,
)
from caudit.index.symbols import Symbol, SymbolTable
from caudit.index.workers import Execute, run_parallel, run_serial
from caudit.intake.plan import ScanPlan, TranslationUnit
from caudit.logging import get_logger
from caudit.model.finding import Limitation
from caudit.model.source import SourceRegion, normalize_repo_path

__all__ = [
    "INDEX_FORMAT_VERSION",
    "Index",
    "IndexCache",
    "IndexSnapshot",
    "IndexStats",
    "UnitRecord",
    "UnitStatus",
    "build_index",
]

log = get_logger(__name__)

#: Bumped when the serialized shape changes. Cache entries written by a
#: different version are ignored rather than misread. ``2`` added the
#: global-reference graph part 09 needs.
INDEX_FORMAT_VERSION: Final = "2"


class UnitStatus(StrEnum):
    """What became of one translation unit — its outcome, not its provenance.

    Deliberately not :class:`~caudit.index.parser.ParseStatus`: whether a unit
    was parsed this run or served from cache is a fact about the run, not about
    the index, and letting it into the snapshot would make two identical runs
    serialize differently.
    """

    INDEXED = "indexed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"


_OUTCOMES: Final[dict[ParseStatus, UnitStatus]] = {
    ParseStatus.PARSED: UnitStatus.INDEXED,
    ParseStatus.REUSED: UnitStatus.INDEXED,
    ParseStatus.FAILED: UnitStatus.FAILED,
    ParseStatus.TIMED_OUT: UnitStatus.TIMED_OUT,
    ParseStatus.CRASHED: UnitStatus.CRASHED,
}


class UnitRecord(BaseModel):
    """One translation unit's place in the index."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file: PurePosixPath
    status: UnitStatus
    #: Repository-relative path → sha256 for every in-repo file the unit read.
    input_hashes: dict[str, str] = Field(default_factory=dict)

    @property
    def indexed(self) -> bool:
        return self.status is UnitStatus.INDEXED


@dataclass
class IndexStats:
    """Run-scoped counters. Never serialized: they describe the run, not the tree."""

    parsed: int = 0
    reused: int = 0
    failed: int = 0
    timed_out: int = 0
    crashed: int = 0
    seconds: float = 0.0

    def record(self, result: ParseResult) -> None:
        if result.status is ParseStatus.PARSED:
            self.parsed += 1
        elif result.status is ParseStatus.REUSED:
            self.reused += 1
        elif result.status is ParseStatus.FAILED:
            self.failed += 1
        elif result.status is ParseStatus.TIMED_OUT:
            self.timed_out += 1
        else:
            self.crashed += 1
        self.seconds += result.duration_seconds

    def describe(self) -> str:
        return (
            f"{self.parsed} parsed, {self.reused} reused, {self.failed} failed, "
            f"{self.timed_out} timed out, {self.crashed} crashed"
        )


class IndexSnapshot(BaseModel):
    """The whole index as data. Two identical trees serialize identically."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = INDEX_FORMAT_VERSION
    #: Recorded because two libclang majors can disagree on an AST.
    libclang: str
    revision: str
    units: list[UnitRecord] = Field(default_factory=list)
    symbols: list[Symbol] = Field(default_factory=list)
    calls: list[CallEdge] = Field(default_factory=list)
    macros: list[MacroExpansion] = Field(default_factory=list)
    includes: list[IncludeEdge] = Field(default_factory=list)
    type_references: list[tuple[str, str]] = Field(default_factory=list)
    global_references: list[tuple[str, str]] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)


class Index:
    """Everything the pipeline asks the compiler about, answered from data.

    Two deliberate departures from the interface sketched in the plan, both in
    the direction of the "unresolved is not absent" invariant:

    * :meth:`callers_of` and :meth:`callees_of` return a
      :class:`~caudit.index.graphs.CallQuery` rather than a bare list, so the
      unresolved indirect calls travel with the answer;
    * :meth:`enclosing_function` consults definitions only, so a prototype in a
      header never masquerades as the body a claim needs.
    """

    def __init__(
        self,
        *,
        revision: str,
        repo_root: Path,
        libclang: str = "",
        units: Iterable[UnitRecord] = (),
        symbols: Iterable[Symbol] = (),
        calls: Iterable[CallEdge] = (),
        macros: Iterable[MacroExpansion] = (),
        includes: Iterable[IncludeEdge] = (),
        type_references: Iterable[tuple[str, str]] = (),
        global_references: Iterable[tuple[str, str]] = (),
        limitations: Iterable[Limitation] = (),
        stats: IndexStats | None = None,
    ) -> None:
        self.revision = revision
        self.repo_root = repo_root
        self.libclang = libclang or libclang_version()
        self.stats = stats or IndexStats()
        self._units = {str(record.file): record for record in units}
        self._symbols = SymbolTable(symbols)
        self._calls = CallGraph(calls)
        self._macros = MacroTable(macros)
        self._includes = IncludeGraph(includes)
        self._types = ReferenceTable(type_references)
        self._globals = ReferenceTable(global_references)
        self._limitations = LimitationLog(limitations)

    # ------------------------------------------------------------ construction

    @classmethod
    def from_results(
        cls,
        results: Sequence[ParseResult],
        *,
        revision: str,
        repo_root: Path,
        libclang: str = "",
    ) -> Index:
        """Merge per-unit parse results into one index, deterministically."""
        stats = IndexStats()
        index = cls(revision=revision, repo_root=repo_root, libclang=libclang, stats=stats)
        for result in sorted(results, key=lambda item: str(item.file)):
            index._absorb(result)
            stats.record(result)
        return index

    def _absorb(self, result: ParseResult) -> None:
        self._units[str(result.file)] = UnitRecord(
            file=result.file,
            status=_OUTCOMES[result.status],
            input_hashes=dict(sorted(result.input_hashes.items())),
        )
        self._limitations.extend(result.limitations)
        if not result.ok:
            # A unit that did not parse contributes its limitation and nothing
            # else. Half a symbol table is worse than none: every claim built
            # on it would inherit the gap without naming it.
            return
        self._symbols.extend(result.symbols)
        self._calls.extend(result.calls)
        self._macros.extend(result.macros)
        self._includes.extend(result.includes)
        for symbol_usr, type_usr in result.type_references:
            self._types.add(symbol_usr, type_usr)
        for symbol_usr, variable_usr in result.global_references:
            self._globals.add(symbol_usr, variable_usr)

    @classmethod
    def from_snapshot(cls, snapshot: IndexSnapshot, *, repo_root: Path) -> Index:
        return cls(
            revision=snapshot.revision,
            repo_root=repo_root,
            libclang=snapshot.libclang,
            units=snapshot.units,
            symbols=snapshot.symbols,
            calls=snapshot.calls,
            macros=snapshot.macros,
            includes=snapshot.includes,
            type_references=snapshot.type_references,
            global_references=snapshot.global_references,
            limitations=snapshot.limitations,
        )

    # ------------------------------------------------------------------ lookup

    def symbol(self, usr: str) -> Symbol | None:
        return self._symbols.get(usr)

    def symbols_named(self, name: str) -> list[Symbol]:
        """Every symbol with that name — an overload set is not one symbol."""
        return self._symbols.named(name)

    def enclosing_function(self, path: PurePosixPath | str, line: int) -> Symbol | None:
        return self._symbols.enclosing_function(normalize_repo_path(path), line)

    def symbols_in(self, path: PurePosixPath | str) -> list[Symbol]:
        return self._symbols.in_file(normalize_repo_path(path))

    def callers_of(self, usr: str, depth: int = 1) -> CallQuery:
        return self._calls.callers_of(usr, depth)

    def callees_of(self, usr: str, depth: int = 1) -> CallQuery:
        return self._calls.callees_of(usr, depth)

    def has_call_edge(self, caller: str, callee: str) -> bool:
        return self._calls.has_edge(caller, callee)

    def call_edges(self) -> list[CallEdge]:
        return self._calls.edges()

    def types_referenced_by(self, usr: str) -> list[Symbol]:
        """Types this symbol mentions, as symbols — unknown USRs are dropped."""
        return self._resolve(self._types.of(usr))

    def globals_referenced_by(self, usr: str) -> list[Symbol]:
        """File-scope variables this symbol reads or writes, as symbols."""
        return self._resolve(self._globals.of(usr))

    def _resolve(self, usrs: list[str]) -> list[Symbol]:
        found = [self._symbols.get(usr) for usr in usrs]
        return [symbol for symbol in found if symbol is not None]

    def macros_expanded_in(self, region: SourceRegion) -> list[MacroExpansion]:
        return self._macros.expanded_in(region)

    def macros_named(self, name: str) -> list[MacroExpansion]:
        return self._macros.named(name)

    def includes(self, path: PurePosixPath | str) -> list[PurePosixPath]:
        return self._includes.includes(normalize_repo_path(path))

    def external_includes(self, path: PurePosixPath | str) -> list[str]:
        return self._includes.external_includes(normalize_repo_path(path))

    def limitations(self) -> list[Limitation]:
        return self._limitations.all()

    def record_limitation(self, limitation: Limitation) -> None:
        """Add a blind spot discovered outside the parse — the plan's, say."""
        self._limitations.add(limitation)

    # ------------------------------------------------------------------- units

    def units(self) -> list[UnitRecord]:
        return [self._units[key] for key in sorted(self._units)]

    def unit(self, path: PurePosixPath | str) -> UnitRecord | None:
        return self._units.get(str(normalize_repo_path(path)))

    def is_indexed(self, path: PurePosixPath | str) -> bool:
        """True only for a unit that parsed. A failed unit is not in the index."""
        record = self.unit(path)
        return record is not None and record.indexed

    def indexed_files(self) -> list[PurePosixPath]:
        return [record.file for record in self.units() if record.indexed]

    # ----------------------------------------------------------- serialization

    def to_snapshot(self) -> IndexSnapshot:
        return IndexSnapshot(
            libclang=self.libclang,
            revision=self.revision,
            units=self.units(),
            symbols=self._symbols.all(),
            calls=self._calls.edges(),
            macros=self._macros.all(),
            includes=self._includes.all(),
            type_references=self._types.pairs(),
            global_references=self._globals.pairs(),
            limitations=self._limitations.all(),
        )

    def to_json(self) -> str:
        """Deterministic JSON. Two builds over one tree produce equal bytes."""
        return self.to_snapshot().model_dump_json(indent=2) + "\n"

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        return path

    @classmethod
    def read(cls, path: Path, *, repo_root: Path) -> Index:
        snapshot = IndexSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
        return cls.from_snapshot(snapshot, repo_root=repo_root)

    def describe(self) -> str:
        indexed = len(self.indexed_files())
        return (
            f"{len(self._symbols)} symbols, {len(self._calls)} call edges, "
            f"{len(self._macros)} macro expansions across {indexed}/{len(self._units)} "
            "translation units"
        )


# ------------------------------------------------------------------------ cache


@dataclass
class IndexCache:
    """Per-unit parse results on disk, keyed by content.

    An entry is reused only when every in-repository file the unit read still
    hashes the same. That is stricter than a timestamp check and it is the
    reason a second run over an unchanged tree parses nothing at all.

    Headers *outside* the tree are not hashed — a toolchain upgrade does not
    invalidate the cache. The libclang version is in the key instead, which
    catches the case that actually changes ASTs.
    """

    directory: Path | None
    hits: int = 0
    misses: int = 0
    stale: int = 0
    libclang: str = field(default_factory=libclang_version)

    def key(self, request: ParseRequest) -> str:
        material = "\n".join([INDEX_FORMAT_VERSION, self.libclang, request.cache_key_material()])
        return hash_bytes(material.encode("utf-8"))

    def path_for(self, request: ParseRequest) -> Path | None:
        if self.directory is None:
            return None
        return self.directory / f"{self.key(request)}.json"

    def get(self, request: ParseRequest, *, repo_root: Path) -> ParseResult | None:
        """A reusable entry, or ``None`` when anything it read has changed."""
        path = self.path_for(request)
        if path is None or not path.is_file():
            self.misses += 1
            return None
        try:
            entry = ParseResult.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, json.JSONDecodeError):
            # A corrupt or older-format entry is a miss, never an error: the
            # cache is an optimisation and must never change what is reported.
            self.misses += 1
            return None
        if not _inputs_match(entry.input_hashes, repo_root):
            self.stale += 1
            return None
        self.hits += 1
        return entry.reused()

    def put(self, request: ParseRequest, result: ParseResult) -> None:
        path = self.path_for(request)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written through a temporary file so an interrupted run cannot leave a
        # half-written entry that the next run would read as truth.
        temporary = path.with_suffix(".tmp")
        temporary.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(path)


def _inputs_match(hashes: dict[str, str], repo_root: Path) -> bool:
    if not hashes:
        return False
    for relative, expected in hashes.items():
        candidate = repo_root / Path(*PurePosixPath(relative).parts)
        try:
            data = candidate.read_bytes()
        except OSError:
            return False
        if hash_bytes(data) != expected:
            return False
    return True


# ------------------------------------------------------------------------ build


def build_index(
    plan: ScanPlan,
    config: Config,
    *,
    cache_dir: Path | None = None,
    execute: Execute | None = None,
) -> Index:
    """Parse every selected translation unit and merge the results.

    Parse failures are recorded, never swallowed, and never fatal: one broken
    unit costs its own symbols, not the run. The scan plan's limitations travel
    into the index too, so a report has one place to ask what was not seen.
    """
    ensure_libclang()
    settings = config.index
    requests = [
        _request_for(unit, plan.repo_root, config)
        for unit in sorted(plan.units, key=lambda item: str(item.file))
    ]
    cache = IndexCache(directory=cache_dir or _configured_cache_dir(settings.cache_dir))

    reused: dict[int, ParseResult] = {}
    pending: list[tuple[int, ParseRequest]] = []
    for position, request in enumerate(requests):
        cached = cache.get(request, repo_root=plan.repo_root)
        if cached is None:
            pending.append((position, request))
        else:
            reused[position] = cached

    parsed = _run(
        [request for _, request in pending],
        settings_jobs=settings.jobs,
        timeout=settings.per_tu_timeout_seconds,
        in_process=settings.in_process,
        execute=execute or parse_request,
    )
    for (position, request), result in zip(pending, parsed, strict=True):
        reused[position] = result
        if result.status is ParseStatus.PARSED:
            cache.put(request, result)

    results = [reused[position] for position in sorted(reused)]
    index = Index.from_results(
        results, revision=plan.revision, repo_root=plan.repo_root, libclang=libclang_version()
    )
    # The plan's blind spots are the index's blind spots: a unit excluded from
    # the scan is just as invisible as one that failed to parse.
    for limitation in plan.limitations:
        index.record_limitation(limitation)
    log.info("index over %s: %s", plan.revision, index.describe())
    return index


def _run(
    requests: Sequence[ParseRequest],
    *,
    settings_jobs: int,
    timeout: float,
    in_process: bool,
    execute: Execute,
) -> list[ParseResult]:
    if not requests:
        return []
    if in_process:
        return run_serial(requests, execute)
    return run_parallel(requests, jobs=settings_jobs, timeout=timeout, execute=execute)


def _request_for(unit: TranslationUnit, repo_root: Path, config: Config) -> ParseRequest:
    return ParseRequest(
        file=unit.file,
        repo_root=repo_root,
        directory=unit.directory,
        arguments=tuple(unit.arguments),
        language=unit.language,
        resource_dir=config.index.resource_dir,
        max_file_bytes=config.token_budget.max_file_bytes,
    )


def _configured_cache_dir(value: str | None) -> Path | None:
    return Path(value).expanduser() if value else None

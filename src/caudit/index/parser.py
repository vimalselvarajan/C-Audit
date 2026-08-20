"""Parsing one translation unit with libclang.

The argument rule is narrow on purpose. A unit's argv arrives from the scan
plan verbatim; this module removes the compilation-only flags part 05 already
identified, adds ``-fsyntax-only``, and adds ``-working-directory=<dir>``
because a relative ``-I`` in the database means "relative to *that* entry's
directory" and libclang would otherwise resolve it against ours. Both additions
carry information the build already stated. Nothing else is added: no include
path, no macro definition, no language standard, no resource directory.

That last one has a visible consequence. The ``libclang`` wheel ships the
shared library without Clang's builtin headers, so a unit that includes
``<stddef.h>`` fails to parse until the user points ``index.resource_dir`` at a
real one. Failing loudly with that instruction is the honest outcome; quietly
searching the machine for a resource directory would be the tool guessing an
include path, which is the one thing this MVP promises never to do.

Parsing uses a detailed preprocessing record, so macro definitions and
expansions are cursors rather than lost text. A macro that hides a bounds check
is exactly the evidence the spec says must survive retrieval.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.errors import ToolchainError
from caudit.index import limits
from caudit.index.graphs import CallEdge, IncludeEdge, MacroExpansion
from caudit.index.symbols import Symbol
from caudit.intake.plan import Language, strip_compile_only_flags
from caudit.model.finding import Limitation

__all__ = [
    "ParseDiagnostic",
    "ParseRequest",
    "ParseResult",
    "ParseStatus",
    "clang_arguments",
    "libclang_version",
    "parse_request",
]

#: Clang emits errors at 3 and fatal errors at 4.
_ERROR_SEVERITY: Final = 3

#: ``'stddef.h' file not found`` — the shape every missing include takes.
_MISSING_INCLUDE_RE: Final = re.compile(r"'([^']+)' file not found")

#: Headers Clang ships itself. A failure on one of these is a missing resource
#: directory, not a missing include path in the build description, and the two
#: call for completely different fixes.
_BUILTIN_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "float.h",
        "inttypes.h",
        "iso646.h",
        "limits.h",
        "stdalign.h",
        "stdarg.h",
        "stdatomic.h",
        "stdbool.h",
        "stddef.h",
        "stdint.h",
        "stdnoreturn.h",
        "tgmath.h",
        "varargs.h",
    }
)


class ParseStatus(StrEnum):
    """How a translation unit's parse ended."""

    PARSED = "parsed"
    #: Errors in the source, a missing header, or a driver that refused it.
    FAILED = "failed"
    #: Stopped at the per-TU ceiling. Distinct from FAILED: nothing is known
    #: about the file, not even that it is broken.
    TIMED_OUT = "timed_out"
    #: The worker died without reporting. Also nothing known.
    CRASHED = "crashed"
    #: Served from the on-disk cache; not parsed this run.
    REUSED = "reused"


class ParseDiagnostic(BaseModel):
    """One Clang diagnostic, kept as data rather than as a printed line."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: int = Field(ge=0, le=4)
    message: str
    #: As Clang reports it — possibly a system header outside the tree.
    path: str | None = None
    line: int = Field(default=0, ge=0)

    @property
    def is_error(self) -> bool:
        return self.severity >= _ERROR_SEVERITY

    def describe(self) -> str:
        where = f"{self.path}:{self.line}: " if self.path else ""
        return f"{where}{self.message}"


@dataclass(frozen=True)
class ParseRequest:
    """Everything one parse needs. Picklable: it crosses a process boundary."""

    file: PurePosixPath
    repo_root: Path
    directory: Path
    #: The build's argv, verbatim, including argv[0].
    arguments: tuple[str, ...]
    language: Language
    resource_dir: str | None = None
    max_file_bytes: int = 2_000_000

    @property
    def absolute_file(self) -> Path:
        return self.repo_root / Path(*self.file.parts)

    def clang_arguments(self) -> list[str]:
        return clang_arguments(
            self.arguments, directory=self.directory, resource_dir=self.resource_dir
        )

    def cache_key_material(self) -> str:
        """What identifies this parse, before file contents are considered."""
        return "\n".join([str(self.file), str(self.language), *self.clang_arguments()[1:]])


def clang_arguments(
    arguments: Sequence[str], *, directory: Path, resource_dir: str | None = None
) -> list[str]:
    """The argv libclang gets: the build's, minus output flags, plus two.

    ``argv[0]`` is dropped — libclang treats a leading compiler name as an
    input file and reports it as an unused linker input.
    """
    kept = strip_compile_only_flags(arguments)
    body = kept[1:] if kept else []
    prefix = [f"-working-directory={directory}"]
    if resource_dir:
        prefix.append(f"-resource-dir={resource_dir}")
    return [*prefix, *body, "-fsyntax-only"]


class ParseResult(BaseModel):
    """What one translation unit contributed to the index.

    Serialized verbatim into the on-disk cache, so every field has to survive
    a JSON round trip — which is also what makes the second run of an
    unchanged tree byte-identical to the first.
    """

    model_config = ConfigDict(extra="forbid")

    file: PurePosixPath
    status: ParseStatus
    symbols: list[Symbol] = Field(default_factory=list)
    calls: list[CallEdge] = Field(default_factory=list)
    macros: list[MacroExpansion] = Field(default_factory=list)
    includes: list[IncludeEdge] = Field(default_factory=list)
    diagnostics: list[ParseDiagnostic] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)
    #: ``(symbol usr, type usr)`` pairs, sorted.
    type_references: list[tuple[str, str]] = Field(default_factory=list)
    #: ``(symbol usr, variable usr)`` pairs for file-scope variables only,
    #: sorted. Locals are excluded: they already live inside the region of the
    #: function that declares them, so retrieving one separately would be
    #: retrieving the same bytes twice.
    global_references: list[tuple[str, str]] = Field(default_factory=list)
    #: Repository-relative path → sha256 of every in-repo file this unit read,
    #: itself included. The cache reuses an entry only when all of them match.
    input_hashes: dict[str, str] = Field(default_factory=dict)
    duration_seconds: float = Field(default=0.0, ge=0.0)

    @property
    def ok(self) -> bool:
        """Whether this unit contributed to the index at all."""
        return self.status in (ParseStatus.PARSED, ParseStatus.REUSED)

    @property
    def first_error(self) -> ParseDiagnostic | None:
        return next((item for item in self.diagnostics if item.is_error), None)

    def reused(self) -> ParseResult:
        """The same result, marked as served from cache."""
        if self.status is not ParseStatus.PARSED:
            return self
        return self.model_copy(update={"status": ParseStatus.REUSED})


# --------------------------------------------------------------------- libclang


def _cindex() -> Any:
    """Import libclang, turning a missing wheel into a typed toolchain error."""
    try:
        from clang import cindex
    except ImportError as exc:  # pragma: no cover - the wheel is a hard dependency
        raise ToolchainError(
            "the libclang wheel is not importable, so nothing can be indexed",
            hint="pip install 'libclang>=18.1.1,<19' — see my_docs/guides/setup.md",
        ) from exc
    return cindex


_INDEX: Any = None


def _clang_index() -> Any:
    """One libclang Index per process, created on first use."""
    global _INDEX
    if _INDEX is None:
        cindex = _cindex()
        try:
            _INDEX = cindex.Index.create()
        except Exception as exc:  # pragma: no cover - platform-specific
            raise ToolchainError(
                f"libclang could not be loaded: {exc}",
                hint="Reinstall the wheel: pip install --force-reinstall libclang",
            ) from exc
    return _INDEX


def ensure_libclang() -> None:
    """Fail once, up front, rather than once per translation unit.

    Without this a missing or unloadable wheel surfaces as every unit crashing
    in a worker, which buries the one sentence the user needs under a thousand
    limitations.
    """
    _clang_index()


def libclang_version() -> str:
    """The wheel's version string, recorded in the index and the manifest."""
    from importlib import metadata

    try:
        return metadata.version("libclang")
    except metadata.PackageNotFoundError:  # pragma: no cover - hard dependency
        return "unknown"


def parse_request(request: ParseRequest) -> ParseResult:
    """Parse one translation unit. Never raises for a bad source file.

    A unit that does not parse comes back with ``status=FAILED`` and a
    limitation naming the file and the first error, because a run that aborts
    on one broken file tells the user less than a run that indexes the other
    nine hundred and says so.
    """
    started = time.monotonic()
    cindex = _cindex()
    # Function bodies are never skipped: they are where the call edges are.
    options = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    try:
        unit = _clang_index().parse(None, args=request.clang_arguments(), options=options)
    except Exception as exc:  # libclang raises TranslationUnitLoadError
        return ParseResult(
            file=request.file,
            status=ParseStatus.FAILED,
            limitations=[limits.parse_failed(request.file, f"libclang refused the unit: {exc}")],
            duration_seconds=time.monotonic() - started,
        )

    from caudit.index.traversal import Collector

    collector = Collector(request)
    result = collector.collect(unit)
    return result.model_copy(update={"duration_seconds": time.monotonic() - started})


# Cursor traversal and index construction live in caudit.index.traversal.

"""The validated output of repository intake.

A :class:`ScanPlan` is the answer to "what, exactly, is going to be analysed,
and what is not". Everything downstream reads it instead of re-deriving build
context, so it has to be complete, honest about its gaps, and identical across
two runs on unchanged inputs.

Two extensions to the interface in ``my_docs/plan/05-repository-intake.md``:

* :attr:`ScanPlan.overrides` records opt-ins that changed what was scanned
  (vendored code included, a below-floor coverage accepted). Without it, a
  report cannot say *why* it looked at third-party code, which AC-05-7 asks
  for.
* :attr:`TranslationUnit.parse_arguments` is a derived view, not stored state.
  ``arguments`` keeps the build's argv verbatim; the stripped form is computed
  where part 06 needs it, so nothing is silently dropped from the record.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from caudit.model.finding import Limitation
from caudit.model.source import normalize_repo_path

__all__ = [
    "UNKNOWN_REVISION",
    "Coverage",
    "ExclusionReason",
    "Language",
    "ScanPlan",
    "TranslationUnit",
]

#: Recorded when the tree is not a repository, or HEAD cannot be resolved.
#: Never blank and never a guess — a reader can tell a pinned run from an
#: unpinned one at a glance.
UNKNOWN_REVISION = "unknown"

Language = Literal["c", "c++"]


class ExclusionReason(StrEnum):
    """Why a translation unit in the database is not being analysed."""

    THIRD_PARTY = "third_party"
    GENERATED = "generated"
    TOO_LARGE = "too_large"
    NOT_SELECTED = "not_selected"
    MISSING_SOURCE = "missing_source"
    UNSUPPORTED_LANGUAGE = "unsupported_language"


#: Flags that only matter when producing object files or dependency lists.
#: Stripped before parsing; part 06 adds ``-fsyntax-only`` in their place.

#: Take a separate value argument, which is dropped with them.
_VALUED_COMPILE_ONLY = frozenset({"-o", "--output", "-MF", "-MT", "-MQ"})
#: Standalone.
_BARE_COMPILE_ONLY = frozenset({"-c", "-M", "-MM", "-MD", "-MMD", "-MG", "-MP"})
#: Joined forms such as ``-MFfoo.d``. The joined ``-ofoo.o`` spelling is left
#: alone: without a full driver flag table it is indistinguishable from
#: ``-object-file-name=…`` and friends, and a stray ``-o`` is inert once part
#: 06 parses with ``-fsyntax-only``. Guessing wrong here would drop a real flag.
_JOINED_COMPILE_ONLY = ("-MF", "-MT", "-MQ")


def strip_compile_only_flags(arguments: Sequence[str]) -> list[str]:
    """Drop ``-c``, ``-o <path>``, and dependency-generation flags.

    Everything else survives verbatim. This never *adds* a flag: the invariant
    for this part is that no include path, macro definition, or language
    standard is ever inferred, and an added flag is an inferred one.
    """
    kept: list[str] = []
    skip_next = False
    for argument in arguments:
        if skip_next:
            skip_next = False
            continue
        if argument in _VALUED_COMPILE_ONLY:
            skip_next = True
            continue
        if argument in _BARE_COMPILE_ONLY:
            continue
        if any(
            argument.startswith(flag) and len(argument) > len(flag) for flag in _JOINED_COMPILE_ONLY
        ):
            continue
        kept.append(argument)
    return kept


class TranslationUnit(BaseModel):
    """One compilable source file, with the exact command the build uses."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Repository-relative, POSIX-separated.
    file: PurePosixPath
    #: Absolute working directory the command runs in. Relative include paths
    #: in ``arguments`` are meaningless without it.
    directory: Path
    #: Normalized argv with response files expanded. Kept verbatim: this is
    #: the record of what the build actually does.
    arguments: list[str] = Field(min_length=1)
    output: str | None = None
    language: Language
    #: As written in ``-std=``, lowercased — ``c11``, ``gnu17``, ``c++20``.
    #: ``None`` means the build did not specify one and the compiler default
    #: applies; it is not a claim about which default.
    std: str | None = None

    @field_validator("file", mode="before")
    @classmethod
    def _validate_file(cls, value: object) -> str:
        # A string, not a PurePosixPath: see SourceRegion._validate_path for
        # why returning the object breaks JSON deserialization.
        if isinstance(value, PurePosixPath | str):
            return str(normalize_repo_path(value))
        raise ValueError(f"file must be a string or PurePosixPath, got {type(value).__name__}")

    @field_validator("directory")
    @classmethod
    def _validate_directory(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError(f"directory must be absolute, got {value}")
        return value

    @property
    def parse_arguments(self) -> list[str]:
        """``arguments`` minus compilation-only flags, for part 06's parser."""
        return strip_compile_only_flags(self.arguments)

    @property
    def compiler(self) -> str:
        """argv[0] as the build spells it — ``clang``, ``/usr/bin/gcc-13``."""
        return self.arguments[0]


class Coverage(BaseModel):
    """How much of the tree the compilation database actually describes.

    The ratio deliberately measures the *database*, not the scan: narrowing
    with ``--target`` reduces ``tus_selected`` and leaves ``coverage_ratio``
    alone, so an intentional narrowing never looks like an incomplete build
    description.

    Denominator: implementation files (``.c``, ``.cc``, ``.cpp``, …) present
    under the repository root and not excluded as vendored or generated.
    Headers are not counted — they have no entry of their own and are reached
    through the units that include them.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Raw entry count, as the file spells it. Selected plus excluded can be
    #: *fewer*: a multi-config build lists one file several times, and those
    #: extra configurations resolve to a single unit rather than to an
    #: exclusion. The gap is named in an ``ambiguous_build_config`` limitation.
    tus_in_database: int = Field(ge=0)
    tus_selected: int = Field(ge=0)
    tus_excluded: Mapping[ExclusionReason, int] = Field(default_factory=dict)
    source_files_in_tree: int = Field(ge=0)
    source_files_covered: int = Field(ge=0)
    coverage_ratio: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_arithmetic(self) -> Self:
        excluded = sum(self.tus_excluded.values())
        if self.tus_selected + excluded > self.tus_in_database:
            raise ValueError(
                f"selected ({self.tus_selected}) + excluded ({excluded}) exceeds "
                f"the {self.tus_in_database} entries in the database"
            )
        if self.source_files_covered > self.source_files_in_tree:
            raise ValueError(
                f"{self.source_files_covered} covered exceeds {self.source_files_in_tree} present"
            )
        return self

    @property
    def duplicate_configurations(self) -> int:
        """Entries dropped because another entry compiles the same file."""
        return self.tus_in_database - self.tus_selected - sum(self.tus_excluded.values())

    @property
    def is_complete(self) -> bool:
        return self.source_files_covered == self.source_files_in_tree

    def describe(self) -> str:
        return (
            f"{self.source_files_covered}/{self.source_files_in_tree} source files "
            f"({self.coverage_ratio:.2f}), {self.tus_selected}/{self.tus_in_database} "
            f"translation units selected"
        )


def compute_ratio(covered: int, present: int) -> float:
    """Covered over present, with an empty tree counting as fully covered."""
    if present <= 0:
        return 1.0
    return covered / present


class ScanPlan(BaseModel):
    """What will be analysed, what will not, and what could not be determined."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    repo_root: Path
    #: Git sha, or :data:`UNKNOWN_REVISION`. Pinned once, at the start.
    revision: str = Field(min_length=1)
    dirty: bool = False
    compile_commands_path: Path
    units: list[TranslationUnit] = Field(default_factory=list)
    #: Every excluded unit with its single attributed reason, sorted. Entries
    #: whose source lies outside the repository root are counted in
    #: :attr:`Coverage.tus_excluded` but cannot appear here — they have no
    #: repository-relative path — and are named in a limitation instead.
    excluded: list[tuple[PurePosixPath, ExclusionReason]] = Field(default_factory=list)
    coverage: Coverage
    limitations: list[Limitation] = Field(default_factory=list)
    #: Opt-ins that changed what was scanned, for the report to disclose.
    overrides: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_units(self) -> Self:
        if len(self.units) != self.coverage.tus_selected:
            raise ValueError(
                f"{len(self.units)} units but coverage reports {self.coverage.tus_selected}"
            )
        seen: set[PurePosixPath] = set()
        for unit in self.units:
            if unit.file in seen:
                raise ValueError(f"{unit.file} appears in more than one selected unit")
            seen.add(unit.file)
        return self

    def unit_for(self, path: PurePosixPath | str) -> TranslationUnit | None:
        wanted = normalize_repo_path(path)
        for unit in self.units:
            if unit.file == wanted:
                return unit
        return None

    def excluded_by(self, reason: ExclusionReason) -> list[PurePosixPath]:
        return [path for path, why in self.excluded if why is reason]

    def limitation_kinds(self) -> set[str]:
        return {str(limitation.kind) for limitation in self.limitations}

    @property
    def is_reproducible(self) -> bool:
        """A clean tree at a known revision. Anything else, the report says so."""
        return self.revision != UNKNOWN_REVISION and not self.dirty


def sort_units(units: Iterable[TranslationUnit]) -> list[TranslationUnit]:
    """Stable order by repository-relative path, so two runs agree."""
    return sorted(units, key=lambda unit: str(unit.file))


def sort_exclusions(
    excluded: Iterable[tuple[PurePosixPath, ExclusionReason]],
) -> list[tuple[PurePosixPath, ExclusionReason]]:
    return sorted(excluded, key=lambda item: (str(item[0]), str(item[1])))

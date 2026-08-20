"""Which files are in scope, and the single reason each excluded one is out.

Third-party and generated code are excluded by default and included only by
explicit opt-in. That is a scoping decision, not a safety one: a finding in
vendored code is usually not the user's to fix, and a finding in generated
code is a finding in the generator.

A file can match several rules at once — vendored *and* oversized, generated
*and* not selected. Exactly one reason is attributed, in a fixed order, so the
counts in :class:`~caudit.intake.plan.Coverage` add up and two runs agree.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Final

from caudit.evidence.filters import PathFilter
from caudit.intake.plan import ExclusionReason

__all__ = [
    "BANNER_SCAN_LINES",
    "DEFAULT_GENERATED_GLOBS",
    "GENERATED_BANNER",
    "THIRD_PARTY_DIRECTORIES",
    "ExclusionRules",
    "TargetSelector",
    "has_generated_banner",
    "is_generated_name",
    "is_third_party_path",
]

#: Directory names that mean "someone else's code" by near-universal convention.
#: Matched as a whole path segment, at any depth.
THIRD_PARTY_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        "third_party",
        "thirdparty",
        "3rdparty",
        "vendor",
        "vendored",
        "external",
        "extern",
        "build",
        "node_modules",
        "subprojects",
    }
)

#: Filename shapes produced by code generators.
DEFAULT_GENERATED_GLOBS: Final[tuple[str, ...]] = (
    "**/*.pb.cc",
    "**/*.pb.h",
    "**/*.pb-c.c",
    "**/*.pb-c.h",
    "**/moc_*.cpp",
    "**/moc_*.cc",
    "**/ui_*.h",
    "**/qrc_*.cpp",
    "**/*_generated.*",
    "**/*.generated.*",
    "**/*_pb2.py",
    "**/lex.yy.c",
    "**/*.tab.c",
    "**/*.tab.h",
    "**/*.yy.c",
)

#: How many lines of a file are read looking for a generator banner. The
#: convention is that the banner is the first thing in the file.
BANNER_SCAN_LINES: Final[int] = 5

#: Banner text, restricted to comment lines. Requiring a comment prefix is what
#: keeps a hand-written file containing the words "do not edit" in a string
#: literal from being silently dropped — the risk this heuristic carries.
GENERATED_BANNER: Final[re.Pattern[str]] = re.compile(
    r"""
    ^[ \t]*                                  # leading indentation
    (?://|/\*|\*|\#|--)                      # a comment opener
    .*?
    (?:
        \@generated
      | do[ \t]+not[ \t]+(?:edit|modify)
      | (?:auto[- ]?|automatically[ \t]+)?generated[ \t]+
        (?:by|from|file|code|with|using)
      | this[ \t]+file[ \t]+(?:is|was)[ \t]+(?:auto[- ]?)?generated
      | machine[ \t]+generated
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


@lru_cache(maxsize=32)
def _filter_for(patterns: tuple[str, ...]) -> PathFilter:
    """One :class:`PathFilter` per pattern set, reused across every path."""
    return PathFilter(patterns)


def is_third_party_path(path: PurePosixPath | str) -> bool:
    """True when any segment names a vendoring directory."""
    return any(part in THIRD_PARTY_DIRECTORIES for part in PurePosixPath(str(path)).parts)


def is_generated_name(path: PurePosixPath | str, extra: Iterable[str] = ()) -> bool:
    """True when the filename matches a generator's naming convention."""
    return _filter_for((*DEFAULT_GENERATED_GLOBS, *extra)).is_excluded(PurePosixPath(str(path)))


def has_generated_banner(real_path: Path, *, scan_lines: int = BANNER_SCAN_LINES) -> bool:
    """True when one of the first few lines carries a generator banner.

    Reads bytes and decodes leniently: a generated file is as likely as any
    other to be Latin-1, and a decode error must not be mistaken for "not
    generated".
    """
    try:
        with real_path.open("rb") as handle:
            head = handle.read(8192)
    except OSError:
        return False
    text = head.decode("utf-8", errors="replace")
    return any(GENERATED_BANNER.search(line) for line in text.splitlines()[:scan_lines])


class TargetSelector:
    """``--target`` narrowing, with suggestions when nothing matches.

    A target may name a file (``src/a.c``) or a directory prefix (``src/``),
    because both are what a user means by "just look at this".
    """

    def __init__(self, targets: Sequence[str] = ()) -> None:
        self._targets = tuple(
            str(PurePosixPath(target.strip().rstrip("/"))) for target in targets if target.strip()
        )

    @property
    def active(self) -> bool:
        return bool(self._targets)

    @property
    def targets(self) -> tuple[str, ...]:
        return self._targets

    def selects(self, path: PurePosixPath) -> bool:
        if not self._targets:
            return True
        text = str(path)
        return any(text == target or text.startswith(f"{target}/") for target in self._targets)

    def unmatched(self, paths: Iterable[PurePosixPath]) -> list[str]:
        """Targets that matched nothing. Each one is a hard stop."""
        known = [str(path) for path in paths]
        missed: list[str] = []
        for target in self._targets:
            if not any(text == target or text.startswith(f"{target}/") for text in known):
                missed.append(target)
        return missed


@dataclass(frozen=True)
class ExclusionRules:
    """Everything needed to attribute one reason to one path.

    The order in :meth:`reason_for` is the contract:

    1. ``NOT_SELECTED`` — an explicit ``--target`` narrowing outranks every
       other reason, so narrowing a scan never renames the reason a file was
       skipped.
    2. ``GENERATED`` by name, then ``THIRD_PARTY`` — in that order so
       ``x.pb.cc`` inside ``third_party/`` is reported as generated, which is
       the more actionable fact.
    3. ``UNSUPPORTED_LANGUAGE`` — knowable from flags, before touching disk.
    4. ``MISSING_SOURCE``, then ``TOO_LARGE`` — the file has to exist before
       its size means anything.
    5. ``GENERATED`` by banner — last, because it is the only rule that reads
       the file.
    """

    selector: TargetSelector
    include_third_party: bool = False
    include_generated: bool = False
    #: ``config.exclude_globs``. Attributed to ``THIRD_PARTY``, and stood down
    #: by ``include_third_party`` together with the built-in directories —
    #: the packaged defaults for that setting *are* vendoring patterns, so an
    #: opt-in that left them in force would not work at all.
    user_globs: tuple[str, ...] = ()
    max_file_bytes: int = 2_000_000

    def reason_for(
        self,
        path: PurePosixPath,
        *,
        real_path: Path | None,
        language_supported: bool,
    ) -> ExclusionReason | None:
        """The single reason ``path`` is out of scope, or ``None`` if it is in."""
        if not self.selector.selects(path):
            return ExclusionReason.NOT_SELECTED
        if not self.include_generated and is_generated_name(path):
            return ExclusionReason.GENERATED
        if not self.include_third_party and self.is_vendored(path):
            return ExclusionReason.THIRD_PARTY
        if not language_supported:
            return ExclusionReason.UNSUPPORTED_LANGUAGE
        if real_path is None or not real_path.is_file():
            return ExclusionReason.MISSING_SOURCE
        if real_path.stat().st_size > self.max_file_bytes:
            return ExclusionReason.TOO_LARGE
        if not self.include_generated and has_generated_banner(real_path):
            return ExclusionReason.GENERATED
        return None

    def is_vendored(self, path: PurePosixPath) -> bool:
        """Built-in vendoring directories, plus the user's own exclude globs."""
        if is_third_party_path(path):
            return True
        return _filter_for(self.user_globs).is_excluded(path)

    def skip_directories(self) -> frozenset[str]:
        """Directory names not worth walking when counting the tree."""
        if self.include_third_party:
            return frozenset({".git"})
        return THIRD_PARTY_DIRECTORIES | {".git"}

    def enabled_overrides(self) -> list[str]:
        """Opt-ins in force, for the plan to disclose."""
        active: list[str] = []
        if self.include_third_party:
            active.append("intake.include_third_party")
        if self.include_generated:
            active.append("intake.include_generated")
        return active

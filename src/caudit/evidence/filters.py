"""Path exclusion, shared by the evidence store (03) and intake (05).

A file excluded as third-party or generated must not be *citable*, not merely
absent from the scan — otherwise exclusion is cosmetic and a model can still
build an argument on code the user asked to be left alone.

``fnmatch`` is not used: it lets ``*`` cross directory separators, which
silently widens every pattern. These globs follow the ``.gitignore``-style
reading a user expects, where ``*`` stops at ``/`` and ``**`` does not.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from functools import lru_cache
from pathlib import PurePosixPath

__all__ = ["PathFilter", "glob_to_regex"]


@lru_cache(maxsize=512)
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile one glob. ``*`` stops at ``/``; ``**`` spans any number of segments."""
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            run_end = index
            while run_end < length and pattern[run_end] == "*":
                run_end += 1
            is_double = run_end - index >= 2
            if is_double and run_end < length and pattern[run_end] == "/":
                out.append("(?:[^/]+/)*")
                index = run_end + 1
                continue
            out.append(".*" if is_double else "[^/]*")
            index = run_end
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        out.append(re.escape(char))
        index += 1
    return re.compile("^" + "".join(out) + "$")


class PathFilter:
    """Decides whether a repository-relative path is excluded."""

    def __init__(self, exclude_globs: Iterable[str] = ()) -> None:
        self._patterns: tuple[str, ...] = tuple(exclude_globs)

    @property
    def patterns(self) -> Sequence[str]:
        return self._patterns

    def matching_pattern(self, path: PurePosixPath | str) -> str | None:
        """The first pattern that excludes ``path``, or ``None``."""
        text = str(path)
        for pattern in self._patterns:
            if glob_to_regex(pattern).match(text):
                return pattern
        return None

    def is_excluded(self, path: PurePosixPath | str) -> bool:
        return self.matching_pattern(path) is not None

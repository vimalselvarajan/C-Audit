"""Secret scrubbing and exclusion enforcement — the last gate before a send.

Two different promises are kept here, and they fail differently on purpose.

**Exclusion is absolute.** A file the user excluded in part 05 must never
appear in a request body. Enforcement is doubled deliberately: units whose
path is excluded are dropped *before* assembly, and the assembled text is
asserted against the same filter afterwards. If the assertion ever fires it is
a bug in this package, not a user error, so it raises rather than trimming —
silently repairing a leak would remove the only signal that one happened.

**Redaction is best effort, and says so.** It replaces credential-shaped
strings with a labelled placeholder and reports how many it replaced. It
cannot promise a repository holds no secret it has never seen the shape of,
and a redaction inside a *primary* unit is recorded as a limitation, because
the model then reasoned about text that differs from the code.

The patterns are narrow on purpose. A rule broad enough to catch
``secret = compute(x)`` would delete an expression that decides a security
claim, which is the one thing this codebase never does to code — so an
assignment is only rewritten when its right-hand side is a quoted literal.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.errors import CauditError
from caudit.evidence.filters import PathFilter
from caudit.logging import registered_secrets
from caudit.model.finding import Limitation, LimitationKind
from caudit.retrieval.context import ContextUnit
from caudit.retrieval.policy import UnitClass
from caudit.status import ExitCode

__all__ = [
    "WITHHELD",
    "PrivacyError",
    "RedactionKind",
    "RedactionReport",
    "assert_nothing_excluded",
    "excluded_limitation",
    "mask_excluded_paths",
    "partition_excluded",
    "redaction_limitations",
    "scrub",
]


class PrivacyError(CauditError):
    """Something that must not be transmitted reached the assembled prompt.

    Raised rather than repaired. The point of the second check is to detect a
    failure of the first one, and a check that fixes what it finds reports
    nothing.
    """

    exit_code = ExitCode.INTERNAL


class RedactionKind(StrEnum):
    """What a placeholder stands for. Kept in the text so a reader can tell."""

    AWS_ACCESS_KEY = "aws_access_key"
    GOOGLE_API_KEY = "google_api_key"
    PRIVATE_KEY_BLOCK = "private_key_block"
    BEARER_TOKEN = "bearer_token"
    JSON_WEB_TOKEN = "json_web_token"
    VENDOR_TOKEN = "vendor_token"
    #: A credential-shaped name assigned a quoted string literal.
    ASSIGNED_LITERAL = "assigned_literal"
    #: A value this process already knows is a secret — the API key itself,
    #: registered by :mod:`caudit.logging` at startup.
    REGISTERED_SECRET = "registered_secret"


_PLACEHOLDER_PREFIX: Final = "[caudit:redacted:"


def placeholder(kind: RedactionKind) -> str:
    """What replaces a secret. Labelled, so its absence is not mistaken for code."""
    return f"{_PLACEHOLDER_PREFIX}{kind}]"


#: ``(kind, pattern, group)``. ``group`` names the span to replace: ``0`` for
#: the whole match, or a group number when the surrounding text must survive —
#: ``password = "..."`` keeps the assignment and loses only the literal.
_RULES: Final[tuple[tuple[RedactionKind, re.Pattern[str], int], ...]] = (
    (
        RedactionKind.PRIVATE_KEY_BLOCK,
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
            r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        0,
    ),
    (RedactionKind.AWS_ACCESS_KEY, re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"), 0),
    (RedactionKind.GOOGLE_API_KEY, re.compile(r"\bAIza[0-9A-Za-z_\-]{16,}"), 0),
    (
        RedactionKind.JSON_WEB_TOKEN,
        re.compile(r"\beyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}"),
        0,
    ),
    (RedactionKind.BEARER_TOKEN, re.compile(r"(?i)\bBearer\s+[0-9A-Za-z\-._~+/]{20,}=*"), 0),
    (
        RedactionKind.VENDOR_TOKEN,
        re.compile(
            r"\b(?:gh[pousr]_[0-9A-Za-z]{16,}|xox[baprs]-[0-9A-Za-z\-]{10,}"
            r"|sk-[0-9A-Za-z_\-]{16,}|ya29\.[0-9A-Za-z_\-]{16,})"
        ),
        0,
    ),
    (
        RedactionKind.ASSIGNED_LITERAL,
        # Only the quoted literal is replaced, and only when the name says what
        # it holds. Anything looser would rewrite expressions, and an expression
        # is code.
        #
        # The name may be a suffix — ``service_password`` is a hard-coded
        # credential as surely as ``password`` is. A bare ``token`` is
        # deliberately *not* in the list: half the lexers in C name a variable
        # that, and redacting their strings would damage code to catch nothing.
        re.compile(
            r"(?i)(?:^|[^\w])[\w]*?"
            r"(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|api[_-]?token"
            r"|secret[_-]?key|client[_-]?secret|private[_-]?key|passphrase"
            r"|password|passwd|secret)"
            r"\s*(?:=|:)\s*"
            r'"([^"\n]{8,})"'
        ),
        1,
    ),
)


class RedactionReport(BaseModel):
    """How much was replaced, and of what. Recorded per run (AC-10-8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    count: int = Field(default=0, ge=0)
    #: ``{kind: occurrences}``, sorted by kind when rendered.
    by_kind: dict[str, int] = Field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return self.count == 0

    def describe(self) -> str:
        if self.clean:
            return "no credential-shaped strings were found"
        parts = ", ".join(f"{kind} x{count}" for kind, count in sorted(self.by_kind.items()))
        return f"{self.count} redaction(s): {parts}"

    def merged_with(self, other: RedactionReport) -> RedactionReport:
        totals = dict(self.by_kind)
        for kind, count in other.by_kind.items():
            totals[kind] = totals.get(kind, 0) + count
        return RedactionReport(count=self.count + other.count, by_kind=totals)


def scrub(text: str) -> tuple[str, RedactionReport]:
    """Replace credential-shaped strings, and say how many were replaced.

    Registered secrets go first: the API key is the one value this process is
    certain about, and a pattern rule that happened to overlap it would
    otherwise decide how it is labelled.
    """
    counts: dict[str, int] = {}
    scrubbed = text

    for secret in sorted(registered_secrets(), key=len, reverse=True):
        occurrences = scrubbed.count(secret)
        if occurrences:
            scrubbed = scrubbed.replace(secret, placeholder(RedactionKind.REGISTERED_SECRET))
            key = str(RedactionKind.REGISTERED_SECRET)
            counts[key] = counts.get(key, 0) + occurrences

    for kind, pattern, group in _RULES:
        replacement = placeholder(kind)
        hits = 0

        def substitute(match: re.Match[str], *, span: int = group, text: str = replacement) -> str:
            nonlocal hits
            # An earlier rule may already have replaced this span. Counting it
            # again would report two redactions for one secret, and AC-10-8 is
            # about a number a reader can act on.
            if match.group(span).startswith(_PLACEHOLDER_PREFIX):
                return match.group(0)
            hits += 1
            if span == 0:
                return text
            start, end = match.span(span)
            whole_start = match.start()
            return (
                match.group(0)[: start - whole_start] + text + match.group(0)[end - whole_start :]
            )

        scrubbed = pattern.sub(substitute, scrubbed)
        if hits:
            counts[str(kind)] = counts.get(str(kind), 0) + hits

    return scrubbed, RedactionReport(count=sum(counts.values()), by_kind=counts)


def redaction_limitations(
    units: Sequence[ContextUnit], reports: Sequence[RedactionReport]
) -> list[Limitation]:
    """One limitation per primary unit whose text was rewritten.

    A redacted supporting unit is a cost; a redacted *primary* unit means the
    model read something the compiler never saw, and a reader of the report is
    entitled to know which function that was.
    """
    limitations: list[Limitation] = []
    for unit, report in zip(units, reports, strict=True):
        if report.clean or unit.unit_class is not UnitClass.PRIMARY:
            continue
        target = unit.symbol.name if unit.symbol else None
        limitations.append(
            Limitation(
                kind=LimitationKind.EXCLUDED_BY_FILTER,
                detail=(
                    f"{report.describe()} inside {unit.describe()}; the model was shown a "
                    "redacted quotation of this code, so a claim that turns on the "
                    "replaced text is not supported by what it read"
                ),
                affects=f"{unit.region.path}::{target}" if target else str(unit.region.path),
            )
        )
    return limitations


def partition_excluded(
    units: Iterable[ContextUnit], path_filter: PathFilter
) -> tuple[list[ContextUnit], list[ContextUnit]]:
    """Split units into ``(sendable, excluded)`` by repository path."""
    sendable: list[ContextUnit] = []
    excluded: list[ContextUnit] = []
    for unit in units:
        target = excluded if path_filter.is_excluded(unit.region.path) else sendable
        target.append(unit)
    return sendable, excluded


def excluded_limitation(unit: ContextUnit, path_filter: PathFilter) -> Limitation:
    """Why a retrieved unit was withheld from the prompt."""
    pattern = path_filter.matching_pattern(unit.region.path) or "an exclusion glob"
    return Limitation(
        kind=LimitationKind.EXCLUDED_BY_FILTER,
        detail=(
            f"{unit.describe()} was retrieved but withheld from the model: "
            f"{unit.region.path} is excluded by '{pattern}'. Any claim about this "
            "candidate was made without it"
        ),
        affects=str(unit.region.path),
    )


#: What an excluded path becomes in text C Audit wrote itself.
WITHHELD = "[caudit:withheld:excluded-file]"


def mask_excluded_paths(text: str, path_filter: PathFilter) -> tuple[str, int]:
    """Replace excluded paths in *generated* prose. Never applied to code.

    A limitation still has to tell the model that something was withheld —
    otherwise it reads a missing macro as an absent one, which is the exact
    inversion part 09 exists to prevent — but it must not name the file. This
    keeps the statement and drops the name.

    Deliberately not applied to quoted source. An ``#include "secrets/keys.h"``
    line is bytes of the *including* file, which the user did not exclude, and
    rewriting it would edit code to satisfy a rule about prose.
    """
    masked = text
    replaced = 0
    for candidate in sorted(_quoted_paths(text), key=len, reverse=True):
        if not path_filter.is_excluded(candidate):
            continue
        replaced += masked.count(candidate)
        masked = masked.replace(candidate, WITHHELD)
    return masked, replaced


def assert_nothing_excluded(
    *,
    paths: Iterable[PurePosixPath | str],
    generated_text: str,
    path_filter: PathFilter,
) -> None:
    """Second check: no excluded file is quoted, and none is named by us.

    Both halves matter and they cover different failures. ``paths`` is every
    region whose bytes were rendered, so an excluded unit that slipped past
    :func:`partition_excluded` is caught. ``generated_text`` is the prose this
    package wrote — headings, the candidate block, the limitation list — where
    a path can arrive without any bytes behind it.

    Quoted source is deliberately not searched: a path inside a non-excluded
    file's code is that file's content.
    """
    offenders = sorted({str(path) for path in paths if path_filter.is_excluded(path)})
    if offenders:
        raise PrivacyError(
            f"{len(offenders)} excluded file(s) reached the assembled prompt: "
            f"{', '.join(offenders)}",
            hint="This is an internal invariant (AC-10-7), not a configuration problem.",
        )
    named = sorted(
        {
            candidate
            for candidate in _quoted_paths(generated_text)
            if path_filter.is_excluded(candidate)
        }
    )
    if named:
        raise PrivacyError(
            f"text written by caudit names excluded file(s): {', '.join(named)}",
            hint="This is an internal invariant (AC-10-7), not a configuration problem.",
        )


_PATH_LIKE: Final = re.compile(
    r"(?:[\w.\-]+/)+[\w.\-]+\.(?:c|h|cc|cpp|cxx|hpp|hh|hxx|inc|ipp)\b", re.IGNORECASE
)


def _quoted_paths(text: str) -> set[str]:
    """Repository-looking paths mentioned anywhere in the text."""
    return set(_PATH_LIKE.findall(text))

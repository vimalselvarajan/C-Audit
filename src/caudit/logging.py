"""Structured logging with a secret-safe formatter.

Redaction lives here, at the bottom of the stack, so part 10 inherits it
rather than reinventing it. Two layers, deliberately redundant:

* a :class:`RedactingFilter` attached to every handler, which rewrites the
  *record* itself — so no handler, at any level, can emit a raw secret;
* a :class:`RedactingFormatter`, which redacts the rendered string as well,
  covering exception text and anything a handler formats on its own.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from collections.abc import Iterable, Mapping
from typing import Final, TextIO

__all__ = [
    "REDACTED",
    "RedactingFilter",
    "RedactingFormatter",
    "configure_logging",
    "get_logger",
    "redact",
    "register_secret",
    "registered_secrets",
]

REDACTED: Final = "***redacted***"

# Environment variables whose *values* are secrets. Registered automatically
# by configure_logging so nothing has to remember to do it.
SECRET_ENV_VARS: Final[tuple[str, ...]] = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
)

# Shapes that are secrets wherever they appear, even if never registered:
# Google API keys, OAuth tokens, and the common "key = value" forms.
_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"AIza[0-9A-Za-z_\-]{16,}"),
    re.compile(r"ya29\.[0-9A-Za-z_\-]{16,}"),
    re.compile(r"\bsk-[0-9A-Za-z_\-]{12,}"),
    re.compile(r"\bgsk_[0-9A-Za-z_\-]{12,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)"
        r"(\s*[=:]\s*[\"']?)([^\s\"',;]{6,})"
    ),
)

_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    """Record a literal value that must never reach a log record.

    Short values are ignored: redacting a two-character string would corrupt
    unrelated output without protecting anything real.
    """
    if value and len(value) >= 6:
        _secrets.add(value)


def registered_secrets() -> frozenset[str]:
    """The literals currently registered. Exposed for tests only."""
    return frozenset(_secrets)


def redact(text: str) -> str:
    """Replace every registered literal and every known secret shape."""
    for secret in sorted(_secrets, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


class RedactingFilter(logging.Filter):
    """Rewrites the record in place so no handler can leak a secret."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except (TypeError, ValueError):  # pragma: no cover - malformed % args
            rendered = str(record.msg)
        record.msg = redact(rendered)
        record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        for key, value in list(record.__dict__.items()):
            if isinstance(value, str) and key not in _RESERVED_RECORD_KEYS:
                record.__dict__[key] = redact(value)
        return True


_RESERVED_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "name",
        "levelname",
        "pathname",
        "filename",
        "module",
        "funcName",
        "threadName",
        "processName",
        "msg",
        "exc_text",
    }
)


class RedactingFormatter(logging.Formatter):
    """Formats ``level  logger  message`` and redacts the result."""

    def __init__(self) -> None:
        super().__init__(fmt="%(levelname)-7s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def configure_logging(
    level: int | str = logging.WARNING,
    *,
    stream: TextIO | None = None,
    env: Mapping[str, str] | None = None,
    extra_secrets: Iterable[str] = (),
) -> logging.Handler:
    """Install the redacting handler on the ``caudit`` logger.

    Returns the handler so tests can inspect what it emitted. Calling this
    twice replaces the previous handler rather than stacking a second one.
    """
    environ = os.environ if env is None else env
    for name in SECRET_ENV_VARS:
        register_secret(environ.get(name))
    for value in extra_secrets:
        register_secret(value)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(RedactingFormatter())
    handler.addFilter(RedactingFilter())

    logger = logging.getLogger("caudit")
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return handler


def get_logger(name: str) -> logging.Logger:
    """A child of the ``caudit`` logger, so it inherits redaction."""
    suffix = name.removeprefix("caudit.").removeprefix("caudit")
    return logging.getLogger(f"caudit.{suffix}" if suffix else "caudit")

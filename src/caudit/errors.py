"""Typed errors, each carrying the exit code it maps to.

The CLI turns any :class:`CauditError` into a clean one-line message plus its
exit code. Anything else is an unexpected failure and gets a traceback id.
"""

from __future__ import annotations

from caudit.status import ExitCode

__all__ = [
    "CauditError",
    "ConfigError",
    "IntakeError",
    "RegionError",
    "ToolchainError",
    "UnimplementedCommandError",
    "UsageError",
]


class CauditError(Exception):
    """Base class for failures that have a defined exit code and message."""

    exit_code: ExitCode = ExitCode.INTERNAL

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def render(self) -> str:
        """The exact text shown to the user, hint included."""
        if self.hint:
            return f"{self.message}\n\n{self.hint}"
        return self.message


class UsageError(CauditError):
    """Bad arguments or bad configuration."""

    exit_code = ExitCode.USAGE


class ConfigError(UsageError):
    """A configuration key, value, or source is not acceptable."""


class ToolchainError(CauditError):
    """A required external tool is missing or outside its supported range.

    This is the plan's ``EnvironmentError``; it is spelled differently so it
    does not shadow the builtin of that name.
    """

    exit_code = ExitCode.ENVIRONMENT


class IntakeError(CauditError):
    """The repository cannot be scanned as described (part 05).

    Raised when the compilation database is absent, unreadable, or materially
    incomplete. It is deliberately *not* recoverable: the alternative to
    stopping is inventing include paths and compiler flags, and an index built
    from guessed flags produces wrong symbols that every finding above it
    inherits.
    """

    exit_code = ExitCode.ENVIRONMENT


class UnimplementedCommandError(CauditError):
    """A command that exists in the CLI but whose part has not been built."""

    exit_code = ExitCode.INTERNAL


class RegionError(CauditError):
    """A source region could not be read exactly as requested (part 03)."""

    exit_code = ExitCode.INTERNAL

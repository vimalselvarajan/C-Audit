"""Exit codes — the single source of truth for every command.

Part 01 fixes these five values. Later parts map their outcomes onto them
rather than inventing new ones, so a caller can branch on the exit status
without knowing which subcommand ran.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["ExitCode"]


class ExitCode(IntEnum):
    """Process exit statuses.

    ``FINDINGS`` means "the run completed and produced something the caller
    should look at": confirmed findings for ``scan``, failed hard gates for
    ``eval``. It never means the tool malfunctioned.

    ``INTERNAL`` covers unexpected failures, which always print a traceback id
    instead of a raw traceback, and the deliberate "not implemented yet"
    states that exist while the plan is only partially built.
    """

    OK = 0
    """Ran to completion with nothing that requires attention."""

    FINDINGS = 1
    """Ran to completion; confirmed findings or failed gates are present."""

    USAGE = 2
    """Bad arguments or bad configuration. Nothing was analysed."""

    ENVIRONMENT = 3
    """Missing or incompatible toolchain, or a missing compilation database."""

    INTERNAL = 4
    """Unexpected failure, or a deliberately unimplemented command."""

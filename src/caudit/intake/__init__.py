"""Repository intake: what will be scanned, and why the rest will not.

Turns a directory plus a compilation database into a validated, revision-pinned
:class:`~caudit.intake.plan.ScanPlan`. A valid ``compile_commands.json`` is
required; if it is absent or materially incomplete this package stops with
setup instructions rather than guessing include paths or compiler flags.
"""

from __future__ import annotations

from caudit.intake.loader import load_scan_plan
from caudit.intake.plan import (
    UNKNOWN_REVISION,
    Coverage,
    ExclusionReason,
    ScanPlan,
    TranslationUnit,
)
from caudit.intake.revision import RevisionInfo, resolve_revision

__all__ = [
    "UNKNOWN_REVISION",
    "Coverage",
    "ExclusionReason",
    "RevisionInfo",
    "ScanPlan",
    "TranslationUnit",
    "load_scan_plan",
    "resolve_revision",
]

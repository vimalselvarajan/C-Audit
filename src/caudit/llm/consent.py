"""The consent gate — the only path to the network.

The spec's risk table treats sending source to a hosted model as a first-class
hazard, so consent is a component rather than a flag read at the call site.
Everything that could open a socket takes a :class:`ConsentDecision` and
refuses to construct without a granted one, which means "did anyone check?" has
exactly one answer and it is visible in the type.

Absence of consent is not an error. ``caudit scan`` runs, produces the part 08
baseline report, and records a limitation saying the adjudication stage was
skipped — because a report that quietly omits the reason it is thinner than
usual is worse than one that says so.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.config.loader import Config
from caudit.errors import UsageError
from caudit.model.finding import Limitation, LimitationKind

__all__ = [
    "CONSENT_RELATIVE_PATH",
    "ConsentDecision",
    "ConsentError",
    "ConsentSource",
    "consent_state",
    "read_consent_record",
    "record_consent",
    "require_consent",
]

#: Where a persisted per-repository grant lives, relative to the repository
#: root. Inside the tree on purpose: consent is a property of *this* checkout,
#: and a machine-wide record would carry it to repositories nobody agreed to.
CONSENT_RELATIVE_PATH: Final = Path(".caudit") / "cloud-consent.json"


class ConsentError(UsageError):
    """Something tried to reach a hosted model without consent."""


class ConsentSource(StrEnum):
    """Which signal granted consent, recorded so a run can say why it sent."""

    #: ``--consent-cloud``, or ``cloud_consent`` in configuration.
    CONFIG = "config"
    #: A persisted per-repository record.
    RECORD = "record"
    #: Nobody consented.
    ABSENT = "absent"


class ConsentDecision(BaseModel):
    """Whether this run may transmit source, and on whose say-so."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    granted: bool
    source: ConsentSource
    detail: str = Field(min_length=1)

    def as_limitation(self) -> Limitation:
        """What the report says when consent is absent.

        A blind spot, not an incident: the analyzers still ran, and the reader
        needs to know that no model looked at anything.
        """
        return Limitation(
            kind=LimitationKind.NO_EVIDENCE_EXPANSION,
            detail=(
                "no candidate was adjudicated by a model because cloud consent was not "
                "given, so this report is the deterministic baseline. Re-run with "
                "--consent-cloud to allow selected source regions to be sent"
            ),
            affects=None,
        )


def read_consent_record(repo_root: Path) -> ConsentDecision | None:
    """The persisted grant for this repository, or ``None``.

    A malformed or negative record is treated as no record at all. Consent is
    the kind of thing that has to be affirmed; a file this function cannot read
    is not an affirmation.
    """
    path = repo_root / CONSENT_RELATIVE_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("granted") is not True:
        return None
    granted_at = str(payload.get("granted_at", "an unrecorded time"))
    return ConsentDecision(
        granted=True,
        source=ConsentSource.RECORD,
        detail=f"{CONSENT_RELATIVE_PATH} records consent granted at {granted_at}",
    )


def consent_state(config: Config, repo_root: Path | None = None) -> ConsentDecision:
    """Resolve every consent signal into one decision.

    Configuration is checked first because it is the signal the user gave
    *this* run; the persisted record is the standing one.
    """
    if config.cloud_consent:
        return ConsentDecision(
            granted=True,
            source=ConsentSource.CONFIG,
            detail="cloud_consent is set for this run (--consent-cloud)",
        )
    if repo_root is not None:
        recorded = read_consent_record(repo_root)
        if recorded is not None:
            return recorded
    return ConsentDecision(
        granted=False,
        source=ConsentSource.ABSENT,
        detail="no consent signal: neither --consent-cloud nor a persisted record",
    )


def require_consent(decision: ConsentDecision) -> None:
    """Raise unless ``decision`` grants consent. Called before anything opens a socket."""
    if decision.granted:
        return
    raise ConsentError(
        "sending source to a hosted model requires explicit consent, and none was given",
        hint=(
            "Re-run with --consent-cloud to allow it for this run, or --remember-consent "
            f"to record it in {CONSENT_RELATIVE_PATH}. Without it, caudit scan still "
            "runs and writes the deterministic baseline report."
        ),
    )


def record_consent(repo_root: Path, *, caudit_version: str, now: datetime | None = None) -> Path:
    """Persist a per-repository grant and return the file written.

    Deliberately trivial to revoke: it is one file inside the tree, and
    deleting it withdraws consent.
    """
    path = repo_root / CONSENT_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "granted": True,
        "granted_at": (now or datetime.now(UTC)).isoformat(),
        "caudit_version": caudit_version,
        "repository": repo_root.name,
        "note": (
            "Delete this file to withdraw consent. It permits caudit to send selected "
            "source regions from this repository to the configured model provider."
        ),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path

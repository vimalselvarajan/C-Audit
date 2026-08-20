"""Stable identifiers and deduplication fingerprints.

Two different jobs, deliberately not one function:

* ``finding_id`` identifies *a report entry*. It is deterministic across
  processes and machines (``hashlib``, never ``hash()``), which is what makes
  SARIF ``partialFingerprints`` and cross-run comparison work.
* ``dedup_fingerprint`` identifies *a defect*. It excludes line numbers and
  normalises the message so the same defect matches after the code around it
  moves.

Every digest is domain-separated, so an evidence id and a finding id computed
from the same bytes can never collide.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Final

__all__ = [
    "candidate_id",
    "dedup_fingerprint",
    "evidence_id",
    "finding_id",
    "normalize_message",
]

_SEP: Final = b"\x00"

# Order matters: paths can contain digits, quoted spans can contain paths.
_PATH_RE: Final = re.compile(
    r"(?:[\w.\-]+/)*[\w.\-]+\.(?:c|h|cc|cpp|cxx|hpp|hh|hxx|inc|ipp)\b", re.IGNORECASE
)
_QUOTED_RE: Final = re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`|\u2018[^\u2019]*\u2019")
_NUMBER_RE: Final = re.compile(r"\b0[xX][0-9a-fA-F]+\b|\b\d+\b")
_WS_RE: Final = re.compile(r"\s+")


def normalize_message(message: str) -> str:
    """Strip the parts of a diagnostic that move without the defect moving.

    Idempotent: normalising an already-normalised message is a no-op, so
    callers may pass either form to :func:`dedup_fingerprint`.
    """
    text = _PATH_RE.sub("<path>", message)
    text = _QUOTED_RE.sub("<id>", text)
    text = _NUMBER_RE.sub("<n>", text)
    text = _WS_RE.sub(" ", text).strip().lower()
    return text.rstrip(" .;:")


def _digest(domain: str, *parts: str | bytes | None) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain.encode("utf-8"))
    hasher.update(_SEP)
    for part in parts:
        if part is None:
            hasher.update(b"\xff")
        elif isinstance(part, bytes):
            hasher.update(part)
        else:
            hasher.update(part.encode("utf-8"))
        hasher.update(_SEP)
    return hasher.hexdigest()


def finding_id(
    cwe: str,
    path: PurePosixPath | str,
    symbol: str | None,
    message: str,
    *,
    start_byte: int,
    end_byte: int,
) -> str:
    """A stable id for one exact report entry.

    The byte range belongs here because two candidates in one function can
    converge on the same CWE and message only after adjudication. Omitting
    the range gives those distinct outcomes one id, which can put that id in
    both report sections when one is confirmed and the other needs review.

    Cross-run matching deliberately does *not* use this id. That is the job
    of :func:`dedup_fingerprint`, whose inputs omit location so it survives
    code motion.
    """
    return (
        "caudit-"
        + _digest(
            "caudit/finding-id/v2",
            cwe,
            str(path),
            symbol,
            message,
            str(start_byte),
            str(end_byte),
        )[:16]
    )


def dedup_fingerprint(
    cwe: str,
    path: PurePosixPath | str,
    symbol: str | None,
    normalized_message: str,
) -> str:
    """A fingerprint that survives code motion within a file.

    Line numbers are absent by construction, and the message is normalised
    (again — the operation is idempotent) so a diagnostic that only differs in
    a buffer size digit produces the same value.
    """
    return (
        "fp-"
        + _digest(
            "caudit/dedup-fingerprint/v1",
            cwe,
            str(path),
            symbol,
            normalize_message(normalized_message),
        )[:16]
    )


def evidence_id(region: object, kind: str) -> str:
    """Content-addressed id: ``sha256(kind || path || byte_range || content_hash)``.

    ``region`` is a :class:`~caudit.model.source.SourceRegion`; it is typed
    loosely here only to keep this module free of model imports. A model can
    cite only an id it was handed, so an invented id fails as
    ``UNKNOWN_EVIDENCE_ID`` before any file is opened.
    """
    path = getattr(region, "path", None)
    start_byte = getattr(region, "start_byte", None)
    end_byte = getattr(region, "end_byte", None)
    sha256 = getattr(region, "sha256", None)
    if path is None or start_byte is None or end_byte is None or sha256 is None:
        raise TypeError("evidence_id requires a SourceRegion-like object")
    return (
        "ev-"
        + _digest(
            "caudit/evidence-id/v1",
            kind,
            str(path),
            str(start_byte),
            str(end_byte),
            str(sha256),
        )[:16]
    )


def candidate_id(
    producer: str,
    rule_id: str | None,
    path: PurePosixPath | str,
    start_line: int,
    normalized_message: str,
) -> str:
    """A stable id for one analyzer candidate, before adjudication.

    Unlike a fingerprint this *does* include the line: two analyzers pointing
    at different lines are two candidates, and merging them (part 07) has to
    be an explicit act that preserves both provenances.
    """
    return (
        "cand-"
        + _digest(
            "caudit/candidate-id/v1",
            producer,
            rule_id,
            str(path),
            str(start_line),
            normalize_message(normalized_message),
        )[:16]
    )

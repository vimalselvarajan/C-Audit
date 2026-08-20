"""CWE mapping rules, encoded as data rather than judgement.

MITRE's guidance is to map to the most specific accurate Base or Variant
entry and to follow each entry's mapping notes
(https://cwe.mitre.org/documents/cwe_usage/guidance.html). That guidance
becomes three sets here:

* an **allowlist** of Base/Variant entries, each tagged with the in-scope
  weakness family it belongs to, so part 04 can compute per-family macro-F2;
* a **prohibited** set of Class and Pillar entries, rejected outright when a
  Base or Variant in the same family applies;
* a **discouraged** set, accepted only with an explicit rationale.

A candidate whose CWE is outside the allowlist is *not* dropped. It is
recorded with ``confidence=review_required`` and reason
``out_of_scope_family`` (see :mod:`caudit.model.finding`), because an
over-strict allowlist that silently suppresses real defects would be a worse
failure than an unclassified report entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Final

from pydantic import StringConstraints

__all__ = [
    "ALLOWLIST",
    "PROHIBITED",
    "CweEntry",
    "CweId",
    "CweStatus",
    "WeaknessFamily",
    "classify_cwe",
    "entries_for_family",
    "family_of",
    "suggest_replacement",
]

#: ``CWE-787``. Validated at the model boundary so a malformed id cannot
#: reach a report.
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-\d{1,5}$")]

_CWE_RE: Final = re.compile(r"^CWE-\d{1,5}$")


class WeaknessFamily(StrEnum):
    """The six in-scope weakness families from the spec's MVP scope."""

    OUT_OF_BOUNDS = "out_of_bounds"
    MEMORY_LIFETIME = "memory_lifetime"
    NULL_UNINITIALIZED = "null_uninitialized"
    INTEGER = "integer"
    RESOURCE_LEAK = "resource_leak"
    INJECTION = "injection"


class CweStatus(StrEnum):
    """How a CWE id may be used in a finding."""

    ALLOWED = "allowed"
    DISCOURAGED = "discouraged"
    PROHIBITED = "prohibited"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class CweEntry:
    """One allowlisted CWE and the family it scores under."""

    cwe: str
    name: str
    family: WeaknessFamily
    status: CweStatus = CweStatus.ALLOWED
    #: Words that, if present in a rationale or message, make this entry the
    #: better suggestion when a prohibited Class entry has to be replaced.
    hints: tuple[str, ...] = ()


def _entries() -> dict[str, CweEntry]:
    listing: tuple[CweEntry, ...] = (
        # ---------------------------------------------------- out of bounds
        CweEntry(
            "CWE-787",
            "Out-of-bounds Write",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("out-of-bounds write", "buffer overflow", "overflow write", "oob write"),
        ),
        CweEntry(
            "CWE-125",
            "Out-of-bounds Read",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("out-of-bounds read", "over-read", "oob read"),
        ),
        CweEntry(
            "CWE-121",
            "Stack-based Buffer Overflow",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("stack buffer", "stack-based"),
        ),
        CweEntry(
            "CWE-122",
            "Heap-based Buffer Overflow",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("heap buffer", "heap-based"),
        ),
        CweEntry(
            "CWE-124",
            "Buffer Underwrite",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("underwrite", "buffer underflow"),
        ),
        CweEntry("CWE-126", "Buffer Over-read", WeaknessFamily.OUT_OF_BOUNDS),
        CweEntry("CWE-127", "Buffer Under-read", WeaknessFamily.OUT_OF_BOUNDS),
        CweEntry(
            "CWE-129",
            "Improper Validation of Array Index",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("array index",),
        ),
        CweEntry(
            "CWE-131",
            "Incorrect Calculation of Buffer Size",
            WeaknessFamily.OUT_OF_BOUNDS,
            hints=("buffer size",),
        ),
        CweEntry(
            "CWE-193", "Off-by-one Error", WeaknessFamily.OUT_OF_BOUNDS, hints=("off-by-one",)
        ),
        CweEntry(
            "CWE-119",
            "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            WeaknessFamily.OUT_OF_BOUNDS,
            status=CweStatus.DISCOURAGED,
        ),
        # ------------------------------------------------- memory lifetime
        CweEntry(
            "CWE-416",
            "Use After Free",
            WeaknessFamily.MEMORY_LIFETIME,
            hints=("use after free", "use-after-free", "dangling"),
        ),
        CweEntry(
            "CWE-415",
            "Double Free",
            WeaknessFamily.MEMORY_LIFETIME,
            hints=("double free", "double-free"),
        ),
        CweEntry("CWE-590", "Free of Memory not on the Heap", WeaknessFamily.MEMORY_LIFETIME),
        CweEntry(
            "CWE-761", "Free of Pointer not at Start of Buffer", WeaknessFamily.MEMORY_LIFETIME
        ),
        CweEntry("CWE-825", "Expired Pointer Dereference", WeaknessFamily.MEMORY_LIFETIME),
        # ------------------------------------------- null and uninitialized
        CweEntry(
            "CWE-476",
            "NULL Pointer Dereference",
            WeaknessFamily.NULL_UNINITIALIZED,
            hints=("null dereference", "null pointer"),
        ),
        CweEntry(
            "CWE-457",
            "Use of Uninitialized Variable",
            WeaknessFamily.NULL_UNINITIALIZED,
            hints=("uninitialized variable",),
        ),
        CweEntry("CWE-824", "Access of Uninitialized Pointer", WeaknessFamily.NULL_UNINITIALIZED),
        CweEntry(
            "CWE-908",
            "Use of Uninitialized Resource",
            WeaknessFamily.NULL_UNINITIALIZED,
            hints=("uninitialized",),
        ),
        # -------------------------------------------------------- integers
        CweEntry(
            "CWE-190",
            "Integer Overflow or Wraparound",
            WeaknessFamily.INTEGER,
            hints=("integer overflow", "wraparound"),
        ),
        CweEntry(
            "CWE-191", "Integer Underflow", WeaknessFamily.INTEGER, hints=("integer underflow",)
        ),
        CweEntry("CWE-194", "Unexpected Sign Extension", WeaknessFamily.INTEGER),
        CweEntry(
            "CWE-195",
            "Signed to Unsigned Conversion Error",
            WeaknessFamily.INTEGER,
            hints=("signed to unsigned", "signedness"),
        ),
        CweEntry("CWE-196", "Unsigned to Signed Conversion Error", WeaknessFamily.INTEGER),
        CweEntry(
            "CWE-197", "Numeric Truncation Error", WeaknessFamily.INTEGER, hints=("truncation",)
        ),
        CweEntry("CWE-369", "Divide By Zero", WeaknessFamily.INTEGER, hints=("divide by zero",)),
        CweEntry(
            "CWE-192",
            "Integer Coercion Error",
            WeaknessFamily.INTEGER,
            status=CweStatus.DISCOURAGED,
        ),
        CweEntry(
            "CWE-680",
            "Integer Overflow to Buffer Overflow",
            WeaknessFamily.INTEGER,
            status=CweStatus.DISCOURAGED,
        ),
        # -------------------------------------------------- resource leaks
        CweEntry(
            "CWE-401",
            "Missing Release of Memory after Effective Lifetime",
            WeaknessFamily.RESOURCE_LEAK,
            hints=("memory leak", "leak of memory"),
        ),
        CweEntry(
            "CWE-772",
            "Missing Release of Resource after Effective Lifetime",
            WeaknessFamily.RESOURCE_LEAK,
            hints=("resource leak",),
        ),
        CweEntry(
            "CWE-775",
            "Missing Release of File Descriptor or Handle",
            WeaknessFamily.RESOURCE_LEAK,
            hints=("file descriptor", "handle leak"),
        ),
        CweEntry("CWE-459", "Incomplete Cleanup", WeaknessFamily.RESOURCE_LEAK, hints=("cleanup",)),
        # ----------------------------------------------------- injection
        CweEntry(
            "CWE-134",
            "Use of Externally-Controlled Format String",
            WeaknessFamily.INJECTION,
            hints=("format string",),
        ),
        CweEntry(
            "CWE-78",
            "Improper Neutralization of Special Elements used in an OS Command",
            WeaknessFamily.INJECTION,
            hints=("command injection", "os command"),
        ),
        CweEntry(
            "CWE-88", "Argument Injection", WeaknessFamily.INJECTION, hints=("argument injection",)
        ),
        CweEntry(
            "CWE-77", "Command Injection", WeaknessFamily.INJECTION, status=CweStatus.DISCOURAGED
        ),
    )
    return {entry.cwe: entry for entry in listing}


ALLOWLIST: Final[dict[str, CweEntry]] = _entries()

#: Class and Pillar entries. MITRE marks these "Prohibited" for mapping;
#: each maps to the families whose Base entries should be used instead.
PROHIBITED: Final[dict[str, tuple[str, tuple[WeaknessFamily, ...]]]] = {
    "CWE-664": (
        "Pillar: Improper Control of a Resource Through its Lifetime",
        (
            WeaknessFamily.OUT_OF_BOUNDS,
            WeaknessFamily.MEMORY_LIFETIME,
            WeaknessFamily.RESOURCE_LEAK,
            WeaknessFamily.NULL_UNINITIALIZED,
        ),
    ),
    "CWE-118": (
        "Class: Incorrect Access of Indexable Resource",
        (WeaknessFamily.OUT_OF_BOUNDS,),
    ),
    "CWE-707": (
        "Pillar: Improper Neutralization",
        (WeaknessFamily.INJECTION,),
    ),
    "CWE-693": ("Pillar: Protection Mechanism Failure", ()),
    "CWE-682": ("Pillar: Incorrect Calculation", (WeaknessFamily.INTEGER,)),
    "CWE-691": ("Pillar: Insufficient Control Flow Management", ()),
    "CWE-710": ("Pillar: Improper Adherence to Coding Standards", ()),
    "CWE-284": ("Class: Improper Access Control", ()),
    "CWE-399": ("Category: Resource Management Errors", (WeaknessFamily.RESOURCE_LEAK,)),
}


def classify_cwe(cwe: str) -> CweStatus:
    """Where a CWE id sits relative to the mapping rules."""
    if cwe in PROHIBITED:
        return CweStatus.PROHIBITED
    entry = ALLOWLIST.get(cwe)
    if entry is None:
        return CweStatus.OUT_OF_SCOPE
    return entry.status


def family_of(cwe: str) -> WeaknessFamily | None:
    """The scoring family for an allowlisted CWE, or ``None`` if out of scope."""
    entry = ALLOWLIST.get(cwe)
    return None if entry is None else entry.family


def entries_for_family(family: WeaknessFamily) -> tuple[CweEntry, ...]:
    """Every allowlisted entry in one family, in declaration order."""
    return tuple(e for e in ALLOWLIST.values() if e.family is family)


def suggest_replacement(cwe: str, context: str = "") -> list[str]:
    """Base/Variant entries to use instead of a prohibited Class or Pillar.

    ``context`` is free text — a rationale, an analyzer message — used only to
    rank the suggestions. Ranking, not deciding: the caller still supplies the
    CWE, this just makes the rejection message useful.
    """
    prohibited = PROHIBITED.get(cwe)
    if prohibited is None:
        return []
    _, families = prohibited
    candidates = [
        entry
        for family in families
        for entry in entries_for_family(family)
        if entry.status is CweStatus.ALLOWED
    ]
    lowered = context.lower()
    matched = [e.cwe for e in candidates if any(hint in lowered for hint in e.hints)]
    rest = [e.cwe for e in candidates if e.cwe not in matched]
    return matched + rest


def is_cwe_id(value: str) -> bool:
    """Shape check, independent of the allowlist."""
    return bool(_CWE_RE.match(value))

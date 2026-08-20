"""Is this CWE allowed here, and does the cited evidence contain what it needs?

Two independent checks that both happen to be about the CWE.

**Status** is part 02's allowlist applied to a model's proposal. Part 02's
:class:`~caudit.model.finding.Finding` already refuses to be constructed with a
prohibited or out-of-scope entry, which is exactly why the check has to run
*before* the finding is built: the gate's job is to explain the refusal and
keep the candidate, not to hit a ``ValueError`` on the way out.

**Preconditions** are the plan's second clause — "the evidence supports the
stated weakness" — encoded as data. A use-after-free argued from evidence with
no release site in it is not necessarily a wrong finding, but it is an
unfinished one: whatever settled the question was not cited, so nothing in the
report lets a reader check it.

Three things this is not, and the distinction is load-bearing:

* **Not a judgement about whether the bug is real.** These are presence checks
  over the bytes that were cited. A defect argued from evidence arranged
  unusually lands in review with the missing structure named, and part 13 counts
  how often that happens on adjudicated real-world cases.
* **Not a bounds check on the bug.** The plan describes an out-of-bounds write
  as needing "the write and something bounding it". Only the write is required
  here: an unbounded write is the *defect*, so requiring a visible bound would
  reject the clearest true positives in the family.
* **Not a parser.** Matching is lexical over the cited text, and it is stated as
  such wherever a failure is reported. A comment containing ``free(p)`` will
  satisfy the memory-lifetime precondition, which is acceptable in a check whose
  only power is to move an item into review — and is the reason this check is
  never the sole basis for confirming anything.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from caudit.model.candidate import Candidate
from caudit.model.cwe import (
    CweStatus,
    WeaknessFamily,
    classify_cwe,
    family_of,
    suggest_replacement,
)
from caudit.model.finding import ReviewReason
from caudit.verify.reasons import Failure

__all__ = [
    "Precondition",
    "precondition_failures",
    "preconditions_for",
    "status_failure",
    "usable_cwe",
]


@dataclass(frozen=True)
class Precondition:
    """One structural thing the cited evidence has to contain.

    ``label`` is what a reviewer is told was missing and ``why`` is why the
    family needs it. Both are stored rather than generated, because a failure
    message that only names a regular expression tells a reader nothing they
    can act on.
    """

    label: str
    pattern: re.Pattern[str]
    why: str

    def satisfied_by(self, text: str) -> bool:
        return self.pattern.search(text) is not None


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.MULTILINE)


# A call to something named like a release. Deliberately generous about the
# name — `kfree`, `buffer_release`, `obj_destroy` and `g_free` are all the same
# claim — because the alternative is a hard-coded list of allocators that is
# wrong for every codebase that wrote its own.
_RELEASE = Precondition(
    label="a release site",
    pattern=_compile(r"\b\w*(?:free|release|destroy|dispose|close|unref|put)\w*\s*\(|\bdelete\b"),
    why=(
        "a memory-lifetime claim is an argument about what happens after a release, so "
        "the release has to be among the evidence"
    ),
)

_ALLOCATION = Precondition(
    label="an acquisition site",
    pattern=_compile(
        r"\b\w*(?:alloc|open|create|new|dup|acquire|socket|fdopen|strdup)\w*\s*\(|\bnew\b"
    ),
    why="a leak claim is an argument about a resource that was acquired and never released",
)

# An assignment whose target is an indexed or dereferenced location, or a call
# to something that writes through a pointer.
_WRITE = Precondition(
    label="a write into memory",
    pattern=_compile(
        r"(?:\[[^\]\n]*\]|\*\s*\w+|->\s*\w+)\s*(?:[-+*/|&^]|<<|>>)?=(?!=)"
        r"|\b(?:mem(?:cpy|move|set)|str(?:n?cpy|n?cat)|sn?printf|vsn?printf|gets|read)\s*\("
    ),
    why="an out-of-bounds *write* claim needs the write itself, not only the buffer",
)

_ACCESS = Precondition(
    label="an access into a buffer",
    pattern=_compile(
        r"\[[^\]\n]*\]|\*\s*\w+|->\s*\w+"
        r"|\b(?:mem(?:cpy|move|cmp|chr)|str(?:n?cpy|n?cat|n?cmp|len|chr)|sn?printf|read)\s*\("
    ),
    why="an out-of-bounds claim needs the access that goes out of bounds",
)

_DEREFERENCE = Precondition(
    label="a dereference or use of the value",
    pattern=_compile(r"->|\*\s*\w+|\[[^\]\n]*\]|\b\w+\s*\(\s*\*"),
    why=(
        "a null or uninitialized claim is an argument about what happens when the value "
        "is used, so the use has to be among the evidence"
    ),
)

# Compound assignment and increment are listed separately from binary
# arithmetic: `total += n` is where an overflow usually lives, and the binary
# alternative below cannot see it because the operator is followed by `=`
# rather than by an operand. The comparison operators are deliberately absent —
# `!=` and `>=` are tests, not calculations.
_ARITHMETIC = Precondition(
    label="an arithmetic operation or conversion",
    pattern=_compile(
        r"[-+*/%]=|\+\+|--|<<|>>|[-+*/%]\s*[\w(]"
        r"|\(\s*(?:un)?signed\b|\(\s*\w+_t\s*\)|\(\s*int\b"
    ),
    why="an integer claim is an argument about a calculation, which has to be visible",
)

_INJECTION_SINK = Precondition(
    label="a call that interprets its argument",
    pattern=_compile(r"\b(?:v?[fs]?printf|v?sn?printf|system|popen|exec[lv][pe]*|dprintf)\s*\("),
    why=(
        "an injection claim is an argument about data reaching an interpreter, so the "
        "call that interprets it has to be among the evidence"
    ),
)

_BY_FAMILY: Final[dict[WeaknessFamily, tuple[Precondition, ...]]] = {
    WeaknessFamily.OUT_OF_BOUNDS: (_ACCESS,),
    WeaknessFamily.MEMORY_LIFETIME: (_RELEASE,),
    WeaknessFamily.NULL_UNINITIALIZED: (_DEREFERENCE,),
    WeaknessFamily.INTEGER: (_ARITHMETIC,),
    WeaknessFamily.RESOURCE_LEAK: (_ALLOCATION,),
    WeaknessFamily.INJECTION: (_INJECTION_SINK,),
}

#: Entries whose own wording is narrower than their family's. A write variant
#: needs the write; the family as a whole only needs the access.
_BY_CWE: Final[dict[str, tuple[Precondition, ...]]] = {
    "CWE-787": (_WRITE,),
    "CWE-121": (_WRITE,),
    "CWE-122": (_WRITE,),
    "CWE-124": (_WRITE,),
    "CWE-193": (_ACCESS,),
    "CWE-131": (_ACCESS,),
}


def preconditions_for(cwe: str) -> tuple[Precondition, ...]:
    """What the cited evidence must contain for this CWE to be argued.

    Empty for a CWE with no family — such a proposal fails the status check
    first, and inventing preconditions for an entry outside the allowlist would
    report the same problem twice.
    """
    specific = _BY_CWE.get(cwe)
    if specific is not None:
        return specific
    family = family_of(cwe)
    return _BY_FAMILY.get(family, ()) if family is not None else ()


def status_failure(cwe: str | None, rationale: str) -> Failure | None:
    """Why this CWE cannot be carried on a finding, or ``None`` if it can.

    Mirrors :class:`~caudit.model.finding.Finding`'s own validators rather than
    reimplementing them: the same three conditions, refused in the same three
    ways, but returned as a reason the gate can report instead of raised as an
    error the gate would have to catch.
    """
    if cwe is None:
        return Failure(
            reason=ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE,
            detail=(
                "the answer confirms a defect without naming a weakness; a confirmation "
                "has to say which weakness was confirmed"
            ),
        )
    status = classify_cwe(cwe)
    if status is CweStatus.PROHIBITED:
        shortlist = ", ".join(suggest_replacement(cwe, rationale)[:3]) or "a Base or Variant entry"
        return Failure(
            reason=ReviewReason.CWE_MAPPING_REJECTED,
            detail=(
                f"{cwe} is a Class or Pillar entry and is prohibited for mapping; the "
                f"most specific entry that applies would be one of {shortlist}"
            ),
            subject=cwe,
        )
    if status is CweStatus.OUT_OF_SCOPE:
        return Failure(
            reason=ReviewReason.OUT_OF_SCOPE_FAMILY,
            detail=(
                f"{cwe} is outside the C Audit allowlist, so this run cannot score or "
                "verify it; the candidate is kept for review rather than forced into a "
                "family it does not belong to"
            ),
            subject=cwe,
        )
    if status is CweStatus.DISCOURAGED and not rationale.strip():
        return Failure(
            reason=ReviewReason.CWE_MAPPING_REJECTED,
            detail=(
                f"{cwe} is a discouraged mapping and was proposed with no rationale "
                "explaining why no Base or Variant entry applies"
            ),
            subject=cwe,
        )
    return None


def precondition_failures(cwe: str, cited_text: str) -> list[Failure]:
    """Structural preconditions this CWE needs that the cited evidence lacks.

    ``cited_text`` is the concatenation of the bytes behind every cited region,
    decoded for matching. Concatenated rather than checked per-region on
    purpose: an argument is allowed to spread across the functions it cites, and
    requiring each precondition to land inside one region would reject exactly
    the cross-function reasoning part 09 exists to enable.
    """
    return [
        Failure(
            reason=ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE,
            detail=(
                f"{cwe} was confirmed but the cited evidence contains no "
                f"{precondition.label} — {precondition.why}. The check is lexical over "
                "the cited regions, so evidence that settles it was either not cited or "
                "is written in a form this check does not recognise"
            ),
            subject=cwe,
        )
        for precondition in preconditions_for(cwe)
        if not precondition.satisfied_by(cited_text)
    ]


def usable_cwe(proposed: str | None, candidate: Candidate, fallback: str) -> str:
    """The CWE a finding built from this proposal can actually carry.

    When the model's entry is allowlisted it is used. When it is not, the
    candidate's own classification stands in, so that a review item still says
    something true about the weakness rather than carrying an entry that part
    02 would refuse. What the model proposed is not lost — the failure that
    rejected it names it.
    """
    if proposed is not None and classify_cwe(proposed) in _CARRIABLE:
        return proposed
    for suggested in candidate.suggested_cwe:
        if classify_cwe(suggested) in _CARRIABLE:
            return suggested
    return fallback


#: Statuses part 02's ``Finding`` will accept on the ``cwe`` field. Discouraged
#: is in it: that entry is allowed with a rationale, and the rationale is
#: checked by :func:`status_failure` rather than here.
_CARRIABLE: Final[frozenset[CweStatus]] = frozenset({CweStatus.ALLOWED, CweStatus.DISCOURAGED})


def cited_text(chunks: Sequence[bytes]) -> str:
    """The cited bytes as one string, decoded the way the prompt decoded them.

    ``errors="replace"`` matches :mod:`caudit.llm.prompts`, so the text matched
    here is the text the model was shown. Decoding more strictly would search a
    different document from the one that was read.
    """
    return "\n".join(chunk.decode("utf-8", errors="replace") for chunk in chunks)

"""Candidate to finding, with no AI in the path.

Moved here from ``caudit.eval.baseline`` when part 08 was built, and the move
is the point. ``caudit scan`` at Milestone 1 and ``caudit eval --baseline``
must describe the *same* thing: if the report promoted candidates one way and
the harness another, the baseline the M2 numbers are compared against would
be measuring a different tool. One function, one policy, both callers.

Promotion is deliberately conservative. An analyzer knows where it fired; it
does not know whether the path is reachable, whether an attacker controls the
input, or what maintaining the fix will cost. Those fields are filled with an
explicit statement that they were not assessed, never with a guess.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from caudit.errors import RegionError
from caudit.evidence.store import SourceStore
from caudit.model.candidate import Candidate
from caudit.model.cwe import WeaknessFamily, family_of
from caudit.model.evidence import EvidenceItem, EvidenceKind
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Finding,
    Impact,
    ImpactKind,
    Limitation,
    LimitationKind,
    MaintainabilityImpact,
    Reachability,
    Remediation,
    ReviewReason,
    Severity,
)
from caudit.model.ids import dedup_fingerprint, finding_id, normalize_message
from caudit.model.source import SourceRegion

__all__ = ["primary_cwe", "promote_candidate"]

_IMPACT_BY_FAMILY: Final[Mapping[WeaknessFamily, tuple[ImpactKind, Severity]]] = {
    WeaknessFamily.OUT_OF_BOUNDS: (ImpactKind.MEMORY_CORRUPTION, Severity.HIGH),
    WeaknessFamily.MEMORY_LIFETIME: (ImpactKind.MEMORY_CORRUPTION, Severity.HIGH),
    WeaknessFamily.NULL_UNINITIALIZED: (ImpactKind.UNDEFINED_BEHAVIOR, Severity.MEDIUM),
    WeaknessFamily.INTEGER: (ImpactKind.INCORRECT_RESULT, Severity.MEDIUM),
    WeaknessFamily.RESOURCE_LEAK: (ImpactKind.RESOURCE_EXHAUSTION, Severity.MEDIUM),
    WeaknessFamily.INJECTION: (ImpactKind.CODE_EXECUTION, Severity.HIGH),
}

_REMEDIATION_BY_FAMILY: Final[Mapping[WeaknessFamily, str]] = {
    WeaknessFamily.OUT_OF_BOUNDS: (
        "Bound the write to the destination's capacity and validate the index or "
        "length before the access."
    ),
    WeaknessFamily.MEMORY_LIFETIME: (
        "Give the allocation a single owner, null the pointer after release, and "
        "make every exit path release exactly once."
    ),
    WeaknessFamily.NULL_UNINITIALIZED: (
        "Check the result before dereferencing it, and initialise the variable on "
        "every path that reaches its use."
    ),
    WeaknessFamily.INTEGER: (
        "Perform the arithmetic in a width that cannot wrap, and reject inputs that "
        "would overflow before they reach the calculation."
    ),
    WeaknessFamily.RESOURCE_LEAK: (
        "Release the resource on every exit path, including early error returns."
    ),
    WeaknessFamily.INJECTION: (
        "Use a constant format string, and pass untrusted data as an argument rather "
        "than as part of the command or format."
    ),
}

_NOT_ASSESSED: Final = (
    "Not assessed: the analyzer-only baseline reports where a check fired and does "
    "not evaluate this dimension."
)


def promote_candidate(
    candidate: Candidate,
    *,
    store: SourceStore,
    limitations: Sequence[Limitation] = (),
) -> Finding:
    """Turn one analyzer candidate into a finding, claiming nothing extra.

    Reachability and exploitability stay ``unknown``: an analyzer firing is
    not evidence that the path is reachable, and the two are separate fields
    precisely so one cannot be read off the other.
    """
    families = candidate.families
    family = families[0] if families else None
    cwe = primary_cwe(candidate)
    impact_kind, severity = (
        _IMPACT_BY_FAMILY.get(family, (ImpactKind.UNDEFINED_BEHAVIOR, Severity.LOW))
        if family
        else (ImpactKind.UNDEFINED_BEHAVIOR, Severity.LOW)
    )
    # A symbol is only carried when there is a region that contains it. An
    # analyzer naming a function is a claim; the region spanning that
    # function is what makes the claim checkable, and part 06's index is what
    # supplies the region in the general case.
    provable_symbol = candidate.symbol if candidate.enclosing_region else None
    symbol_name = provable_symbol.name if provable_symbol else None

    # Re-hash the cited region now. If the file moved under us between
    # analysis and promotion, the finding goes to review-required rather than
    # carrying a quotation that no longer matches the tree.
    stale = _region_is_stale(candidate.region, store)

    evidence = [
        EvidenceItem.create(
            kind=EvidenceKind.ANALYZER_DIAGNOSTIC,
            region=candidate.region,
            provenance=list(candidate.provenance),
        )
    ]
    if candidate.enclosing_region is not None:
        evidence.append(
            EvidenceItem.create(
                kind=EvidenceKind.PRIMARY_CODE,
                region=candidate.enclosing_region,
                provenance=list(candidate.provenance),
                symbol=provable_symbol,
            )
        )
    # The analyzer's own path, in the order it walked it. Part 07 keeps these
    # ordered on the candidate; re-sorting them here would turn an argument
    # into a list of unrelated lines.
    seen = {item.evidence_id for item in evidence}
    for step in candidate.evidence:
        if step.evidence_id not in seen:
            seen.add(step.evidence_id)
            evidence.append(step)

    unproven_symbol = candidate.symbol is not None and provable_symbol is None
    out_of_scope = family is None
    if stale:
        confidence = Confidence.REVIEW_REQUIRED
        reason = ReviewReason.HASH_MISMATCH
    elif out_of_scope:
        confidence = Confidence.REVIEW_REQUIRED
        reason = ReviewReason.OUT_OF_SCOPE_FAMILY
    else:
        confidence = Confidence.MEDIUM
        reason = ReviewReason.ANALYZER_ONLY

    return Finding(
        finding_id=finding_id(
            cwe,
            candidate.region.path,
            symbol_name,
            candidate.message,
            start_byte=candidate.region.start_byte,
            end_byte=candidate.region.end_byte,
        ),
        fingerprint=dedup_fingerprint(cwe, candidate.region.path, symbol_name, candidate.message),
        cwe=cwe,
        cwe_rationale=_cwe_rationale(candidate, cwe, mapped=not out_of_scope),
        location=candidate.region,
        symbol=provable_symbol,
        evidence=evidence,
        preconditions=[
            "Preconditions not established: the baseline records the analyzer's "
            "trigger location, not the inputs required to reach it."
        ],
        impact=Impact(
            kind=impact_kind,
            severity=severity,
            description=candidate.message,
            evidence_supports=(
                f"A static analyzer reported this at {candidate.region.describe()}. "
                "The evidence is the diagnostic and the cited region, nothing more."
            ),
        ),
        reachability=Reachability.UNKNOWN,
        exploitability=Exploitability.UNKNOWN,
        provenance=list(candidate.provenance),
        confidence=confidence,
        confidence_reason=reason,
        remediation=Remediation(
            strategy=_REMEDIATION_BY_FAMILY.get(
                family, "Review the diagnostic and the surrounding code."
            )
            if family
            else "Review the diagnostic and the surrounding code.",
            rationale=(
                "Derived from the weakness family, not from repository-specific "
                "reasoning. The MVP recommends; it does not modify code."
            ),
        ),
        maintainability_impact=MaintainabilityImpact(
            ownership=_NOT_ASSESSED,
            complexity=_NOT_ASSESSED,
            coupling=_NOT_ASSESSED,
            regression_risk=_NOT_ASSESSED,
            effort=Severity.MEDIUM,
        ),
        limitations=[
            *limitations,
            Limitation(
                kind=LimitationKind.NO_EVIDENCE_EXPANSION,
                detail=(
                    "Analyzer-only baseline: no cross-function evidence expansion and "
                    "no adjudication were performed for this candidate."
                ),
                affects=str(candidate.region.path),
            ),
            *(
                [
                    Limitation(
                        kind=LimitationKind.UNRESOLVED_INDIRECT_CALL,
                        detail=(
                            f"The analyzer attributed this to "
                            f"{candidate.symbol.name if candidate.symbol else '?'}, but "
                            "no region proves the line sits inside that function, so the "
                            "symbol is not reported."
                        ),
                        affects=str(candidate.region.path),
                    )
                ]
                if unproven_symbol
                else []
            ),
        ],
    )


def _region_is_stale(region: SourceRegion, store: SourceStore) -> bool:
    """Whether the region's bytes still hash to what the candidate recorded."""
    try:
        return store.hash_region(region) != region.sha256
    except (RegionError, ValueError):
        return True


def _cwe_rationale(candidate: Candidate, cwe: str, *, mapped: bool) -> str:
    """Say where the classification came from, including when it is provisional."""
    rule = candidate.provenance[0].rule_id or candidate.provenance[0].tool_name
    if mapped:
        return (
            f"Mapped from the analyzer rule {rule} using the committed rule-to-CWE "
            "table; no model was involved."
        )
    return (
        f"The analyzer rule {rule} has no accurate entry in the rule-to-CWE table. "
        f"{cwe} is provisional, derived from the diagnostic text alone, which is why "
        "this item is routed to review-required with reason out_of_scope_family "
        "rather than reported as a confirmed finding."
    )


#: Phrases that say which defect a multi-CWE rule actually reported, most
#: specific first. Consulted **only** to choose between CWEs the profile
#: already sanctioned for that rule, never to introduce one it did not — so
#: this narrows a set someone committed, rather than reading a classification
#: out of prose. A phrase that names no sanctioned CWE is ignored.
#:
#: One checker reporting several distinct defects is the normal case, not an
#: edge: ``unix.Malloc`` alone reports leaks (CWE-401), use-after-free
#: (CWE-416) and double-free (CWE-415), and the rule id is identical for all
#: three. The message is the only thing that separates them.
_MESSAGE_DISCRIMINATORS: Final[tuple[tuple[str, str], ...]] = (
    ("use of memory after it is freed", "CWE-416"),
    ("use-after-free", "CWE-416"),
    ("use after free", "CWE-416"),
    ("attempt to free released memory", "CWE-415"),
    ("attempt to release already released", "CWE-415"),
    ("double free", "CWE-415"),
    ("double-free", "CWE-415"),
    ("potential leak of memory", "CWE-401"),
    ("memory is never released", "CWE-401"),
    ("potential memory leak", "CWE-401"),
    ("opened file is never closed", "CWE-772"),
    ("leak", "CWE-401"),
)


def _discriminate(message: str, sanctioned: Sequence[str]) -> str | None:
    """Pick between CWEs the rule maps to, using what the analyzer said.

    Returns ``None`` when the message settles nothing, which leaves the caller
    on its documented first-entry behaviour rather than inventing an answer.
    """
    text = normalize_message(message)
    allowed = set(sanctioned)
    for phrase, cwe in _MESSAGE_DISCRIMINATORS:
        if phrase in text and cwe in allowed:
            return cwe
    return None


def primary_cwe(candidate: Candidate) -> str:
    """The most specific in-scope CWE the candidate suggests.

    When the rule maps to several, the diagnostic text chooses between them.
    Taking the first unconditionally is a guessed classification — the thing
    the profile's own comment says this project does not do — and it is wrong
    often enough to matter: every ``unix.Malloc`` use-after-free was reported
    as CWE-401, a memory leak, which is both the wrong remediation for a
    reader and a miss plus a false positive for the benchmark.

    Falls back to a review-required placeholder family entry when the
    analyzer's rule has no accurate mapping — the candidate is still
    reported, which is the point.
    """
    mapped = [cwe for cwe in candidate.suggested_cwe if family_of(cwe) is not None]
    if len(mapped) > 1:
        chosen = _discriminate(candidate.message, mapped)
        if chosen is not None:
            return chosen
    if mapped:
        return mapped[0]
    message = normalize_message(candidate.message)
    if "leak" in message:
        return "CWE-772"
    if "null" in message:
        return "CWE-476"
    if "uninitialized" in message:
        return "CWE-457"
    return "CWE-908"

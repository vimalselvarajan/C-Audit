"""Analyzer candidates — what exists before anything adjudicates.

A candidate is deliberately weaker than a finding. It may carry several
suggested CWEs, or none it can justify, and its CWEs are *not* checked
against the allowlist: dropping an out-of-family candidate at this stage
would hide it before a human ever sees it. Part 11 is where a candidate
either becomes a finding or becomes a review-required item.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from caudit.model.cwe import CweId, CweStatus, WeaknessFamily, classify_cwe, family_of
from caudit.model.evidence import EvidenceItem, Provenance
from caudit.model.ids import candidate_id, dedup_fingerprint, normalize_message
from caudit.model.source import SourceRegion, Symbol

__all__ = ["Candidate"]


def _ordered(first: list[EvidenceItem], second: list[EvidenceItem]) -> list[EvidenceItem]:
    """Concatenate two evidence lists, dropping repeats by content address."""
    merged: dict[str, EvidenceItem] = {}
    for item in [*first, *second]:
        merged.setdefault(item.evidence_id, item)
    return list(merged.values())


class Candidate(BaseModel):
    """One normalized analyzer diagnostic."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    fingerprint: str = Field(min_length=1)
    region: SourceRegion
    symbol: Symbol | None = None
    #: The containing function, when something can actually prove it — the
    #: index in part 06, or a recording that declares it. A symbol claim is
    #: only citable if there is a region that contains it, so this is what
    #: turns ``symbol`` from an assertion into evidence.
    enclosing_region: SourceRegion | None = None
    suggested_cwe: list[CweId] = Field(default_factory=list)
    message: str = Field(min_length=1)
    #: Supporting regions the analyzer itself pointed at: the ordered
    #: ``control_flow_step`` items of a static-analyzer path, then any plain
    #: notes. **Order is meaningful** — a path read out of sequence is a
    #: different argument from the one the analyzer made — so this list is
    #: never sorted, only appended to.
    evidence: list[EvidenceItem] = Field(default_factory=list)
    #: Grows when candidates merge. Entries are never dropped — provenance is
    #: how part 04 measures analyzer bias.
    provenance: list[Provenance] = Field(min_length=1)

    @classmethod
    def create(
        cls,
        *,
        region: SourceRegion,
        message: str,
        provenance: list[Provenance],
        suggested_cwe: list[str] | None = None,
        symbol: Symbol | None = None,
        enclosing_region: SourceRegion | None = None,
        evidence: list[EvidenceItem] | None = None,
    ) -> Candidate:
        """Build a candidate with derived id and fingerprint."""
        cwes = list(suggested_cwe or [])
        primary = cwes[0] if cwes else "CWE-0"
        producer = provenance[0].producer if provenance else "unknown"
        rule_id = provenance[0].rule_id if provenance else None
        symbol_name = symbol.name if symbol else None
        return cls(
            candidate_id=candidate_id(
                str(producer), rule_id, region.path, region.start_line, message
            ),
            fingerprint=dedup_fingerprint(primary, region.path, symbol_name, message),
            region=region,
            symbol=symbol,
            enclosing_region=enclosing_region,
            suggested_cwe=cwes,
            message=message,
            evidence=list(evidence or []),
            provenance=provenance,
        )

    @property
    def normalized_message(self) -> str:
        return normalize_message(self.message)

    @property
    def families(self) -> list[WeaknessFamily]:
        """Scoring families implied by the suggested CWEs, deduplicated."""
        seen: dict[WeaknessFamily, None] = {}
        for cwe in self.suggested_cwe:
            family = family_of(cwe)
            if family is not None:
                seen.setdefault(family, None)
        return list(seen)

    @property
    def out_of_scope(self) -> bool:
        """True when no suggested CWE maps into an in-scope family.

        Such a candidate is still reported — as review-required with reason
        ``out_of_scope_family`` — never discarded.
        """
        if not self.suggested_cwe:
            return True
        return all(
            classify_cwe(cwe) in {CweStatus.OUT_OF_SCOPE, CweStatus.PROHIBITED}
            for cwe in self.suggested_cwe
        )

    def merged_with(self, other: Candidate) -> Candidate:
        """Merge a duplicate, keeping every provenance entry.

        The earliest region wins so the merged candidate still points at real
        code; the union of suggested CWEs is kept because disagreement between
        analyzers is itself a signal part 11 uses. Evidence is unioned by
        content address with each analyzer's own step order intact — one
        analyzer's path is never interleaved into another's.
        """
        if other.fingerprint != self.fingerprint:
            raise ValueError(
                f"refusing to merge candidates with different fingerprints: "
                f"{self.fingerprint} != {other.fingerprint}"
            )
        cwes = list(dict.fromkeys([*self.suggested_cwe, *other.suggested_cwe]))
        provenance = list(dict.fromkeys([*self.provenance, *other.provenance]))
        earlier = min(self, other, key=lambda c: (c.region.start_line, c.candidate_id))
        return self.model_copy(
            update={
                "candidate_id": earlier.candidate_id,
                "region": earlier.region,
                "suggested_cwe": cwes,
                "evidence": _ordered(self.evidence, other.evidence),
                "provenance": provenance,
            }
        )

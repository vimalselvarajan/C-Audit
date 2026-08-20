"""Evidence items and provenance.

An evidence item is a quotation of the scanned revision plus a record of who
produced it. Both parts are mandatory: a claim with no producer is not
representable, and a producer with no region is not evidence.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.model.ids import evidence_id
from caudit.model.source import SourceRegion, Symbol

__all__ = [
    "ANALYZER_PRODUCERS",
    "EvidenceItem",
    "EvidenceKind",
    "Producer",
    "Provenance",
]


class Producer(StrEnum):
    """What kind of component produced a fact."""

    CLANG_DIAGNOSTIC = "clang_diagnostic"
    CSA = "csa"
    CLANG_TIDY = "clang_tidy"
    INDEX = "index"
    LLM = "llm"
    #: Hand-written benchmark ground truth and recorded fixtures.
    FIXTURE = "fixture"


#: Producers whose ``tool_name`` is an external analyzer this run had to
#: invoke. ``index``, ``llm`` and ``fixture`` name components of C Audit
#: itself, so they are not held to the set of analyzers that ran and they do
#: not count as independent corroboration.
#:
#: Lives beside the enum because two parts read it for opposite purposes —
#: part 11 rejects a name that is not in the run's analyzer set, part 12
#: counts distinct names as agreement — and a second copy of the set would
#: eventually disagree with the first.
ANALYZER_PRODUCERS: frozenset[Producer] = frozenset(
    {Producer.CLANG_DIAGNOSTIC, Producer.CSA, Producer.CLANG_TIDY}
)


class EvidenceKind(StrEnum):
    """What role a region plays in an argument."""

    PRIMARY_CODE = "primary_code"
    SUPPORTING_CODE = "supporting_code"
    TYPE_DECL = "type_decl"
    MACRO_DEF = "macro_def"
    CALL_EDGE = "call_edge"
    ANALYZER_DIAGNOSTIC = "analyzer_diagnostic"
    CONTROL_FLOW_STEP = "control_flow_step"


class Provenance(BaseModel):
    """Which analyzer, compiler fact, or retrieval step produced a fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    producer: Producer
    tool_name: str = Field(min_length=1)
    #: Recorded verbatim, never inferred. A run whose tool versions are
    #: unknown is not reproducible.
    tool_version: str = Field(min_length=1)
    rule_id: str | None = None
    detail: str | None = None

    def describe(self) -> str:
        rule = f" [{self.rule_id}]" if self.rule_id else ""
        return f"{self.tool_name} {self.tool_version}{rule}"


class EvidenceItem(BaseModel):
    """One citable region. The ``evidence_id`` is content-addressed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1)
    kind: EvidenceKind
    region: SourceRegion
    symbol: Symbol | None = None
    provenance: list[Provenance] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_content_addressing(self) -> Self:
        expected = evidence_id(self.region, str(self.kind))
        if self.evidence_id != expected:
            raise ValueError(
                f"evidence_id {self.evidence_id!r} is not the content address of this "
                f"region and kind (expected {expected!r})"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        kind: EvidenceKind,
        region: SourceRegion,
        provenance: list[Provenance],
        symbol: Symbol | None = None,
    ) -> EvidenceItem:
        """Build an item with its id derived from its content."""
        return cls(
            evidence_id=evidence_id(region, str(kind)),
            kind=kind,
            region=region,
            symbol=symbol,
            provenance=provenance,
        )

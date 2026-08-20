"""Claim-level provenance policy shared by verification and output renderers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from caudit.model.evidence import ANALYZER_PRODUCERS, Producer
from caudit.model.finding import Finding

__all__ = ["MODEL_AUTHORED_FIELDS", "ClaimProvenance", "claim_provenance"]

MODEL_AUTHORED_FIELDS: Final[tuple[str, ...]] = (
    "cwe_rationale",
    "preconditions",
    "impact",
    "remediation",
    "maintainability_impact",
)


@dataclass(frozen=True)
class ClaimProvenance:
    """Which producer stands behind each claim in a finding."""

    analyzers: tuple[str, ...] = ()
    index_tools: tuple[str, ...] = ()
    models: tuple[str, ...] = ()
    facts: tuple[tuple[str, str], ...] = ()

    @property
    def model_involved(self) -> bool:
        return bool(self.models)

    def describe(self) -> str:
        """Describe the source responsible for every class of claim."""
        parts: list[str] = []
        if self.analyzers:
            analyzers = ", ".join(self.analyzers)
            parts.append(f"analyzers ({analyzers}): the diagnostic and its location")
        if self.index_tools:
            index_tools = ", ".join(self.index_tools)
            parts.append(f"index ({index_tools}): the surrounding code, types and callers")
        if self.models:
            models = ", ".join(self.models)
            fields = ", ".join(MODEL_AUTHORED_FIELDS)
            parts.append(
                f"model ({models}): {fields} — argument and wording only, "
                "every citation checked by the gate"
            )
        else:
            parts.append("no model was consulted about this finding")
        return "; ".join(parts)


def claim_provenance(finding: Finding) -> ClaimProvenance:
    """Split finding provenance according to the producer of each fact."""
    analyzers: list[str] = []
    index_tools: list[str] = []
    models: list[str] = []
    for entry in finding.provenance:
        target = (
            analyzers
            if entry.producer in ANALYZER_PRODUCERS
            else models
            if entry.producer is Producer.LLM
            else index_tools
            if entry.producer is Producer.INDEX
            else None
        )
        if target is not None and entry.tool_name not in target:
            target.append(entry.tool_name)

    facts: list[tuple[str, str]] = []
    for item in finding.evidence:
        producers = ", ".join(sorted({entry.tool_name for entry in item.provenance}))
        facts.append((f"{item.region.describe()} ({item.kind})", producers))
        for entry in item.provenance:
            if entry.producer is Producer.INDEX and entry.tool_name not in index_tools:
                index_tools.append(entry.tool_name)

    return ClaimProvenance(
        analyzers=tuple(analyzers),
        index_tools=tuple(index_tools),
        models=tuple(models),
        facts=tuple(facts),
    )

"""Benchmark cases and the suite protocol.

A suite is anything that can enumerate cases with ground truth. That keeps
the committed mini suite, CASTLE, Juliet, and (part 13) CVE pairs behind one
interface, so the metrics code never learns which corpus it is scoring.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from caudit.model.cwe import CweId, WeaknessFamily

__all__ = [
    "BenchmarkCase",
    "BenchmarkSuite",
    "GroundTruth",
    "TruthFrame",
    "count_lines_of_code",
]


class TruthFrame(StrEnum):
    """What the ground truth is a complete account *of*.

    Two label sets can both be honest and still have different recall
    denominators, and the difference is invisible in the number. A synthetic
    corpus knows every defect it contains, so a missed one is a false negative.
    A label set drawn from one scan's candidates knows only what the analyzers
    proposed, so a defect nothing flagged produces no row and cannot be counted
    against the tool at all.

    Both are worth measuring and neither may be compared with the other, so the
    frame is declared rather than inferred and is carried on
    :class:`~caudit.eval.metrics.Metrics` all the way to ``caudit compare``.
    """

    #: Every defect in the case is labelled. Recall is recall.
    EXHAUSTIVE = "exhaustive"
    #: Labels were drawn from one scan's candidate set, so the recall
    #: denominator is "defects the analyzers flagged", not "defects present".
    #: Within the frame every count is real: a labelled-vulnerable candidate
    #: left unconfirmed is a genuine false negative, and a labelled-safe one
    #: that gets confirmed is a genuine false positive.
    ANALYZER_CANDIDATES = "analyzer_candidates"

    def describe(self) -> str:
        if self is TruthFrame.EXHAUSTIVE:
            return "every defect in the corpus is labelled"
        return (
            "labels drawn from the analyzer candidate set; recall is bounded by what the analyzers "
            "flagged"
        )


class GroundTruth(BaseModel):
    """One labelled defect, or one labelled *absence* of a defect."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: PurePosixPath
    line: int = Field(ge=1)
    cwe: CweId
    family: WeaknessFamily
    #: ``fixed`` entries are what make Juliet good/bad twins and CVE pairs
    #: informative: a finding against one is a false positive, not a miss.
    variant: Literal["vulnerable", "fixed"] = "vulnerable"
    note: str = ""


class BenchmarkCase(BaseModel):
    """One compilable unit of evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    case_id: str = Field(min_length=1)
    root: Path
    compile_commands: Path | None = None
    ground_truth: list[GroundTruth]
    lines_of_code: int = Field(ge=0)
    family: WeaknessFamily | None = None
    #: Set for cases the deterministic analyzers are known to miss. A suite
    #: where everything passes is suspicious; these make that visible.
    analyzer_blind_spot: bool = False
    description: str = ""

    @property
    def vulnerable_truths(self) -> list[GroundTruth]:
        return [t for t in self.ground_truth if t.variant == "vulnerable"]

    @property
    def fixed_truths(self) -> list[GroundTruth]:
        return [t for t in self.ground_truth if t.variant == "fixed"]


@runtime_checkable
class BenchmarkSuite(Protocol):
    """What every adapter provides."""

    name: str

    def case_ids(self) -> Sequence[str]: ...

    def load(self, case_id: str) -> BenchmarkCase: ...

    def cases(self) -> Sequence[BenchmarkCase]: ...


def count_lines_of_code(paths: Sequence[Path]) -> int:
    """Non-blank, non-comment-only lines. Used for FP/KLOC.

    Deliberately crude and deliberately fixed: the number only has to be
    stable and documented for the rate to be comparable between runs.
    """
    total = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover - unreadable fixture
            continue
        in_block = False
        for raw in text.splitlines():
            line = raw.strip()
            if in_block:
                if "*/" in line:
                    in_block = False
                continue
            if not line or line.startswith("//"):
                continue
            if line.startswith("/*"):
                if "*/" not in line:
                    in_block = True
                continue
            total += 1
    return total

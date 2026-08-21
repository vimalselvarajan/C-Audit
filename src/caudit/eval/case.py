"""Benchmark cases and the suite protocol.

A suite is anything that can enumerate cases with ground truth. That keeps
the committed mini suite, CASTLE, Juliet, and (part 13) CVE pairs behind one
interface, so the metrics code never learns which corpus it is scoring.
"""

from __future__ import annotations

from collections.abc import Sequence
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


class TruthFrame(BaseModel):
    """Structured, defaultable description of the benchmark truth boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exhaustive: bool = True
    single_cwe: bool = False

    def describe(self) -> str:
        if self.exhaustive:
            return "every defect in the corpus is labelled"
        return "labels are bounded by the analyzer candidate set"


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

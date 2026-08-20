"""The matching policy — the experiment, written down.

An undefined notion of "detected" makes every metric meaningless, and it is
the easiest place to accidentally flatter the tool. So the policy is
explicit, versioned, and recorded next to every result:

* a finding matches a truth entry when the file is the same, the line is
  within ``line_tolerance``, and the CWE is the truth CWE or a declared
  equivalent;
* each truth entry is consumed **once** — surplus findings on the same defect
  are false positives, not free credit;
* findings against ``fixed`` sources are false positives;
* changing the tolerance or the equivalence map requires a version bump, and
  reports carrying different versions are refused for comparison rather than
  differenced into a misleading delta.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from caudit.eval.case import GroundTruth
from caudit.model.cwe import CweId
from caudit.model.finding import Finding

__all__ = ["DEFAULT_EQUIVALENCE", "MatchResult", "MatchingPolicy", "default_policy"]

#: Accepted alternates, keyed by the *truth* CWE. Each entry is a pairing a
#: reasonable analyst would accept, not a convenience: CWE-121/122 are the
#: stack and heap variants of an out-of-bounds write, CWE-126/127 the read
#: variants, and so on.
DEFAULT_EQUIVALENCE: Mapping[str, frozenset[str]] = {
    "CWE-787": frozenset({"CWE-121", "CWE-122", "CWE-124", "CWE-193", "CWE-131"}),
    "CWE-125": frozenset({"CWE-126", "CWE-127", "CWE-193"}),
    "CWE-121": frozenset({"CWE-787"}),
    "CWE-122": frozenset({"CWE-787"}),
    "CWE-416": frozenset({"CWE-825"}),
    "CWE-415": frozenset({"CWE-416"}),
    "CWE-476": frozenset({"CWE-824"}),
    "CWE-457": frozenset({"CWE-908", "CWE-824"}),
    "CWE-190": frozenset({"CWE-680", "CWE-191", "CWE-131"}),
    "CWE-191": frozenset({"CWE-190"}),
    "CWE-197": frozenset({"CWE-195", "CWE-196", "CWE-194"}),
    "CWE-401": frozenset({"CWE-772", "CWE-459"}),
    "CWE-772": frozenset({"CWE-401", "CWE-775", "CWE-459"}),
    "CWE-134": frozenset(),
    "CWE-78": frozenset({"CWE-88", "CWE-77"}),
}


@dataclass(frozen=True)
class MatchResult:
    """Which findings matched which truths, and what was left over."""

    #: ``(truth index, finding index)`` pairs, one per consumed truth entry.
    pairs: tuple[tuple[int, int], ...]
    unmatched_truths: tuple[int, ...]
    unmatched_findings: tuple[int, ...]

    @property
    def true_positives(self) -> int:
        return len(self.pairs)

    @property
    def false_negatives(self) -> int:
        return len(self.unmatched_truths)

    @property
    def false_positives(self) -> int:
        return len(self.unmatched_findings)


class MatchingPolicy(BaseModel):
    """Versioned rules for turning findings and truths into tp/fp/fn."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "1"
    line_tolerance: int = Field(default=3, ge=0)
    require_same_file: bool = True
    cwe_equivalence: dict[CweId, frozenset[CweId]] = Field(
        default_factory=lambda: dict(DEFAULT_EQUIVALENCE)
    )

    # ------------------------------------------------------------------ core

    def matches(self, truth: GroundTruth, finding: Finding) -> bool:
        """Whether one finding may be credited against one truth entry."""
        if self.require_same_file and finding.location.path != truth.path:
            return False
        if not self._line_within_tolerance(truth.line, finding):
            return False
        return finding.cwe == truth.cwe or finding.cwe in self.cwe_equivalence.get(
            truth.cwe, frozenset()
        )

    def _line_within_tolerance(self, truth_line: int, finding: Finding) -> bool:
        """Distance to the finding's line *range*, not just its first line."""
        start, end = finding.location.start_line, finding.location.end_line
        if start <= truth_line <= end:
            return True
        distance = start - truth_line if truth_line < start else truth_line - end
        return distance <= self.line_tolerance

    def match_all(self, truths: Sequence[GroundTruth], findings: Sequence[Finding]) -> MatchResult:
        """Greedy one-to-one assignment, nearest finding first.

        Deterministic by construction: candidates are ordered by line
        distance and then by finding id, so shuffling the inputs cannot
        change the score.
        """
        taken: set[int] = set()
        pairs: list[tuple[int, int]] = []
        for truth_index, truth in enumerate(truths):
            if truth.variant == "fixed":
                # A truth entry on fixed code is not something to detect; any
                # finding near it is handled below as a false positive.
                continue
            candidates = sorted(
                (
                    (self._distance(truth.line, findings[i]), findings[i].finding_id, i)
                    for i in range(len(findings))
                    if i not in taken and self.matches(truth, findings[i])
                ),
            )
            if candidates:
                chosen = candidates[0][2]
                taken.add(chosen)
                pairs.append((truth_index, chosen))

        matched_truths = {t for t, _ in pairs}
        unmatched_truths = tuple(
            i
            for i, truth in enumerate(truths)
            if truth.variant == "vulnerable" and i not in matched_truths
        )
        unmatched_findings = tuple(i for i in range(len(findings)) if i not in taken)
        return MatchResult(
            pairs=tuple(pairs),
            unmatched_truths=unmatched_truths,
            unmatched_findings=unmatched_findings,
        )

    @staticmethod
    def _distance(truth_line: int, finding: Finding) -> int:
        start, end = finding.location.start_line, finding.location.end_line
        if start <= truth_line <= end:
            return 0
        return start - truth_line if truth_line < start else truth_line - end

    # ------------------------------------------------------------ comparison

    def assert_comparable(self, other: MatchingPolicy) -> None:
        """Refuse to compare results produced under different rules."""
        if self.version != other.version:
            raise ValueError(
                f"matching policy versions differ ({self.version} vs {other.version}); "
                "results produced under different policies are not comparable"
            )


def default_policy() -> MatchingPolicy:
    """Policy version 1, as documented in part 04 of the plan."""
    return MatchingPolicy()

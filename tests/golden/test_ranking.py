"""Part 12 golden test: T-12-07 (AC-12-1, AC-12-4).

A snapshot of the ranked order *and* the explanation beside each entry. Two
files would let them drift; one file means a change to the key that the
explanation does not describe fails here rather than shipping as an ordering
nobody can account for.

Regenerate with::

    python -m tests.golden.test_ranking --record
"""

from __future__ import annotations

import sys
from pathlib import Path

from caudit.finding_policy.ranking import explain, rank_findings
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Finding,
    ImpactKind,
    Reachability,
    ReviewReason,
)
from tests.conftest import make_finding

GOLDEN = Path(__file__).parent / "ranking" / "order.txt"

#: Ten findings chosen so every key component decides at least one pair:
#: severity, confidence, reachability, agreement, effort, and the tie-break.
_CASES: tuple[tuple[str, str, ImpactKind, Confidence, Reachability, int], ...] = (
    (
        "CWE-787",
        "unbounded copy into a fixed buffer",
        ImpactKind.MEMORY_CORRUPTION,
        Confidence.HIGH,
        Reachability.DEMONSTRATED,
        2,
    ),
    (
        "CWE-787",
        "second unbounded copy",
        ImpactKind.MEMORY_CORRUPTION,
        Confidence.HIGH,
        Reachability.DEMONSTRATED,
        1,
    ),
    (
        "CWE-416",
        "use after release on the error path",
        ImpactKind.MEMORY_CORRUPTION,
        Confidence.HIGH,
        Reachability.ARGUED,
        1,
    ),
    (
        "CWE-134",
        "attacker-controlled format string",
        ImpactKind.CODE_EXECUTION,
        Confidence.HIGH,
        Reachability.ARGUED,
        1,
    ),
    (
        "CWE-125",
        "read past the end of the array",
        ImpactKind.INFORMATION_DISCLOSURE,
        Confidence.MEDIUM,
        Reachability.ARGUED,
        1,
    ),
    (
        "CWE-476",
        "dereference of an unchecked allocation",
        ImpactKind.UNDEFINED_BEHAVIOR,
        Confidence.HIGH,
        Reachability.DEMONSTRATED,
        1,
    ),
    (
        "CWE-190",
        "narrowing conversion before the bound check",
        ImpactKind.INCORRECT_RESULT,
        Confidence.HIGH,
        Reachability.ARGUED,
        1,
    ),
    (
        "CWE-772",
        "handle leaked on the early return",
        ImpactKind.RESOURCE_EXHAUSTION,
        Confidence.MEDIUM,
        Reachability.UNKNOWN,
        1,
    ),
    (
        "CWE-457",
        "read of an uninitialised local",
        ImpactKind.UNDEFINED_BEHAVIOR,
        Confidence.HIGH,
        Reachability.UNKNOWN,
        1,
    ),
    (
        "CWE-415",
        "second release of the same allocation",
        ImpactKind.MEMORY_CORRUPTION,
        Confidence.MEDIUM,
        Reachability.ARGUED,
        1,
    ),
)

_TOOLS = ("clang-tidy", "clang-static-analyzer")


def _provenance(count: int) -> list[Provenance]:
    return [
        Provenance(
            producer=Producer.CLANG_TIDY if tool == "clang-tidy" else Producer.CSA,
            tool_name=tool,
            tool_version="18.1.8",
            rule_id="fixture-check",
        )
        for tool in _TOOLS[:count]
    ]


def fixture_findings() -> list[Finding]:
    """Ten findings, built the same way every time this runs."""
    findings: list[Finding] = []
    for cwe, message, kind, confidence, reachability, agreement in _CASES:
        base = make_finding(
            _provenance(agreement),
            cwe=cwe,
            message=message,
            confidence=confidence,
            confidence_reason=(
                ReviewReason.ALL_CITATIONS_RESOLVED
                if confidence is Confidence.HIGH
                else ReviewReason.ANALYZER_ONLY
            ),
        )
        findings.append(
            base.model_copy(
                update={
                    "impact": base.impact.model_copy(update={"kind": kind}),
                    "reachability": reachability,
                    "exploitability": Exploitability.UNKNOWN,
                }
            )
        )
    return findings


def render_order() -> str:
    """The ranked order with each entry's explanation, one per line."""
    lines = [
        f"{position:2d}. {finding.cwe} — {explain(finding)}"
        for position, finding in enumerate(rank_findings(fixture_findings()), start=1)
    ]
    return "\n".join(lines) + "\n"


def test_the_ten_finding_ranking_matches_the_committed_snapshot() -> None:
    """T-12-07: the order and the reasons for it, byte for byte."""
    assert render_order() == GOLDEN.read_text(encoding="utf-8"), (
        "the ranked order changed. If that is intended, re-record it and check that "
        "tests/unit/test_report_ranking.py still describes the new key."
    )


def test_the_snapshot_explains_every_position() -> None:
    """AC-12-4: no entry is placed without a reason beside it."""
    lines = GOLDEN.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(_CASES)
    for line in lines:
        for term in ("severity", "confidence", "reachability", "fix"):
            assert term in line, f"{term!r} missing from {line!r}"


def test_the_snapshot_is_a_total_order_over_distinct_findings() -> None:
    """T-12-07's premise: ten distinct findings, so the snapshot means something."""
    findings = fixture_findings()
    assert len({finding.finding_id for finding in findings}) == len(_CASES)


if __name__ == "__main__":  # pragma: no cover - developer tool
    if "--record" in sys.argv:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(render_order(), encoding="utf-8", newline="\n")
        print(f"recorded {GOLDEN}")
    else:
        print(render_order(), end="")

"""Part 12's ranking: T-12-01 to T-12-08 (AC-12-1 to AC-12-4).

The load-bearing test here is T-12-04. Everything else checks that the order is
the documented one; that one checks that a model cannot influence it, which is
the reason this module exists rather than a `sorted()` call at the render site.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import CitationResolver
from caudit.evidence.store import SourceStore
from caudit.finding_policy.ranking import (
    EffortEstimate,
    RankInputs,
    effort_of,
    explain,
    provenance_agreement,
    rank_findings,
    rank_inputs,
    rank_key,
    severity_of,
)
from caudit.model.evidence import EvidenceItem, EvidenceKind, Producer, Provenance
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Finding,
    ImpactKind,
    Reachability,
    ReviewReason,
    Severity,
)
from caudit.report.sections import build_sections
from tests.conftest import demo_coverage, make_finding, make_region


def _tuned(finding: Finding, **updates: object) -> Finding:
    """A finding with fields replaced, bypassing validation deliberately.

    ``model_copy`` skips the validators, which is what a test needs to build
    the combinations a well-behaved pipeline would refuse to produce — the
    whole point being to watch the ranking handle them.
    """
    return finding.model_copy(update=updates)


def _analyzer(tool: str, rule: str = "check") -> Provenance:
    return Provenance(
        producer=Producer.CLANG_TIDY if tool == "clang-tidy" else Producer.CSA,
        tool_name=tool,
        tool_version="18.1.8",
        rule_id=rule,
    )


# ------------------------------------------------------------------- T-12-01


def test_the_order_is_total_and_shuffling_the_input_does_not_change_it(
    provenance: list[Provenance],
) -> None:
    """T-12-01 (AC-12-1): 30 findings with overlapping attributes, one answer."""
    findings: list[Finding] = []
    for index in range(30):
        base = make_finding(
            provenance,
            cwe=("CWE-787", "CWE-476", "CWE-190")[index % 3],
            path=f"src/f{index % 4}.c",
            start_line=index + 1,
            message=f"defect number {index}",
        )
        findings.append(
            _tuned(
                base,
                reachability=list(Reachability)[index % 3],
                confidence=(Confidence.HIGH, Confidence.MEDIUM)[index % 2],
            )
        )

    expected = [f.finding_id for f in rank_findings(findings)]
    assert len({f.finding_id for f in findings}) == 30

    rng = random.Random(20260813)
    for _ in range(8):
        shuffled = list(findings)
        rng.shuffle(shuffled)
        assert [f.finding_id for f in rank_findings(shuffled)] == expected

    keys = [rank_key(f) for f in findings]
    assert len(set(keys)) == len(keys), "two findings compared equal, so the order is not total"


# ------------------------------------------------------------------- T-12-02


def test_two_findings_alike_but_for_their_id_break_the_tie_deterministically(
    provenance: list[Provenance],
) -> None:
    """T-12-02 (AC-12-1): the sixth key component is the only one left."""
    left = make_finding(provenance, message="one")
    right = make_finding(provenance, message="two")

    assert rank_inputs(left) == rank_inputs(right)
    assert rank_key(left)[:-1] == rank_key(right)[:-1]
    assert rank_key(left)[-1] != rank_key(right)[-1]

    ordered = rank_findings([right, left])
    assert [f.finding_id for f in ordered] == sorted([left.finding_id, right.finding_id])


# ------------------------------------------------------------------- T-12-03


def test_review_items_never_enter_the_confirmed_ranking(
    provenance: list[Provenance], repo: Path
) -> None:
    """T-12-03 (AC-12-2): the split happens before the ranking, not after."""
    store = SourceStore(repo, revision="ranking-test")
    resolver = CitationResolver(store, EvidenceBundle(store))

    confirmed = [
        make_finding(provenance, message=f"confirmed {n}", confidence=Confidence.HIGH)
        for n in range(3)
    ]
    review = [
        make_finding(
            provenance,
            message=f"review {n}",
            confidence=Confidence.REVIEW_REQUIRED,
            confidence_reason=ReviewReason.SYMBOL_UNRESOLVED,
        )
        for n in range(3)
    ]

    sections = build_sections([*review, *confirmed], resolver=resolver, coverage=demo_coverage())
    review_ids = {f.finding_id for f in review}
    assert all(f.finding_id not in review_ids for f in sections.confirmed)
    assert all(f.is_confirmed for f in sections.confirmed)
    assert all(not f.is_confirmed for f in sections.needs_review)


def test_a_review_item_cannot_outrank_a_confirmed_finding_even_when_more_severe(
    provenance: list[Provenance],
) -> None:
    """AC-12-2 as a property of the key, not only of the call graph.

    Confidence is the second key component and ``review_required`` is its worst
    value, so even a critical-impact review item sorts below a low-severity
    confirmed finding of the same severity band. The sections keep them apart
    anyway; this is the belt to that pair of braces.
    """
    strong_review = _tuned(
        make_finding(
            provenance,
            cwe="CWE-787",
            message="review",
            confidence=Confidence.REVIEW_REQUIRED,
            confidence_reason=ReviewReason.HASH_MISMATCH,
        ),
        reachability=Reachability.DEMONSTRATED,
    )
    weak_confirmed = make_finding(provenance, cwe="CWE-787", message="confirmed")

    assert rank_findings([strong_review, weak_confirmed])[0] is weak_confirmed


# ------------------------------------------------------------------- T-12-04


def test_the_rank_ignores_what_the_model_said_about_its_own_finding(
    provenance: list[Provenance],
) -> None:
    """T-12-04 (AC-12-3): every ranking input is a verified value.

    The gate downgraded this finding to ``medium``. The model's ``impact``
    still says ``critical`` — nothing rewrites it, because the argument the
    model made is kept as it was made. Ranking simply does not read it.
    """
    base = make_finding(provenance, cwe="CWE-787", message="overflow")
    boastful = _tuned(
        base,
        confidence=Confidence.MEDIUM,
        impact=base.impact.model_copy(update={"severity": Severity.CRITICAL}),
    )
    modest = _tuned(
        base.model_copy(update={"finding_id": base.finding_id + "-b"}),
        confidence=Confidence.HIGH,
        impact=base.impact.model_copy(update={"severity": Severity.LOW}),
    )

    assert boastful.impact.severity is Severity.CRITICAL
    assert severity_of(boastful) is severity_of(modest) is Severity.HIGH

    # The self-reported severity moves nothing; the gate's confidence does.
    assert rank_findings([boastful, modest])[0] is modest


def test_severity_comes_from_the_family_and_is_only_ever_lowered(
    provenance: list[Provenance],
) -> None:
    """AC-12-3: the impact kind is a ceiling, never a floor."""
    out_of_bounds = make_finding(provenance, cwe="CWE-787", message="oob")
    assert severity_of(out_of_bounds) is Severity.HIGH

    # An impact kind that cannot do as much lowers it.
    quieter = _tuned(
        out_of_bounds,
        impact=out_of_bounds.impact.model_copy(update={"kind": ImpactKind.INCORRECT_RESULT}),
    )
    assert severity_of(quieter) is Severity.LOW

    # A louder impact kind on a quieter family does not raise it above the
    # family — but it also cannot be capped below what the family says.
    leak = make_finding(provenance, cwe="CWE-772", message="leak")
    louder = _tuned(leak, impact=leak.impact.model_copy(update={"kind": ImpactKind.CODE_EXECUTION}))
    assert severity_of(leak) is severity_of(louder) is Severity.MEDIUM


# ------------------------------------------------------------------- T-12-05


def test_severity_outranks_reachability(provenance: list[Provenance]) -> None:
    """T-12-05 (AC-12-1): the documented key precedence, first term first."""
    high_unknown = make_finding(provenance, cwe="CWE-787", message="high severity")
    medium_demonstrated = _tuned(
        make_finding(provenance, cwe="CWE-190", message="medium severity"),
        reachability=Reachability.DEMONSTRATED,
        exploitability=Exploitability.DEMONSTRATED,
    )

    assert severity_of(high_unknown) is Severity.HIGH
    assert severity_of(medium_demonstrated) is Severity.MEDIUM
    assert rank_findings([medium_demonstrated, high_unknown])[0] is high_unknown


def test_reachability_orders_demonstrated_above_argued_above_unknown(
    provenance: list[Provenance],
) -> None:
    """AC-12-1: the third key component, with the first two held equal."""
    findings = [
        _tuned(
            make_finding(provenance, cwe="CWE-787", message=f"reach {reach}"),
            reachability=reach,
        )
        for reach in (Reachability.UNKNOWN, Reachability.DEMONSTRATED, Reachability.ARGUED)
    ]
    assert [f.reachability for f in rank_findings(findings)] == [
        Reachability.DEMONSTRATED,
        Reachability.ARGUED,
        Reachability.UNKNOWN,
    ]


# ------------------------------------------------------------------- T-12-06


def test_two_analyzers_agreeing_outranks_one(provenance: list[Provenance]) -> None:
    """T-12-06 (AC-12-1): independent corroboration, all else equal."""
    corroborated = _tuned(
        make_finding(provenance, cwe="CWE-787", message="agreed"),
        provenance=[_analyzer("clang-tidy"), _analyzer("clang-static-analyzer")],
    )
    alone = make_finding(provenance, cwe="CWE-787", message="alone")

    assert provenance_agreement(corroborated) == 2
    assert provenance_agreement(alone) == 1
    assert rank_findings([alone, corroborated])[0] is corroborated


def test_a_model_and_an_index_are_not_a_second_opinion(provenance: list[Provenance]) -> None:
    """AC-12-1, AC-12-3: only external analyzers count as agreement.

    One analyzer plus a model plus the index is still one analyzer. Counting
    the other two would let a finding corroborate itself with the components
    that produced it.
    """
    padded = _tuned(
        make_finding(provenance, cwe="CWE-787", message="padded"),
        provenance=[
            _analyzer("clang-tidy"),
            Provenance(producer=Producer.LLM, tool_name="gemini-flash-latest", tool_version="2"),
            Provenance(producer=Producer.INDEX, tool_name="libclang", tool_version="18.1.1"),
        ],
    )
    assert provenance_agreement(padded) == 1


# ------------------------------------------------------------------- effort


def test_effort_is_measured_from_the_span_of_the_cited_evidence(
    provenance: list[Provenance],
) -> None:
    """AC-12-3: a checkable proxy for remediation scope, not an opinion."""
    local = make_finding(provenance, cwe="CWE-787", message="local")
    assert effort_of(local) is EffortEstimate.LOCAL

    same_file = _tuned(
        local,
        evidence=[
            *local.evidence,
            EvidenceItem.create(
                kind=EvidenceKind.SUPPORTING_CODE,
                region=make_region("src/main.c", 40, 48),
                provenance=provenance,
            ),
        ],
    )
    assert effort_of(same_file) is EffortEstimate.FUNCTION

    across_files = _tuned(
        local,
        evidence=[
            *local.evidence,
            EvidenceItem.create(
                kind=EvidenceKind.SUPPORTING_CODE,
                region=make_region("src/other.c", 4, 9),
                provenance=provenance,
            ),
        ],
    )
    assert effort_of(across_files) is EffortEstimate.CROSS_MODULE


def test_a_cheap_fix_surfaces_above_an_expensive_one_of_equal_weight(
    provenance: list[Provenance],
) -> None:
    """AC-12-1: effort ascending, as the fifth key component."""
    cheap = make_finding(provenance, cwe="CWE-787", message="cheap")
    expensive = _tuned(
        make_finding(provenance, cwe="CWE-787", message="expensive"),
        evidence=[
            *cheap.evidence,
            EvidenceItem.create(
                kind=EvidenceKind.SUPPORTING_CODE,
                region=make_region("src/elsewhere.c", 3, 7),
                provenance=provenance,
            ),
        ],
    )
    assert rank_findings([expensive, cheap])[0] is cheap


# ------------------------------------------------------------------- T-12-08


def test_the_explanation_names_every_input_consistently_with_its_value(
    provenance: list[Provenance],
) -> None:
    """T-12-08 (AC-12-4): the string is built from the key's own inputs."""
    finding = _tuned(
        make_finding(provenance, cwe="CWE-787", message="explained"),
        reachability=Reachability.ARGUED,
        provenance=[_analyzer("clang-tidy"), _analyzer("clang-static-analyzer")],
    )
    inputs = rank_inputs(finding)
    text = explain(finding, inputs)

    assert str(inputs.severity) in text
    assert str(inputs.confidence) in text
    assert str(inputs.reachability) in text
    assert str(inputs.effort) in text
    assert "2 independent analyzers agree" in text
    # The severity in the sentence is the ranked one, not the finding's own.
    assert str(finding.impact.kind) in text


def test_the_explanation_agrees_with_the_order_for_every_finding(
    provenance: list[Provenance],
) -> None:
    """AC-12-4: no finding is placed by a term its explanation omits."""
    findings = [
        _tuned(
            make_finding(provenance, cwe=cwe, message=f"{cwe}-{n}"),
            reachability=reach,
        )
        for n, (cwe, reach) in enumerate(
            [
                ("CWE-787", Reachability.DEMONSTRATED),
                ("CWE-190", Reachability.UNKNOWN),
                ("CWE-476", Reachability.ARGUED),
            ]
        )
    ]
    for finding in rank_findings(findings):
        inputs = rank_inputs(finding)
        assert explain(finding) == explain(finding, inputs)
        for value in (inputs.severity, inputs.confidence, inputs.reachability, inputs.effort):
            assert str(value) in explain(finding)


def test_rank_inputs_reject_a_negative_agreement_count() -> None:
    """The model is a schema, so an impossible input is not representable."""
    with pytest.raises(ValueError, match="greater than or equal to 0"):
        RankInputs(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            reachability=Reachability.ARGUED,
            effort=EffortEstimate.LOCAL,
            provenance_agreement=-1,
        )

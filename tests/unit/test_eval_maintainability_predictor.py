"""Part 13's finding-to-hazard bridge: T-13-25 to T-13-30 (AC-13-13, AC-13-14).

The predictor was deliberately absent until now, for a reason worth restating:
`MaintainabilityImpact` is five prose fields, `score_maintainability` wants one
of five categories, and two of those categories have no signal at all. A mapping
written anyway would score 0.0 on those two by construction and understate the
tool for a reason that is a fact about the schema rather than about the tool.

So the predictor abstains and the score refuses, and these tests hold both to
it. T-13-27 and T-13-29 are the two that matter: the first says a signal-free
finding produces `None` rather than a fallback category, and the second says a
labelled category the predictor cannot reach withholds the macro-average
instead of dragging it down.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from caudit.eval.maintainability import (
    UNCOVERABLE,
    LabelSet,
    MaintainabilityCategory,
    MaintainabilityCoverageError,
    MaintainabilityLabel,
    MaintainabilityScore,
    PredictorCoverage,
    macro_f1,
    predict_categories,
    predict_category,
    score_maintainability,
)
from caudit.model.cwe import ALLOWLIST, WeaknessFamily
from caudit.model.finding import Finding
from tests.conftest import make_evidence, make_finding, make_region

POLICIES = {"matching": "1", "prompt": "2"}


def _finding(
    provenance: list[object],
    *,
    cwe: str = "CWE-787",
    regions: tuple[tuple[str, int], ...] = (),
) -> Finding:
    """A finding whose cited evidence spans exactly ``regions``.

    ``make_finding`` gives one evidence item at the location, which is what
    ``effort_of`` reads as ``local``. Extra regions are what make it ``function``
    or ``cross_module``, so they are supplied here rather than assumed.
    """
    base = make_finding(provenance, cwe=cwe)  # type: ignore[arg-type]
    if not regions:
        return base
    evidence = list(base.evidence) + [
        make_evidence(provenance, make_region(path, line, line))  # type: ignore[arg-type]
        for path, line in regions
    ]
    return Finding.model_validate({**base.model_dump(), "evidence": evidence})


def _label(case_id: str, category: MaintainabilityCategory) -> MaintainabilityLabel:
    return MaintainabilityLabel(
        case_id=case_id,
        category=category,
        path=PurePosixPath("src/alloc.c"),
        line=42,
        labelers=["alice", "bob"],
        agreed=True,
    )


# ------------------------------------------------------------ the two signals


def test_memory_lifetime_predicts_ownership_ambiguity(provenance: list[object]) -> None:
    """T-13-25: the weakness family wins, and it wins over the evidence span.

    A use-after-free whose evidence sits in two files is an ownership question,
    not a coupling one — which is only observable because the family is
    consulted first.
    """
    local = _finding(provenance, cwe="CWE-416")
    spread = _finding(provenance, cwe="CWE-416", regions=(("src/other.c", 90),))

    assert predict_category(local) is MaintainabilityCategory.OWNERSHIP_AMBIGUITY
    assert predict_category(spread) is MaintainabilityCategory.OWNERSHIP_AMBIGUITY


def test_evidence_span_predicts_coupling_and_complexity(provenance: list[object]) -> None:
    """T-13-26: how far the verified citations reach, for families with no rule."""
    cross_module = _finding(provenance, cwe="CWE-787", regions=(("src/other.c", 90),))
    within_function = _finding(provenance, cwe="CWE-787", regions=(("src/main.c", 90),))

    assert predict_category(cross_module) is MaintainabilityCategory.COUPLING
    assert predict_category(within_function) is MaintainabilityCategory.COMPLEXITY


def test_a_signal_free_finding_abstains(provenance: list[object]) -> None:
    """T-13-27: `None`, never a fallback bucket.

    Both halves of the abstention live here. A single-region finding has no
    span to read, and `CWE-772` is a resource leak — genuinely ambiguous between
    ownership (nobody owns the close) and error handling (the close is skipped
    on the failure path), so the family table declines to guess between them.
    """
    assert predict_category(_finding(provenance, cwe="CWE-787")) is None
    assert predict_category(_finding(provenance, cwe="CWE-772")) is None


def test_no_allowlisted_weakness_reaches_an_uncoverable_category(
    provenance: list[object],
) -> None:
    """T-13-28: the declared limit is real, across every CWE the tool may emit.

    `UNCOVERABLE` is a claim about the schema, so it is checked against the
    whole allowlist rather than against a handful of chosen findings. If some
    future family table entry reached `error_handling`, the declaration would be
    stale and the refusal in `score_maintainability` would be refusing a score
    it could actually compute.
    """
    for cwe in ALLOWLIST:
        for regions in ((), (("src/main.c", 90),), (("src/other.c", 90),)):
            predicted = predict_category(_finding(provenance, cwe=cwe, regions=regions))
            assert predicted not in UNCOVERABLE, (
                f"{cwe} produced {predicted}, which UNCOVERABLE declares unreachable"
            )


def test_uncoverable_names_exactly_the_categories_with_no_route() -> None:
    """T-13-28: and it is neither too wide nor too narrow.

    Derived from the tables rather than restated, so widening a table without
    narrowing `UNCOVERABLE` fails here.
    """
    from caudit.eval.maintainability import _CATEGORY_BY_EFFORT, _CATEGORY_BY_FAMILY

    reachable = set(_CATEGORY_BY_FAMILY.values()) | set(_CATEGORY_BY_EFFORT.values())
    assert set(MaintainabilityCategory) - reachable == UNCOVERABLE
    assert WeaknessFamily.RESOURCE_LEAK not in _CATEGORY_BY_FAMILY


# ------------------------------------------------------------- the refusal


def test_an_uncoverable_label_withholds_the_average(provenance: list[object]) -> None:
    """T-13-29: `None` with a reason — the whole point of the exercise.

    The alternative this replaces is a macro-F1 of 0.0 for `error_handling`,
    averaged in beside a real number, reported as the tool's maintainability
    score. The per-category figures survive, because *which* category was
    unreachable is the part a reader can act on.
    """
    labels = LabelSet(
        version="1",
        labels=[
            _label("case-1", MaintainabilityCategory.OWNERSHIP_AMBIGUITY),
            _label("case-2", MaintainabilityCategory.ERROR_HANDLING),
        ],
    )
    by_case = {
        "case-1": [_finding(provenance, cwe="CWE-416")],
        "case-2": [_finding(provenance, cwe="CWE-772")],
    }
    predicted, coverage = predict_categories(by_case, labels)
    score = score_maintainability(
        labels, predicted, [1.0], policy_versions=POLICIES, coverage=coverage
    )

    assert score.macro_f1 is None
    assert score.refusal is not None
    assert "error_handling" in score.refusal
    assert score.per_category_f1[MaintainabilityCategory.OWNERSHIP_AMBIGUITY] == 1.0
    assert "refused" in score.describe()

    assert coverage.categories_uncovered == [MaintainabilityCategory.ERROR_HANDLING]
    assert coverage.predicted == 1
    assert coverage.abstained == 1
    with pytest.raises(MaintainabilityCoverageError, match="error_handling"):
        coverage.assert_covers()


def test_a_fully_covered_label_set_scores_normally(provenance: list[object]) -> None:
    """T-13-30: the refusal is narrow. Reachable categories still get a number."""
    labels = LabelSet(
        version="1",
        labels=[
            _label("case-1", MaintainabilityCategory.OWNERSHIP_AMBIGUITY),
            _label("case-2", MaintainabilityCategory.COUPLING),
        ],
    )
    by_case = {
        "case-1": [_finding(provenance, cwe="CWE-416")],
        "case-2": [_finding(provenance, cwe="CWE-787", regions=(("src/other.c", 90),))],
    }
    predicted, coverage = predict_categories(by_case, labels)
    score = score_maintainability(
        labels, predicted, [1.0], policy_versions=POLICIES, coverage=coverage
    )

    truth = {case: label.category for case, label in labels.by_case().items()}
    expected = macro_f1(truth, predicted)
    assert coverage.categories_uncovered == []
    assert coverage.refusal is None
    assert score.refusal is None
    assert score.macro_f1 == pytest.approx(sum(expected.values()) / len(expected))
    assert score.macro_f1 == pytest.approx(1.0)
    coverage.assert_covers()


def test_the_top_ranked_finding_speaks_for_its_case(provenance: list[object]) -> None:
    """T-13-30: one case, one prediction, taken from the report's own order.

    The high-severity memory-lifetime finding outranks the out-of-bounds one, so
    the case is `ownership_ambiguity`. Consulting the runner-up when the leader
    abstains would turn abstention into a search for any answer at all, so a
    case led by an abstaining finding abstains too.
    """
    decided = predict_categories(
        {
            "case-1": [
                _finding(provenance, cwe="CWE-787", regions=(("src/other.c", 90),)),
                _finding(provenance, cwe="CWE-416"),
            ]
        }
    )[0]
    assert decided["case-1"] is MaintainabilityCategory.OWNERSHIP_AMBIGUITY

    # A leader with no signal abstains for the case, even with a mappable
    # finding behind it.
    predicted, coverage = predict_categories({"case-1": [_finding(provenance, cwe="CWE-772")]})
    assert predicted == {}
    assert coverage.abstained == 1

    empty, no_findings = predict_categories({"case-1": []})
    assert empty == {}
    assert no_findings.abstained == 1


def test_a_score_cannot_hide_a_refusal_or_explain_a_number() -> None:
    """T-13-29: `macro_f1` and `refusal` are set together, in both directions."""
    common = {
        "label_set_version": "1",
        "ndcg_at_10": 1.0,
        "recommendation_useful_rate": 1.0,
        "recommendations_reviewed": 0,
        "agreement": {"cases": 0, "agreed": 0, "raw_agreement": 1.0, "kappa": None},
        "cases_scored": 0,
    }
    with pytest.raises(ValueError, match="set together"):
        MaintainabilityScore(**common, macro_f1=None, refusal=None)
    with pytest.raises(ValueError, match="set together"):
        MaintainabilityScore(**common, macro_f1=0.5, refusal="because")


def test_coverage_describes_what_it_could_name() -> None:
    """T-13-28: the counts are published, so heavy abstention is visible."""
    coverage = PredictorCoverage(
        predicted=1,
        abstained=9,
        categories_predicted=[MaintainabilityCategory.COUPLING],
    )
    assert coverage.cases == 10
    assert "1/10" in coverage.describe()
    assert "coupling" in coverage.describe()
    assert "9 abstained" in coverage.describe()
    assert PredictorCoverage(predicted=0, abstained=0).describe().endswith("0 abstained")

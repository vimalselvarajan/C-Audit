"""Part 13's maintainability set: T-13-05 to T-13-08 (AC-13-5 to AC-13-7).

The two labelling rules are the point. Everything else here is arithmetic that
can be checked by hand — which is exactly what T-13-06 and T-13-08 do, against
values computed on paper rather than against the implementation's own output.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError

from caudit.eval.maintainability import (
    AgreementReport,
    LabelSet,
    MaintainabilityCategory,
    MaintainabilityLabel,
    RecommendationVerdict,
    agreement,
    load_labels,
    macro_f1,
    ndcg_at_k,
    score_maintainability,
    unlabelled,
    write_labels,
)

POLICIES = {"matching": "1", "prompt": "2"}


def _label(case_id: str = "case-1", **overrides: object) -> MaintainabilityLabel:
    fields: dict[str, object] = {
        "case_id": case_id,
        "category": MaintainabilityCategory.OWNERSHIP_AMBIGUITY,
        "path": PurePosixPath("src/alloc.c"),
        "line": 42,
        "labelers": ["alice", "bob"],
        "agreed": True,
        "source": "manual review of the allocation and free paths",
    }
    fields.update(overrides)
    return MaintainabilityLabel.model_validate(fields)


# ------------------------------------------------------------------- T-13-05


def test_a_case_with_one_labeler_is_refused() -> None:
    """T-13-05 (AC-13-5): a single-labeller set measures one person's taste."""
    with pytest.raises(ValidationError, match="at least"):
        _label(labelers=["alice"])


def test_one_person_listed_twice_is_still_one_person() -> None:
    """AC-13-5: the rule is two *independent* labellers, not two entries."""
    with pytest.raises(ValidationError, match="1 distinct labeller"):
        _label(labelers=["alice", "alice"])


def test_a_label_derived_from_the_tools_own_checks_is_refused() -> None:
    """The spec's named trap: scoring the tool against its own output."""
    for source in ("clang-tidy readability-function-size", "adjudicated from caudit output"):
        with pytest.raises(ValidationError, match="score the tool against"):
            _label(source=source)


def test_an_unadjudicated_disagreement_is_refused() -> None:
    """A label with a hidden third opinion in it cannot be audited."""
    with pytest.raises(ValidationError, match="no adjudicator note"):
        _label(agreed=False)

    resolved = _label(agreed=False, adjudicator_note="both readings apply; coupling dominates")
    assert not resolved.agreed


def test_duplicate_case_ids_in_a_label_set_are_refused() -> None:
    with pytest.raises(ValidationError, match="duplicate case id"):
        LabelSet(version="1", labels=[_label("same"), _label("same")])


# ------------------------------------------------------------------- T-13-06


def test_agreement_matches_the_hand_computed_value() -> None:
    """T-13-06 (AC-13-6): 20 cases with a known disagreement pattern.

    Fifteen of twenty agreed, so raw agreement is 0.75. The categories are
    split 12/8, so chance agreement is 0.6² + 0.4² = 0.52 and kappa is
    (0.75 - 0.52) / (1 - 0.52) = 0.479166…, computed on paper.
    """
    labels = [
        _label(
            f"case-{index}",
            category=(
                MaintainabilityCategory.COMPLEXITY
                if index < 12
                else MaintainabilityCategory.COUPLING
            ),
            agreed=index < 15,
            adjudicator_note=None if index < 15 else "adjudicated to the majority reading",
        )
        for index in range(20)
    ]
    report = agreement(labels)

    assert report.cases == 20
    assert report.agreed == 15
    assert report.raw_agreement == pytest.approx(0.75)
    assert report.kappa is not None
    assert report.kappa == pytest.approx((0.75 - 0.52) / (1 - 0.52))
    assert "15/20" in report.describe()


def test_a_single_category_leaves_kappa_undefined_rather_than_perfect() -> None:
    """Everyone agreeing on the only category available has measured nothing."""
    labels = [_label(f"case-{index}") for index in range(6)]
    report = agreement(labels)

    assert report.raw_agreement == pytest.approx(1.0)
    assert report.kappa is None
    assert "undefined" in report.describe()


def test_an_empty_set_agrees_vacuously() -> None:
    assert agreement([]) == AgreementReport(cases=0, agreed=0, raw_agreement=1.0, kappa=None)


# ------------------------------------------------------------------- T-13-08


def test_ndcg_matches_the_hand_computed_value() -> None:
    """T-13-08 (AC-13-7): a ranking with a known ideal.

    Relevances [0, 1] in that order: DCG = 0/log2(2) + 1/log2(3) = 0.63093.
    The ideal order is [1, 0]: DCG = 1/log2(2) = 1.0. So nDCG = 0.63093.
    """
    assert ndcg_at_k([0.0, 1.0], k=2) == pytest.approx(1 / 1.5849625007211562)
    assert ndcg_at_k([1.0, 0.0], k=2) == pytest.approx(1.0)


def test_ndcg_rewards_putting_the_important_findings_first() -> None:
    """AC-13-7: this is what part 12's ranking is being measured on."""
    best = ndcg_at_k([3.0, 2.0, 1.0, 0.0])
    worst = ndcg_at_k([0.0, 1.0, 2.0, 3.0])
    assert best == pytest.approx(1.0)
    assert worst < best


def test_ndcg_is_vacuously_one_when_nothing_is_relevant() -> None:
    """There was no ordering to get wrong."""
    assert ndcg_at_k([0.0, 0.0, 0.0]) == pytest.approx(1.0)


def test_a_relevant_finding_pushed_past_the_cutoff_scores_zero() -> None:
    """The cutoff is the point: nDCG@10 is about the first screenful.

    The only relevant finding is ranked eleventh. At ``k=10`` the ideal
    ordering would have had it first, and this ranking has nothing — so the
    score is 0.0, not a near-miss. Widening the cutoff to 11 finds it, heavily
    discounted for its position.
    """
    ranked = [0.0] * 10 + [5.0]
    assert ndcg_at_k(ranked, k=10) == pytest.approx(0.0)

    widened = ndcg_at_k(ranked, k=11)
    assert 0.0 < widened < 1.0


def test_ndcg_rejects_a_non_positive_cutoff() -> None:
    with pytest.raises(ValueError, match="k must be positive"):
        ndcg_at_k([1.0], k=0)


# ------------------------------------------------------------------- T-13-07


def test_macro_f1_excludes_categories_nobody_scored() -> None:
    """The same convention part 04 applies to weakness families."""
    truth = {"a": MaintainabilityCategory.COMPLEXITY, "b": MaintainabilityCategory.COUPLING}
    predicted = {"a": MaintainabilityCategory.COMPLEXITY, "b": MaintainabilityCategory.COMPLEXITY}

    scores = macro_f1(truth, predicted)
    assert set(scores) == {MaintainabilityCategory.COMPLEXITY, MaintainabilityCategory.COUPLING}
    # complexity: tp=1, fp=1 → precision 0.5, recall 1.0 → F1 = 2/3.
    assert scores[MaintainabilityCategory.COMPLEXITY] == pytest.approx(2 / 3)
    # coupling: predicted nowhere, so recall 0 and F1 0.
    assert scores[MaintainabilityCategory.COUPLING] == pytest.approx(0.0)


def test_all_three_metrics_are_reported_and_none_of_them_is_merged() -> None:
    """T-13-07 (AC-13-7): three questions, three numbers, no average of them."""
    labels = LabelSet(
        version="1",
        labels=[
            _label("a", category=MaintainabilityCategory.COMPLEXITY),
            _label("b", category=MaintainabilityCategory.COUPLING),
        ],
        verdicts=[
            RecommendationVerdict(case_id="a", accurate=True, actionable=True, reviewer="carol"),
            RecommendationVerdict(case_id="b", accurate=True, actionable=False, reviewer="carol"),
        ],
    )
    score = score_maintainability(
        labels,
        {"a": MaintainabilityCategory.COMPLEXITY, "b": MaintainabilityCategory.COUPLING},
        [3.0, 2.0],
        policy_versions=POLICIES,
    )

    assert score.macro_f1 == pytest.approx(1.0)
    assert score.ndcg_at_10 == pytest.approx(1.0)
    # One of two recommendations was both accurate and actionable.
    assert score.recommendation_useful_rate == pytest.approx(0.5)
    assert score.recommendations_reviewed == 2
    assert score.agreement.cases == 2
    assert score.policy_versions == POLICIES

    # No field or property combines the three, by design.
    names = set(type(score).model_fields) | {
        name for name in dir(type(score)) if isinstance(getattr(type(score), name, None), property)
    }
    assert not any(word in name for name in names for word in ("overall", "combined", "total"))


def test_an_accurate_but_unactionable_recommendation_is_not_useful() -> None:
    """The two halves fail independently, so they are two booleans."""
    verdict = RecommendationVerdict(case_id="a", accurate=True, actionable=False, reviewer="carol")
    assert not verdict.useful


# ------------------------------------------------------------------- the set


def test_a_missing_label_file_reads_as_an_empty_set(tmp_path: Path) -> None:
    """The labels are human work this repository does not have yet."""
    labels = load_labels(tmp_path / "labels.json")
    assert labels.is_empty
    assert labels.case_ids == []
    assert "no label set" in labels.note


def test_the_repository_ships_no_labels_yet() -> None:
    """A guard against a set appearing without the two rules being applied."""
    labels = load_labels(Path("benchmarks/maintainability/labels.json"))
    assert labels.is_empty, (
        "labels.json now exists. Check that every case names two independent "
        "labellers and that none was adjudicated from analyzer output; the loader "
        "enforces both, so this assertion is what should be updated."
    )


def test_a_label_set_round_trips(tmp_path: Path) -> None:
    labels = LabelSet(version="1", labels=[_label("a"), _label("b")])
    written = write_labels(labels, tmp_path / "labels.json")
    assert load_labels(written) == labels


def test_unlabelled_cases_are_reported_so_coverage_is_visible() -> None:
    labels = LabelSet(version="1", labels=[_label("a")])
    assert unlabelled(["a", "b", "c"], labels) == ["b", "c"]


def test_scoring_an_empty_set_produces_zeros_rather_than_an_exception() -> None:
    """The harness has to be runnable before the corpus exists."""
    score = score_maintainability(LabelSet(version="0"), {}, [], policy_versions=POLICIES)
    assert score.macro_f1 == pytest.approx(0.0)
    assert score.cases_scored == 0
    assert score.recommendations_reviewed == 0

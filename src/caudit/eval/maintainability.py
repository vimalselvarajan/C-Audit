"""The labelled maintainability set, and how it is scored.

The spec defines maintainability for the report-only MVP as identifying and
explaining security-relevant *maintenance hazards* — not style, not metrics —
across five categories. Two rules about the labels matter more than any scoring
formula, and both are enforced here rather than described in a README:

**At least two independent labellers per case.** A single-labeller set measures
one person's taste and reports it as a benchmark. :func:`load_labels` refuses a
case with fewer, and the inter-labeller agreement is computed and published
*with* the scores rather than kept as a footnote.

**Labels are not derived from ``clang-tidy`` output.** Deriving them from the
tool's own checks scores the tool against itself; the spec names this trap
directly. A label recording a check id as its source is rejected here — the one
place that rule can be made checkable rather than hoped for.

Scoring reports three numbers and never one: category macro-F1, ranking quality
(nDCG@10) for the top findings, and the share of recommendations a reviewer
judged factually accurate *and* actionable. They answer different questions —
did we categorise the hazard, did we put the important ones first, and was the
advice any good — and an average of the three would hide which one moved.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.finding_policy.ranking import EffortEstimate, effort_of, rank_findings
from caudit.model.cwe import WeaknessFamily, family_of
from caudit.model.finding import Finding

__all__ = [
    "MINIMUM_LABELERS",
    "UNCOVERABLE",
    "AgreementReport",
    "LabelSet",
    "MaintainabilityCategory",
    "MaintainabilityCoverageError",
    "MaintainabilityLabel",
    "MaintainabilityScore",
    "PredictorCoverage",
    "RecommendationVerdict",
    "agreement",
    "load_labels",
    "macro_f1",
    "ndcg_at_k",
    "predict_categories",
    "predict_category",
    "score_maintainability",
]

#: The spec's rule, as a number this module can enforce.
MINIMUM_LABELERS: Final = 2


class MaintainabilityCategory(StrEnum):
    """The five hazards the spec names, and nothing else.

    Fixed deliberately. Letting the categories grow to match whatever the tool
    happens to detect would make the score a description of the tool rather
    than a measurement of it.
    """

    COMPLEXITY = "complexity"
    DUPLICATED_VALIDATION = "duplicated_validation"
    OWNERSHIP_AMBIGUITY = "ownership_ambiguity"
    COUPLING = "coupling"
    ERROR_HANDLING = "error_handling"


#: Sources a label may not come from. A label derived from an analyzer check is
#: the tool grading its own homework, and the spec calls it out by name.
_FORBIDDEN_SOURCES: Final[frozenset[str]] = frozenset(
    {"clang-tidy", "clang", "clang-static-analyzer", "scan-build", "caudit"}
)


class RecommendationVerdict(BaseModel):
    """A reviewer's judgement of one recommendation.

    Two independent booleans, because they fail independently: advice can be
    perfectly accurate and impossible to act on, and a plausible-sounding
    action can be wrong about the code. Collapsing them into "good" would lose
    which one to fix.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1)
    accurate: bool
    actionable: bool
    reviewer: str = Field(min_length=1)
    note: str = ""

    @property
    def useful(self) -> bool:
        return self.accurate and self.actionable


class MaintainabilityLabel(BaseModel):
    """One labelled maintenance hazard, with who labelled it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1)
    category: MaintainabilityCategory
    path: PurePosixPath
    line: int = Field(ge=1)
    #: Independent labellers, by identifier. At least two, and distinct: one
    #: person listed twice is one person.
    labelers: list[str] = Field(min_length=MINIMUM_LABELERS)
    #: Whether the labellers agreed on the category without adjudication.
    agreed: bool
    #: Required when they did not agree. An adjudicated label whose adjudication
    #: nobody wrote down is a label with a hidden third opinion in it.
    adjudicator_note: str | None = None
    #: Where the label came from. Free text, but never an analyzer check.
    source: str = "manual review"
    severity_note: str = ""

    @model_validator(mode="after")
    def _check_labelers_are_independent(self) -> Self:
        distinct = set(self.labelers)
        if len(distinct) < MINIMUM_LABELERS:
            raise ValueError(
                f"case {self.case_id} names {len(distinct)} distinct labeller(s) "
                f"({', '.join(sorted(distinct))}); the spec requires at least "
                f"{MINIMUM_LABELERS} independent ones, because a single-labeller set "
                "measures one person's taste"
            )
        return self

    @model_validator(mode="after")
    def _check_disagreement_was_adjudicated(self) -> Self:
        if not self.agreed and not (self.adjudicator_note or "").strip():
            raise ValueError(
                f"case {self.case_id} records a disagreement with no adjudicator note; "
                "the resolution is part of the label, not something to reconstruct later"
            )
        return self

    @model_validator(mode="after")
    def _check_the_label_is_not_the_tools_own_output(self) -> Self:
        lowered = self.source.strip().lower()
        named = sorted(tool for tool in _FORBIDDEN_SOURCES if tool in lowered)
        if named:
            raise ValueError(
                f"case {self.case_id} names {', '.join(named)} as its label source. "
                "Labels adjudicated from the tool's own checks score the tool against "
                "itself; label from the code, then compare"
            )
        return self


class LabelSet(BaseModel):
    """One version of the labelled set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    labels: list[MaintainabilityLabel] = Field(default_factory=list)
    #: Reviewer verdicts on the recommendations, keyed by case elsewhere.
    verdicts: list[RecommendationVerdict] = Field(default_factory=list)
    note: str = ""

    @model_validator(mode="after")
    def _check_case_ids_are_unique(self) -> Self:
        seen: set[str] = set()
        duplicated: set[str] = set()
        for label in self.labels:
            if label.case_id in seen:
                duplicated.add(label.case_id)
            seen.add(label.case_id)
        if duplicated:
            raise ValueError(
                f"duplicate case id(s) in the label set: {', '.join(sorted(duplicated))}"
            )
        return self

    @property
    def case_ids(self) -> list[str]:
        return sorted(label.case_id for label in self.labels)

    def by_case(self) -> dict[str, MaintainabilityLabel]:
        return {label.case_id: label for label in self.labels}

    @property
    def is_empty(self) -> bool:
        """True before any human has labelled anything. Not an error, a state."""
        return not self.labels


def load_labels(path: Path) -> LabelSet:
    """Read a committed label set, enforcing every rule above.

    A missing file is an empty set rather than an exception: the labels are
    human work this repository does not yet have, and a scorer that crashes on
    their absence would make the rest of the harness untestable.
    """
    if not path.is_file():
        return LabelSet(version="0", note=f"no label set at {path}")
    return LabelSet.model_validate_json(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- agreement


class AgreementReport(BaseModel):
    """How often the labellers agreed, and how much of that beat chance.

    Both numbers are published. Raw agreement alone flatters a set whose
    categories are unevenly distributed — five labellers who always say
    ``complexity`` agree perfectly and have measured nothing — and kappa alone
    is hard to read, so neither stands in for the other.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cases: int = Field(ge=0)
    agreed: int = Field(ge=0)
    raw_agreement: float
    #: Cohen's kappa against the observed category distribution. ``None`` when
    #: there is only one category in play, where chance agreement is 1.0 and
    #: the statistic is undefined rather than perfect.
    kappa: float | None = None

    def describe(self) -> str:
        kappa = "undefined (one category)" if self.kappa is None else f"{self.kappa:.3f}"
        return (
            f"{self.agreed}/{self.cases} cases agreed without adjudication "
            f"({self.raw_agreement:.3f}); kappa {kappa}"
        )


def agreement(labels: Sequence[MaintainabilityLabel]) -> AgreementReport:
    """Inter-labeller agreement over a label set.

    ``agreed`` is what the labellers recorded, not something recomputed from
    the final category: a case that needed adjudication agreed on its answer
    afterwards and did not agree at the time, and only the second is a fact
    about the labelling.
    """
    if not labels:
        return AgreementReport(cases=0, agreed=0, raw_agreement=1.0, kappa=None)

    agreed = sum(1 for label in labels if label.agreed)
    raw = agreed / len(labels)

    counts: dict[MaintainabilityCategory, int] = {}
    for label in labels:
        counts[label.category] = counts.get(label.category, 0) + 1
    if len(counts) < 2:
        return AgreementReport(cases=len(labels), agreed=agreed, raw_agreement=raw, kappa=None)

    # Chance agreement under the observed marginal distribution. With per-case
    # agreement recorded rather than per-labeller category votes, this is the
    # honest approximation available, and it is labelled as such.
    expected = sum((count / len(labels)) ** 2 for count in counts.values())
    kappa = 1.0 if expected >= 1.0 else (raw - expected) / (1.0 - expected)
    return AgreementReport(cases=len(labels), agreed=agreed, raw_agreement=raw, kappa=kappa)


# ---------------------------------------------------------------- predictor


class MaintainabilityCoverageError(ValueError):
    """A labelled category lies outside anything the predictor can name."""


#: Which maintenance hazard a weakness family implies, where the implication is
#: a fact about the weakness rather than a guess about the code.
#:
#: Absence is the interesting half of this table. ``RESOURCE_LEAK`` is missing
#: on purpose: a leak is genuinely ambiguous between ``ownership_ambiguity``
#: (nobody owns the close) and ``error_handling`` (the close is skipped on the
#: failure path), and picking one would be exactly the blind mapping this
#: predictor exists to avoid. It abstains instead.
_CATEGORY_BY_FAMILY: Final[Mapping[WeaknessFamily, MaintainabilityCategory]] = {
    WeaknessFamily.MEMORY_LIFETIME: MaintainabilityCategory.OWNERSHIP_AMBIGUITY,
}

#: Where a finding's evidence reaches, read as a structural hazard. This is the
#: span of *verified* regions — :func:`~caudit.finding_policy.ranking.effort_of` derives
#: it from citations that resolved against the scanned revision — so it is a
#: measurement rather than an opinion, unlike the prose in
#: :class:`~caudit.model.finding.MaintainabilityImpact`. ``LOCAL`` is absent:
#: a fix contained in one region is evidence of no structural hazard at all,
#: and calling that ``complexity`` would manufacture a prediction.
_CATEGORY_BY_EFFORT: Final[Mapping[EffortEstimate, MaintainabilityCategory]] = {
    EffortEstimate.CROSS_MODULE: MaintainabilityCategory.COUPLING,
    EffortEstimate.FUNCTION: MaintainabilityCategory.COMPLEXITY,
}

#: Categories no signal in the current schema can produce. Declared here rather
#: than left to fall out of the tables above, because the difference matters: an
#: uncoverable category is a stated limit of the bridge between a `Finding` and
#: a hazard label, and :class:`PredictorCoverage` reports it as one. A category
#: that is merely *unpredicted* on some corpus is a fact about that corpus.
#:
#: Closing this set needs a model-facing field naming the hazard, which means a
#: prompt version bump and re-recording every cassette. Until then, a labelled
#: case in one of these categories makes the macro-average unavailable rather
#: than merely low — see :func:`score_maintainability`.
UNCOVERABLE: Final[frozenset[MaintainabilityCategory]] = frozenset(
    {MaintainabilityCategory.DUPLICATED_VALIDATION, MaintainabilityCategory.ERROR_HANDLING}
)


def predict_category(finding: Finding) -> MaintainabilityCategory | None:
    """The maintenance hazard a finding implies, or ``None`` to abstain.

    Two signals, in a fixed precedence. The weakness family goes first because
    it is a statement about what the defect *is*; the evidence span is a
    fallback describing how far it reaches. Neither reads a value a model
    wrote, which is the same rule part 12's ranking is built on.

    ``None`` is a real answer and never a category. A predictor with a
    catch-all bucket reports a confident label for every finding and measures
    the bucket.
    """
    family = family_of(finding.cwe)
    if family is not None and family in _CATEGORY_BY_FAMILY:
        return _CATEGORY_BY_FAMILY[family]
    return _CATEGORY_BY_EFFORT.get(effort_of(finding))


class PredictorCoverage(BaseModel):
    """What the predictor could and could not name, published with the score.

    The counts alone would let a run with 90% abstention look like a run that
    scored well on 10% of the cases, so ``categories_uncovered`` names the
    labelled categories that were never reachable — the ones whose F1 would
    otherwise be 0.0 for a reason that is a fact about the schema rather than
    about the tool.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    predicted: int = Field(ge=0)
    abstained: int = Field(ge=0)
    categories_predicted: list[MaintainabilityCategory] = Field(default_factory=list)
    #: Labelled categories outside :data:`UNCOVERABLE`'s complement — the
    #: predictor has no route to them, so their score would measure the bridge.
    categories_uncovered: list[MaintainabilityCategory] = Field(default_factory=list)

    @property
    def cases(self) -> int:
        return self.predicted + self.abstained

    @property
    def refusal(self) -> str | None:
        """Why a macro-average is unavailable, or ``None`` if it is available."""
        if not self.categories_uncovered:
            return None
        named = ", ".join(sorted(self.categories_uncovered))
        return (
            f"the label set contains {named}, which no signal in the current schema "
            "can predict; a macro-F1 including them would measure the finding-to-hazard "
            "bridge rather than the tool"
        )

    def assert_covers(self) -> None:
        """Raise when a labelled category is outside the predictor's range."""
        refusal = self.refusal
        if refusal is not None:
            raise MaintainabilityCoverageError(refusal)

    def describe(self) -> str:
        named = ", ".join(sorted(self.categories_predicted)) or "nothing"
        return (
            f"predicted {self.predicted}/{self.cases} case(s) as {named}; "
            f"{self.abstained} abstained"
        )


def predict_categories(
    by_case: Mapping[str, Sequence[Finding]],
    labels: LabelSet | None = None,
) -> tuple[dict[str, MaintainabilityCategory], PredictorCoverage]:
    """Predict one category per case, and report what could not be reached.

    A case with several findings is represented by the one the *report* put
    first — :func:`~caudit.finding_policy.ranking.rank_findings`, unmodified. That is
    the same premise :func:`ndcg_at_k` scores: the hazard a reader meets first
    is the tool's answer for that case. Re-deriving an order here would score a
    ranking nobody was shown.

    A case whose top-ranked finding abstains does not fall through to the next
    one. The ordering is the claim; consulting the runner-up until something
    sticks would turn abstention into a search for any answer at all.
    """
    predicted: dict[str, MaintainabilityCategory] = {}
    abstained = 0
    for case_id, findings in sorted(by_case.items()):
        ranked = rank_findings(findings)
        category = predict_category(ranked[0]) if ranked else None
        if category is None:
            abstained += 1
        else:
            predicted[case_id] = category

    reachable = set(MaintainabilityCategory) - UNCOVERABLE
    labelled = {label.category for label in labels.labels} if labels is not None else set()
    return predicted, PredictorCoverage(
        predicted=len(predicted),
        abstained=abstained,
        categories_predicted=sorted(set(predicted.values())),
        categories_uncovered=sorted(labelled - reachable),
    )


# ------------------------------------------------------------------ scoring


def macro_f1(
    truth: Mapping[str, MaintainabilityCategory],
    predicted: Mapping[str, MaintainabilityCategory],
) -> dict[MaintainabilityCategory, float]:
    """Per-category F1, macro-averaged by the caller.

    Categories with no truths and no predictions are excluded, the same
    convention part 04 applies to weakness families: an empty category cannot
    inflate an average it was never scored in.
    """
    scores: dict[MaintainabilityCategory, float] = {}
    for category in MaintainabilityCategory:
        expected = {case for case, value in truth.items() if value is category}
        actual = {case for case, value in predicted.items() if value is category}
        if not expected and not actual:
            continue
        overlap = len(expected & actual)
        precision = 1.0 if not actual else overlap / len(actual)
        recall = 1.0 if not expected else overlap / len(expected)
        scores[category] = (
            0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
        )
    return scores


def ndcg_at_k(relevance: Sequence[float], k: int = 10) -> float:
    """Normalised discounted cumulative gain over a ranked list.

    ``relevance[i]`` is the graded relevance of the item the tool placed at
    position ``i``. 1.0 means the ranking put the most useful findings first;
    a ranking whose top ten are all irrelevant scores 0.0. Vacuously 1.0 when
    nothing is relevant, because there was no ordering to get wrong.
    """
    if k <= 0:
        raise ValueError("k must be positive")
    actual = _dcg(relevance[:k])
    ideal = _dcg(sorted(relevance, reverse=True)[:k])
    return 1.0 if ideal == 0.0 else actual / ideal


def _dcg(relevance: Sequence[float]) -> float:
    return sum(value / math.log2(position + 2) for position, value in enumerate(relevance))


class MaintainabilityScore(BaseModel):
    """Three metrics, side by side, with the agreement that qualifies them.

    There is deliberately no combined field and no method that averages the
    three. The spec asks for all of them to be reported; a single number would
    be the thing everyone quotes and the one nobody could act on.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    label_set_version: str = Field(min_length=1)
    per_category_f1: dict[MaintainabilityCategory, float] = Field(default_factory=dict)
    #: ``None`` when a labelled category is outside the predictor's range. That
    #: is a refusal, not a zero: averaging in an F1 of 0.0 that the schema made
    #: unavoidable would understate the tool for a reason that is an artefact of
    #: the bridge. Same discipline as
    #: :meth:`~caudit.eval.ablation.AblationSuite.structural_retrieval_earns_itself`,
    #: which returns ``None`` rather than "no" when its control has not run.
    macro_f1: float | None
    #: Why :attr:`macro_f1` is unavailable. Set together with it, never alone.
    refusal: str | None = None
    ndcg_at_10: float
    #: Share of reviewed recommendations judged both accurate and actionable.
    recommendation_useful_rate: float
    recommendations_reviewed: int = Field(ge=0)
    agreement: AgreementReport
    cases_scored: int = Field(ge=0)
    policy_versions: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_a_refusal_accompanies_a_missing_average(self) -> Self:
        """One is never set without the other, in either direction.

        An unexplained ``None`` reads as a bug, and a refusal beside a number
        invites a reader to quote the number anyway.
        """
        if (self.macro_f1 is None) is not (self.refusal is not None):
            raise ValueError(
                "macro_f1 and refusal must be set together: a withheld average "
                "needs a stated reason, and a stated reason must withhold the average"
            )
        return self

    def describe(self) -> str:
        average = "refused" if self.macro_f1 is None else f"{self.macro_f1:.3f}"
        tail = f" ({self.refusal})" if self.refusal else ""
        return (
            f"macro-F1 {average}, nDCG@10 {self.ndcg_at_10:.3f}, "
            f"{self.recommendation_useful_rate:.3f} of "
            f"{self.recommendations_reviewed} recommendation(s) accurate and "
            f"actionable; {self.agreement.describe()}{tail}"
        )


def score_maintainability(
    labels: LabelSet,
    predicted: Mapping[str, MaintainabilityCategory],
    ranked_relevance: Sequence[float],
    *,
    policy_versions: Mapping[str, str],
    coverage: PredictorCoverage | None = None,
) -> MaintainabilityScore:
    """Score one run against one version of the labelled set.

    ``ranked_relevance`` is the graded relevance of the tool's top findings, in
    the order the report ranked them — part 12's ranking is what is being
    measured here, so re-sorting it would test nothing.

    ``coverage`` is what :func:`predict_categories` reported. When it names a
    labelled category the predictor cannot reach, the macro-average is withheld
    and the reason recorded. The per-category numbers are still published: which
    category was unreachable is the useful part, and hiding the whole score
    would lose it. Passing ``None`` scores without that check, which is only
    honest when ``predicted`` came from somewhere other than this module.
    """
    truth = {case_id: label.category for case_id, label in labels.by_case().items()}
    per_category = macro_f1(truth, predicted)
    scored = list(per_category.values())
    refusal = coverage.refusal if coverage is not None else None
    reviewed = labels.verdicts
    return MaintainabilityScore(
        label_set_version=labels.version,
        per_category_f1=per_category,
        macro_f1=None if refusal else (sum(scored) / len(scored) if scored else 0.0),
        refusal=refusal,
        ndcg_at_10=ndcg_at_k(ranked_relevance, 10),
        recommendation_useful_rate=(
            sum(1 for verdict in reviewed if verdict.useful) / len(reviewed) if reviewed else 0.0
        ),
        recommendations_reviewed=len(reviewed),
        agreement=agreement(labels.labels),
        cases_scored=len(truth),
        policy_versions=dict(sorted(policy_versions.items())),
    )


def write_labels(labels: LabelSet, path: Path) -> Path:
    """Write a label set. Sorted keys, so two versions diff cleanly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.loads(labels.model_dump_json())
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path


def unlabelled(case_ids: Iterable[str], labels: LabelSet) -> list[str]:
    """Cases with no label yet. Published, so the set's coverage is visible."""
    known = set(labels.case_ids)
    return sorted(case_id for case_id in case_ids if case_id not in known)

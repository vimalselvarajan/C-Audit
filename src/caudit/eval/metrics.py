"""Detection metrics.

Security is scored with macro-averaged F2 so recall matters more than
precision, with precision, false positives per thousand lines, and evidence
validity reported *separately*. The spec is explicit that no single
aggregate should be relied on, so this module never produces one.

Degenerate cases have documented conventions rather than exceptions:

* ``precision`` is 1.0 when nothing was predicted — vacuously precise.
* ``recall`` is 1.0 when there was nothing to find — vacuously complete.
* ``f_beta`` is 0.0 when precision and recall are both 0.
* A family with neither ground truth nor findings is **excluded** from the
  macro average, so empty families cannot inflate it.

Two rate fields exist because they answer different questions, and the
difference matters when arguing that a report is trustworthy:

* ``citation_resolution_rate`` — resolved citations over all citations. This
  is the quantity the spec's ≥95% hard gate is stated in.
* ``evidence_validity_rate`` — findings whose evidence resolves *completely*
  over all findings. Strictly harsher: one bad citation invalidates the
  finding that leans on it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from caudit.eval.case import BenchmarkCase, GroundTruth, TruthFrame
from caudit.eval.matching import MatchingPolicy
from caudit.evidence.resolver import Resolution
from caudit.model.cwe import WeaknessFamily
from caudit.model.finding import Confidence, Finding

__all__ = [
    "SUMMABLE_COUNT_FIELDS",
    "FamilyMetrics",
    "Metrics",
    "compute_metrics",
    "f_beta",
    "precision_of",
    "recall_of",
]


def precision_of(true_positives: int, false_positives: int) -> float:
    """1.0 when nothing was predicted; no division by zero."""
    predicted = true_positives + false_positives
    return 1.0 if predicted == 0 else true_positives / predicted


def recall_of(true_positives: int, false_negatives: int) -> float:
    """1.0 when there was nothing to find; no division by zero."""
    actual = true_positives + false_negatives
    return 1.0 if actual == 0 else true_positives / actual


def f_beta(precision: float, recall: float, beta: float = 2.0) -> float:
    """Weighted harmonic mean. ``beta=2`` weights recall four times precision."""
    if precision <= 0.0 and recall <= 0.0:
        return 0.0
    beta_sq = beta * beta
    denominator = beta_sq * precision + recall
    if denominator == 0.0:  # pragma: no cover - unreachable given the guard above
        return 0.0
    return (1.0 + beta_sq) * precision * recall / denominator


class FamilyMetrics(BaseModel):
    """Counts and rates for one weakness family."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: WeaknessFamily
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float
    recall: float
    f2: float
    #: Families with no truths and no findings are not scored at all.
    scored: bool = True

    @classmethod
    def build(cls, family: WeaknessFamily, tp: int, fp: int, fn: int) -> FamilyMetrics:
        precision = precision_of(tp, fp)
        recall = recall_of(tp, fn)
        return cls(
            family=family,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f2=f_beta(precision, recall, beta=2.0),
            scored=(tp + fp + fn) > 0,
        )


#: Fields that count findings. Deliberately enumerated so a test can assert
#: nothing sums confirmed and review-required into one number.
SUMMABLE_COUNT_FIELDS = ("confirmed_count", "review_required_count")


class Metrics(BaseModel):
    """One suite's results under one matching policy.

    There is no ``total_findings`` field and no method that adds
    ``confirmed_count`` to ``review_required_count``. The spec forbids
    merging them, and the cheapest way to keep that promise is to make the
    merged number impossible to read off the object.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    suite: str
    policy_version: str
    truth_frame: TruthFrame = Field(default_factory=TruthFrame)
    per_family: dict[WeaknessFamily, FamilyMetrics]
    precision: float = 0.0
    recall: float = 0.0
    macro_f2: float
    fp_per_kloc: float
    evidence_validity_rate: float
    citation_resolution_rate: float
    confirmed_count: int = Field(ge=0)
    review_required_count: int = Field(ge=0)
    lines_of_code: int = Field(ge=0)
    case_count: int = Field(ge=0)
    #: Cases the analyzers are known to miss, carried through so a suite
    #: where everything passes is visibly suspicious.
    blind_spot_case_ids: list[str] = Field(default_factory=list)

    @property
    def scored_families(self) -> list[FamilyMetrics]:
        return [m for m in self.per_family.values() if m.scored]

    def assert_comparable(self, other: Metrics) -> None:
        """Refuse to difference two reports produced under different rules."""
        if self.policy_version != other.policy_version:
            raise ValueError(
                f"matching policy versions differ ({self.policy_version} vs "
                f"{other.policy_version}); these reports are not comparable"
            )


def _family_of_truth(truth: GroundTruth) -> WeaknessFamily:
    return truth.family


def compute_metrics(
    *,
    suite: str,
    cases: Sequence[BenchmarkCase],
    findings_by_case: Mapping[str, Sequence[Finding]],
    resolutions: Sequence[Resolution],
    policy: MatchingPolicy,
) -> Metrics:
    """Score a whole suite.

    Only confirmed findings are matched against ground truth. Review-required
    items are counted and reported, never scored as detections — crediting
    them would be exactly the merge the spec forbids.
    """
    tp: dict[WeaknessFamily, int] = {}
    fp: dict[WeaknessFamily, int] = {}
    fn: dict[WeaknessFamily, int] = {}
    confirmed = 0
    review_required = 0
    total_loc = 0
    total_fp = 0

    for case in cases:
        total_loc += case.lines_of_code
        case_findings = list(findings_by_case.get(case.case_id, ()))
        confirmed_findings = [f for f in case_findings if f.is_confirmed]
        confirmed += len(confirmed_findings)
        review_required += sum(
            1 for f in case_findings if f.confidence is Confidence.REVIEW_REQUIRED
        )

        result = policy.match_all(case.ground_truth, confirmed_findings)

        for truth_index, _ in result.pairs:
            family = _family_of_truth(case.ground_truth[truth_index])
            tp[family] = tp.get(family, 0) + 1
        for truth_index in result.unmatched_truths:
            family = _family_of_truth(case.ground_truth[truth_index])
            fn[family] = fn.get(family, 0) + 1
        for finding_index in result.unmatched_findings:
            finding = confirmed_findings[finding_index]
            # A finding with no in-scope family still costs precision; it is
            # attributed to the case's family so it cannot disappear.
            family = finding.family or case.family or _fallback_family(case)
            fp[family] = fp.get(family, 0) + 1
            total_fp += 1

    families = sorted(set(tp) | set(fp) | set(fn), key=lambda f: f.value)
    per_family = {
        family: FamilyMetrics.build(family, tp.get(family, 0), fp.get(family, 0), fn.get(family, 0))
        for family in families
    }
    scored = [m.f2 for m in per_family.values() if m.scored]
    macro_f2 = sum(scored) / len(scored) if scored else 0.0

    resolved = sum(1 for r in resolutions if r.ok)
    citation_rate = 1.0 if not resolutions else resolved / len(resolutions)

    return Metrics(
        suite=suite,
        policy_version=policy.version,
        per_family=per_family,
        precision=precision_of(sum(tp.values()), sum(fp.values())),
        recall=recall_of(sum(tp.values()), sum(fn.values())),
        macro_f2=macro_f2,
        fp_per_kloc=(total_fp / (total_loc / 1000.0)) if total_loc else 0.0,
        evidence_validity_rate=_evidence_validity(findings_by_case, resolutions),
        citation_resolution_rate=citation_rate,
        confirmed_count=confirmed,
        review_required_count=review_required,
        lines_of_code=total_loc,
        case_count=len(cases),
        blind_spot_case_ids=[c.case_id for c in cases if c.analyzer_blind_spot],
    )


def _fallback_family(case: BenchmarkCase) -> WeaknessFamily:
    """Where to charge a false positive that names no in-scope family."""
    if case.ground_truth:
        return case.ground_truth[0].family
    return WeaknessFamily.OUT_OF_BOUNDS


def _evidence_validity(
    findings_by_case: Mapping[str, Sequence[Finding]],
    resolutions: Sequence[Resolution],
) -> float:
    """Findings whose evidence resolves completely, over all findings."""
    total = sum(len(items) for items in findings_by_case.values())
    if total == 0:
        return 1.0
    failed_paths = {
        str(r.citation.path) for r in resolutions if not r.ok and r.citation.path is not None
    }
    failed_ids = {
        r.citation.evidence_id
        for r in resolutions
        if not r.ok and r.citation.evidence_id is not None
    }
    intact = 0
    for items in findings_by_case.values():
        for finding in items:
            cited_ids = {item.evidence_id for item in finding.evidence}
            cited_paths = {str(item.region.path) for item in finding.evidence}
            cited_paths.add(str(finding.location.path))
            if cited_ids & failed_ids or cited_paths & failed_paths:
                continue
            intact += 1
    return intact / total

"""Baseline against adjudicated — the comparison the spec requires.

Milestone 2 is only finished when the AI-assisted numbers have been measured
against the Milestone 1 analyzer baseline and the comparison is written down.
This module is that measurement: two recorded runs in, per-family and macro
deltas plus what the model cost, out.

**Comparison is like-for-like or it is refused.** Two runs scored under
different matching policies, different prompt versions, different check
profiles, or over different cases are not two measurements of one change —
they are two different experiments, and differencing them produces a number
that looks like an improvement and means nothing. :func:`compare_runs` names
both values and stops rather than reporting it.

**The two counts stay apart here too.** There is a delta for confirmed findings
and a delta for review-required candidates, and nothing that adds them. A
change that moved thirty findings from confirmed to needs-review is an enormous
change, and a summed count would render it as zero.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.eval.experiment import ExperimentManifest
from caudit.eval.gates import GateResult
from caudit.eval.metrics import Metrics
from caudit.model.cwe import WeaknessFamily

__all__ = [
    "ADJUDICATED_POLICIES",
    "COMPARABLE_POLICIES",
    "ComparisonError",
    "ComparisonReport",
    "CostSummary",
    "FamilyDelta",
    "MetricsDelta",
    "RunReport",
    "compare_runs",
    "load_run_report",
]

#: Policies both runs must agree on whatever they are. ``matching`` decides
#: which findings count as detections and ``profile`` decides which checks
#: fired at all, so a difference in either shows up as a difference in the
#: score and gets attributed to the wrong cause.
COMPARABLE_POLICIES: tuple[str, ...] = ("matching", "profile")

#: Policies that only exist on a run with a model in it. An analyzer-only
#: baseline has no prompt version, and demanding one match the adjudicated
#: run's would refuse exactly the comparison Milestone 2 is defined by. Checked
#: when both sides adjudicated, and noted as a caveat when only one did.
ADJUDICATED_POLICIES: tuple[str, ...] = ("prompt", "retrieval")


class ComparisonError(ValueError):
    """Two runs cannot be compared, and this says which field differs."""


class CostSummary(BaseModel):
    """What a run spent. Zero throughout on an analyzer-only baseline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Requests that reached a provider. Cached answers are not calls.
    calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    thinking_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    tool_use_tokens: int = Field(default=0, ge=0)
    provider_tokens: int = Field(default=0, ge=0)
    retry_count: int = Field(default=0, ge=0)
    usd: float = Field(default=0.0, ge=0.0)
    #: Wall time for the whole measured run, which is the latency figure the
    #: milestone asks for. Not a per-request latency: this is what a user
    #: waits, and it is the number that decides whether the tool is usable.
    wall_seconds: float = Field(default=0.0, ge=0.0)

    @property
    def total_tokens(self) -> int:
        return self.provider_tokens or (
            self.input_tokens
            + self.output_tokens
            + self.thinking_tokens
            + self.cached_input_tokens
            + self.tool_use_tokens
        )

    def describe(self) -> str:
        return (
            f"{self.calls} call(s), {self.total_tokens} token(s), "
            f"${self.usd:.4f}, {self.wall_seconds:.1f}s wall"
        )

    def minus(self, other: CostSummary) -> CostSummary:
        """This run's cost less ``other``'s. Never negative below zero."""
        return CostSummary(
            calls=max(0, self.calls - other.calls),
            input_tokens=max(0, self.input_tokens - other.input_tokens),
            output_tokens=max(0, self.output_tokens - other.output_tokens),
            thinking_tokens=max(0, self.thinking_tokens - other.thinking_tokens),
            cached_input_tokens=max(0, self.cached_input_tokens - other.cached_input_tokens),
            tool_use_tokens=max(0, self.tool_use_tokens - other.tool_use_tokens),
            provider_tokens=max(0, self.total_tokens - other.total_tokens),
            retry_count=max(0, self.retry_count - other.retry_count),
            usd=max(0.0, self.usd - other.usd),
            wall_seconds=max(0.0, self.wall_seconds - other.wall_seconds),
        )


class RunReport(BaseModel):
    """One measured run: what ``caudit eval`` writes and ``compare`` reads.

    Every field beyond ``metrics`` exists so a later run can be told apart from
    this one for a *reason*. A metrics file that recorded only the scores would
    let two incomparable runs be differenced with nothing to object with.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    metrics: Metrics
    gates: list[GateResult] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    #: Every policy version that shaped this run, ``profile`` included.
    policy_versions: dict[str, str] = Field(default_factory=dict)
    cost: CostSummary = Field(default_factory=CostSummary)
    #: The case ids actually scored, sorted. Two runs over different cases are
    #: not two measurements of one change — this is the eval harness's
    #: equivalent of "the same scan plan".
    scope: list[str] = Field(default_factory=list)
    #: Whether a model participated. A ``False`` here against a ``True`` there
    #: is the whole point of the comparison, so it is recorded rather than
    #: inferred from a zero cost — a cached adjudicated run also costs nothing.
    adjudicated: bool = False
    experiment: ExperimentManifest | None = None

    @model_validator(mode="after")
    def _truth_frame_agrees(self) -> RunReport:
        if self.experiment is not None and self.metrics.truth_frame != self.experiment.truth_frame:
            raise ValueError("report metrics truth frame disagrees with its experiment manifest")
        return self

    @property
    def passed(self) -> bool:
        return all(gate.passed for gate in self.gates)

    def failed_gates(self) -> list[str]:
        return [gate.name for gate in self.gates if not gate.passed]


class FamilyDelta(BaseModel):
    """One weakness family's movement between two runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: WeaknessFamily
    precision: float
    recall: float
    f2: float
    true_positives: int
    false_positives: int
    false_negatives: int


class MetricsDelta(BaseModel):
    """Adjudicated minus baseline, per family and overall.

    There is no field here that adds ``confirmed_count`` to
    ``review_required_count``, and there is no overall "score". The spec is
    explicit that no single aggregate should be relied on, and a delta is the
    easiest place to reintroduce one by accident.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    macro_f2: float
    precision: float
    recall: float
    fp_per_kloc: float
    evidence_validity_rate: float
    citation_resolution_rate: float
    confirmed_count: int
    review_required_count: int
    per_family: dict[WeaknessFamily, FamilyDelta] = Field(default_factory=dict)

    @property
    def improved(self) -> bool:
        """Recall-weighted detection went up and evidence validity did not fall.

        Deliberately not a single score. It is the one question the milestone
        asks — did adding a model make detection better without making the
        evidence worse — and both halves have to hold.
        """
        return self.macro_f2 > 0.0 and self.evidence_validity_rate >= 0.0


class ComparisonReport(BaseModel):
    """The recorded comparison of an analyzer baseline with an adjudicated run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline: Metrics
    adjudicated: Metrics
    delta: MetricsDelta
    cost: CostSummary
    policy_versions: dict[str, str] = Field(default_factory=dict)
    #: Gates failing on either side. An improvement measured under a failing
    #: hard gate is not an improvement — the spec makes the average valid only
    #: once the gates pass, and this is where a reader is told.
    failing_gates: list[str] = Field(default_factory=list)
    #: Things that could not be checked, rather than things that failed. A
    #: baseline that recorded no case list cannot be held to the adjudicated
    #: run's, and saying so is the difference between an unchecked assumption
    #: and a hidden one.
    caveats: list[str] = Field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Whether the deltas may be read as a result at all.

        Caveats do not make a comparison invalid. They are gaps in what could be
        verified about the two runs, not evidence that the numbers are wrong,
        and a reader is shown both.
        """
        return not self.failing_gates

    def headline(self) -> str:
        direction = "+" if self.delta.macro_f2 >= 0 else ""
        line = (
            f"macro-F2 {self.baseline.macro_f2:.4f} → {self.adjudicated.macro_f2:.4f} "
            f"({direction}{self.delta.macro_f2:.4f}) for {self.cost.describe()}"
        )
        if self.failing_gates:
            return f"{line} — NOT VALID: {', '.join(self.failing_gates)} failing"
        return line


def compare_runs(baseline: RunReport, adjudicated: RunReport) -> ComparisonReport:
    """Difference two runs, or refuse and say which field made them different.

    ``baseline`` is the analyzer-only Milestone 1 run and ``adjudicated`` is
    the run with a model in it. The order matters: every delta is
    ``adjudicated - baseline``, so a positive macro-F2 delta means the model
    helped.
    """
    _assert_comparable(baseline, adjudicated)
    return ComparisonReport(
        baseline=baseline.metrics,
        adjudicated=adjudicated.metrics,
        delta=_delta(baseline.metrics, adjudicated.metrics),
        cost=adjudicated.cost.minus(baseline.cost),
        policy_versions=dict(sorted(adjudicated.policy_versions.items())),
        failing_gates=sorted(set(baseline.failed_gates()) | set(adjudicated.failed_gates())),
        caveats=_caveats(baseline, adjudicated),
    )


def _caveats(baseline: RunReport, adjudicated: RunReport) -> list[str]:
    """What this comparison could not verify about the two runs."""
    caveats: list[str] = []
    if baseline.experiment is None or adjudicated.experiment is None:
        caveats.append(
            "one of these runs has no immutable experiment manifest, so experiment "
            "identity could not be fully checked"
        )
    if not baseline.scope or not adjudicated.scope:
        caveats.append(
            "one of these runs did not record which cases it scored, so this "
            "comparison could not check that both covered the same set"
        )
    unchecked = [
        policy
        for policy in _policies_to_check(baseline, adjudicated)
        if not (_policy(baseline, policy) and _policy(adjudicated, policy))
    ]
    if unchecked:
        caveats.append(
            f"one of these runs did not record its {', '.join(unchecked)} policy "
            "version, so this comparison could not check that both ran under the same one"
        )
    if not baseline.adjudicated and not adjudicated.adjudicated:
        caveats.append(
            "neither run had a model in it, so this compares two analyzer-only "
            "measurements rather than the effect of adjudication"
        )
    elif baseline.adjudicated == adjudicated.adjudicated:
        caveats.append(
            "both runs were adjudicated, so this measures a change between two "
            "model-assisted runs rather than against the analyzer baseline"
        )
    return caveats


def _assert_comparable(baseline: RunReport, adjudicated: RunReport) -> None:
    """Every way two runs can fail to be about the same thing.

    The matching policy is checked twice, and deliberately: once through
    :meth:`~caudit.eval.metrics.Metrics.assert_comparable`, which reads the
    version that actually scored the run, and once through the recorded
    ``policy_versions`` below. A report whose two records of its own matching
    policy disagree is not a report either check should be asked to prefer a
    side of.
    """
    if baseline.experiment is not None and adjudicated.experiment is not None:
        manifest_left = baseline.experiment.comparable_values()
        manifest_right = adjudicated.experiment.comparable_values()
        for field in manifest_left:
            if manifest_left[field] != manifest_right.get(field):
                raise ComparisonError(f"experiment {field} differs; these runs are not comparable")
    try:
        baseline.metrics.assert_comparable(adjudicated.metrics)
    except ValueError as exc:
        raise ComparisonError(str(exc)) from exc
    if baseline.metrics.suite != adjudicated.metrics.suite:
        raise ComparisonError(
            f"these runs scored different suites ({baseline.metrics.suite} vs "
            f"{adjudicated.metrics.suite}); there is nothing to difference"
        )
    # An empty scope means "not recorded", not "no cases". Refusing on it would
    # reject every baseline written before the field existed — which is the
    # baseline an adjudicated run most needs to be measured against. It becomes
    # a caveat instead, so the gap is stated rather than assumed away.
    if baseline.scope and adjudicated.scope and sorted(baseline.scope) != sorted(adjudicated.scope):
        only_left = sorted(set(baseline.scope) - set(adjudicated.scope))
        only_right = sorted(set(adjudicated.scope) - set(baseline.scope))
        raise ComparisonError(
            "these runs scored different cases, so their scores are not comparable; "
            f"only in the baseline: {only_left or 'none'}; only in the adjudicated "
            f"run: {only_right or 'none'}"
        )

    for policy in _policies_to_check(baseline, adjudicated):
        left = _policy(baseline, policy)
        right = _policy(adjudicated, policy)
        # An unrecorded version is unknown, not different. Refusing on it would
        # reject every report written before the field existed, and the gap is
        # surfaced as a caveat by :func:`_caveats` instead.
        if left and right and left != right:
            raise ComparisonError(
                f"the {policy} policy version differs ({left} vs {right}); a score "
                "measured under one policy is not a measurement of the other, so "
                "these reports are not comparable"
            )


def _policies_to_check(baseline: RunReport, adjudicated: RunReport) -> tuple[str, ...]:
    """Which policy versions apply to both of these runs.

    ``matching`` is always in the list because every scored run has one. The
    prompt and retrieval policies only exist on a run with a model in it, so
    they are compared when both sides had one and skipped otherwise — that
    asymmetry *is* the Milestone 2 comparison.
    """
    if baseline.adjudicated and adjudicated.adjudicated:
        return (*COMPARABLE_POLICIES, *ADJUDICATED_POLICIES)
    return COMPARABLE_POLICIES


def _policy(report: RunReport, name: str) -> str:
    """One policy version, preferring the explicit record.

    ``matching`` falls back to ``Metrics.policy_version`` so a report written
    before ``policy_versions`` existed still compares on the one policy it did
    record, rather than silently comparing two blanks and passing.
    """
    recorded = report.policy_versions.get(name, "")
    if recorded:
        return recorded
    if name == "matching":
        return report.metrics.policy_version
    return ""


def _delta(baseline: Metrics, adjudicated: Metrics) -> MetricsDelta:
    families = sorted(set(baseline.per_family) | set(adjudicated.per_family), key=lambda f: f.value)
    per_family: dict[WeaknessFamily, FamilyDelta] = {}
    for family in families:
        left = baseline.per_family.get(family)
        right = adjudicated.per_family.get(family)
        per_family[family] = FamilyDelta(
            family=family,
            precision=_value(right, "precision") - _value(left, "precision"),
            recall=_value(right, "recall") - _value(left, "recall"),
            f2=_value(right, "f2") - _value(left, "f2"),
            true_positives=int(_value(right, "true_positives") - _value(left, "true_positives")),
            false_positives=int(_value(right, "false_positives") - _value(left, "false_positives")),
            false_negatives=int(_value(right, "false_negatives") - _value(left, "false_negatives")),
        )
    return MetricsDelta(
        macro_f2=adjudicated.macro_f2 - baseline.macro_f2,
        precision=adjudicated.precision - baseline.precision,
        recall=adjudicated.recall - baseline.recall,
        fp_per_kloc=adjudicated.fp_per_kloc - baseline.fp_per_kloc,
        evidence_validity_rate=(
            adjudicated.evidence_validity_rate - baseline.evidence_validity_rate
        ),
        citation_resolution_rate=(
            adjudicated.citation_resolution_rate - baseline.citation_resolution_rate
        ),
        confirmed_count=adjudicated.confirmed_count - baseline.confirmed_count,
        review_required_count=(adjudicated.review_required_count - baseline.review_required_count),
        per_family=per_family,
    )


def _value(metrics: object, field: str) -> float:
    """One family metric, or zero when that family was not scored at all.

    A family present on one side and absent on the other is a real difference,
    and treating the absent side as zero is what makes it visible rather than
    dropping the family from the comparison.
    """
    return 0.0 if metrics is None else float(getattr(metrics, field))


def load_run_report(path: Path) -> RunReport:
    """Read a metrics file written by ``caudit eval``.

    Accepts the shape written before this module existed — a bare ``metrics``
    object with ``gates`` and ``tool_versions`` beside it — because a report
    recorded by an earlier revision is exactly the baseline a later run wants
    to be compared against. The fields it lacks default to empty, and
    :func:`_assert_comparable` then refuses on the ones that matter rather than
    guessing them.
    """
    payload: Mapping[str, object] = json.loads(path.read_text(encoding="utf-8"))
    if "metrics" not in payload:
        return RunReport(metrics=Metrics.model_validate(payload))
    known = set(RunReport.model_fields)
    return RunReport.model_validate({key: value for key, value in payload.items() if key in known})

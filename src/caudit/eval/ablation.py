"""Ablations: change one thing, re-measure, record what moved.

Every claim this project makes about its own design is a claim an ablation can
test. Compiler-aware retrieval is more complicated than reading a window of
lines around the diagnostic — this is where that complication has to earn
itself, against a flat window of comparable size, on the same cases, with the
same scorer.

Two rules make the results readable:

**One factor at a time.** A grid that varied budget and depth together would
produce a table nobody can attribute. :func:`vary` builds each configuration
from one baseline by changing a single field, and :func:`differing_fields`
checks it — the check is cheap and the mistake is easy.

**The flat-window control is not optional.** :func:`ablation_grid` always
includes it, and :func:`assert_control_present` refuses a set without one. An
ablation suite that only compares structural retrieval against itself measures
tuning, not value.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.config.loader import Config, ModelTierConfig, RetrievalVariantName
from caudit.retrieval.policy import RetrievalVariant

__all__ = [
    "AblationConfig",
    "AblationMode",
    "AblationResult",
    "AblationSuite",
    "RetrievalVariant",
    "RetrievalVariantName",
    "TierMode",
    "ablation_grid",
    "assert_control_present",
    "differing_fields",
    "vary",
]


class TierMode(StrEnum):
    """Which model tiers participate."""

    TRIAGE_ONLY = "triage_only"
    ADJUDICATION_ONLY = "adjudication_only"
    WITH_ESCALATION = "with_escalation"


#: The fields an ablation may vary. Enumerated so :func:`vary` can reject a
#: typo instead of silently building a configuration identical to its baseline
#: — an ablation that changed nothing would report "no effect" convincingly.
ABLATABLE_FIELDS: Final[tuple[str, ...]] = (
    "token_budget",
    "caller_depth",
    "callee_depth",
    "type_closure_depth",
    "expansion_policy_version",
    "retrieval_variant",
    "tier_mode",
)


class AblationConfig(BaseModel):
    """One point in the ablation grid."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    token_budget: int = Field(gt=0)
    caller_depth: int = Field(ge=0, le=8)
    #: These two became ablatable when the corpus first had call chains deep
    #: enough for them to matter: on single-function synthetic cases every
    #: value produced an identical run, so "the depth defaults are shallow"
    #: was an assertion nobody could test.
    #:
    #: ``callee_depth`` is ``ge=1`` here while
    #: :class:`~caudit.config.loader.RetrievalConfig` allows ``0``, and the
    #: divergence is deliberate. At ``0`` the callee walk in
    #: :func:`caudit.retrieval.paths` never enters its loop, so ``incomplete``
    #: stays false and the ``unresolved_indirect_call`` limitation is never
    #: attached -- a grid point at ``0`` reports *fewer* blind spots than one at
    #: ``1`` and reads as an improvement, when what changed is that nothing
    #: looked. A scan may still be configured that way; an ablation may not
    #: measure it that way.
    callee_depth: int = Field(default=1, ge=1, le=8)
    type_closure_depth: int = Field(default=2, ge=1, le=16)
    expansion_policy_version: str = Field(min_length=1)
    tiers: ModelTierConfig = Field(default_factory=ModelTierConfig)
    tier_mode: TierMode = TierMode.WITH_ESCALATION
    retrieval_variant: RetrievalVariant = RetrievalVariant.STRUCTURAL

    @property
    def is_control(self) -> bool:
        return self.retrieval_variant is RetrievalVariant.FLAT_WINDOW

    def factors(self) -> dict[str, object]:
        """Everything but the name — the name is a label, not a variable."""
        return {field: getattr(self, field) for field in ABLATABLE_FIELDS}

    def apply_to(self, config: Config) -> Config:
        """This configuration as a runnable :class:`Config`.

        Only the fields the ablation names are changed. Everything else comes
        from the caller's configuration, so an ablation measures the factor it
        varies rather than the difference between two hand-built configs.
        """
        merged: dict[str, Any] = config.model_dump()
        merged["token_budget"] = {**merged["token_budget"], "per_run": self.token_budget}
        merged["policy_versions"] = {
            **merged["policy_versions"],
            "retrieval": self.expansion_policy_version,
        }
        # The two factors that only became settable when part 13 needed them.
        # Without this the grid would build configurations that differ on
        # paper and produce identical runs.
        merged["retrieval"] = {
            **merged["retrieval"],
            "caller_depth": self.caller_depth,
            "callee_depth": self.callee_depth,
            "type_closure_depth": self.type_closure_depth,
            "variant": str(self.retrieval_variant),
        }
        merged["models"] = self.tiers.model_dump()
        merged["llm"] = {
            **merged["llm"],
            "triage_enabled": self.tier_mode is not TierMode.ADJUDICATION_ONLY,
            "allow_escalation": self.tier_mode is TierMode.WITH_ESCALATION,
        }
        return Config.model_validate(merged)


def differing_fields(left: AblationConfig, right: AblationConfig) -> list[str]:
    """Which ablatable factors differ between two configurations."""
    return sorted(name for name, value in left.factors().items() if value != right.factors()[name])


def vary(baseline: AblationConfig, field: str, value: object, *, name: str = "") -> AblationConfig:
    """One configuration differing from ``baseline`` in exactly one field.

    Raises on a field that is not ablatable and on a value that changes
    nothing — a grid point identical to its baseline would produce two
    identical rows and an apparent confirmation that the factor does not
    matter.
    """
    if field not in ABLATABLE_FIELDS:
        raise ValueError(
            f"{field!r} is not an ablatable factor; the grid varies {', '.join(ABLATABLE_FIELDS)}"
        )
    if getattr(baseline, field) == value:
        raise ValueError(
            f"varying {field} to {value!r} changes nothing: the baseline already has it. "
            "A grid point identical to its baseline reports 'no effect' for a factor "
            "that was never varied"
        )
    changed = baseline.model_copy(update={field: value, "name": name or f"{field}={_label(value)}"})
    varied = differing_fields(baseline, changed)
    if varied != [field]:  # pragma: no cover - guarded by the checks above
        raise ValueError(f"expected only {field} to change, but {', '.join(varied)} did")
    return changed


def _label(value: object) -> str:
    return str(value)


def ablation_grid(
    baseline: AblationConfig,
    *,
    token_budgets: Sequence[int] = (),
    caller_depths: Sequence[int] = (),
    callee_depths: Sequence[int] = (),
    type_closure_depths: Sequence[int] = (),
    retrieval_variants: Sequence[RetrievalVariant] = (),
    tier_modes: Sequence[TierMode] = (),
) -> list[AblationConfig]:
    """The baseline plus one configuration per varied value.

    The flat-window control is added whether or not it was asked for. It is the
    only configuration in the grid that tests whether the *approach* works
    rather than how well it is tuned, and leaving it out would be the easiest
    way to produce a flattering table.
    """
    grid = [baseline]
    for budget in token_budgets:
        if budget != baseline.token_budget:
            grid.append(vary(baseline, "token_budget", budget))
    for depth in caller_depths:
        if depth != baseline.caller_depth:
            grid.append(vary(baseline, "caller_depth", depth))
    for depth in callee_depths:
        if depth != baseline.callee_depth:
            grid.append(vary(baseline, "callee_depth", depth))
    for depth in type_closure_depths:
        if depth != baseline.type_closure_depth:
            grid.append(vary(baseline, "type_closure_depth", depth))
    for variant in retrieval_variants:
        if variant is not baseline.retrieval_variant:
            grid.append(vary(baseline, "retrieval_variant", variant))
    for mode in tier_modes:
        if mode is not baseline.tier_mode:
            grid.append(vary(baseline, "tier_mode", mode))

    if not any(config.is_control for config in grid):
        grid.append(vary(baseline, "retrieval_variant", RetrievalVariant.FLAT_WINDOW))
    return grid


def assert_control_present(configs: Sequence[AblationConfig]) -> None:
    """Refuse an ablation set with no flat-window control (AC-13-9)."""
    if not any(config.is_control for config in configs):
        raise ValueError(
            "this ablation set has no flat_window control, so it cannot measure "
            "whether compiler-aware retrieval earns its complexity — only how well it "
            "is tuned"
        )


class AblationMode(StrEnum):
    """What a row actually measured.

    ``detection`` is the full pipeline with a model in the loop, and its
    ``macro_f2`` answers the question the ablation is really about.

    ``retrieval_only`` runs expansion and stops. It needs no API key, which is
    what makes it runnable where a model is not available, and it measures the
    one thing that separates the variants offline: whether the code that
    decides the answer was retrieved at all, and what it cost. Its ``macro_f2``
    is the analyzer-only score and is **identical in every row** — no model
    read the context, so nothing downstream of retrieval could move. Reading a
    variant comparison out of that column would be reading noise; the mode is
    recorded so that mistake is not available.
    """

    DETECTION = "detection"
    RETRIEVAL_ONLY = "retrieval_only"


class AblationResult(BaseModel):
    """What one configuration produced. Four axes, reported together."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config: AblationConfig
    macro_f2: float
    evidence_validity_rate: float
    citation_resolution_rate: float
    confirmed_count: int = Field(ge=0)
    review_required_count: int = Field(ge=0)
    tokens: int = Field(default=0, ge=0)
    wall_time_s: float = Field(default=0.0, ge=0.0)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    mode: AblationMode = AblationMode.DETECTION
    #: Model calls that actually happened. A row that meant to measure
    #: detection and made none of these did not measure detection — a missing
    #: key, an unreachable provider or a cost ceiling that bound immediately
    #: all produce a full grid of provider failures, which reads exactly like
    #: a model that found nothing.
    adjudication_calls: int = Field(default=0, ge=0)
    #: Share of ground-truth vulnerable lines that appear inside some retrieved
    #: unit. ``None`` when nothing measured it. This is the column a
    #: retrieval-only grid is read from: a variant that does not put the
    #: decisive lines in front of the model cannot be rescued by the model.
    evidence_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    #: How many candidate contexts the coverage above was computed over. A rate
    #: with no denominator beside it is a number people over-read.
    contexts_measured: int = Field(default=0, ge=0)

    # ------------------------------------------------------- scaling hazards
    #
    # Three limits that are structural rather than accidental, and that no
    # synthetic corpus can exhibit: a single-function case never starves a 2M
    # budget, never overruns a 24k context, and has no dispatch table to lose.
    # They were documented as risks and never measured, which is the same
    # standing as an unmeasured claim. Counted per row so a configuration that
    # trades one for another is visible rather than inferred.
    #
    # All default to 0 and are optional on input: a record written before they
    # existed still loads, and `extra="forbid"` rejects unknown keys, not
    # absent ones.

    #: Candidates the run budget was gone before reaching. Their diagnostic
    #: still reaches the report as review-required; what is lost is the
    #: expansion, so they are a *lower* bound on what a bigger budget would see.
    starved_candidates: int = Field(default=0, ge=0)
    #: Candidates whose primary set alone exceeded the per-candidate ceiling.
    #: Nothing is emitted for these -- a half-function is worse than admitting
    #: the limit -- so they reach the model with no context at all.
    budget_exceeded_candidates: int = Field(default=0, ge=0)
    #: Candidates whose *callee* traversal hit a call through a function
    #: pointer and stopped there.
    #:
    #: The callee direction only. `callers_of` returns every unresolved site in
    #: the whole index rather than those reachable from the target, so on any
    #: real C codebase with one dispatch table the caller direction is
    #: incomplete for every candidate -- correct, and a column of all ones that
    #: distinguishes nothing.
    indirect_callee_candidates: int = Field(default=0, ge=0)

    def row(self) -> tuple[str, float, float, int, float]:
        """The comparison table's line: quality, validity, cost, latency."""
        return (
            self.config.name,
            self.macro_f2,
            self.evidence_validity_rate,
            self.tokens,
            self.wall_time_s,
        )


class AblationSuite(BaseModel):
    """A whole grid's results, and what they may be compared with.

    Results from two different policy configurations are not one experiment.
    The suite refuses to hold both rather than letting a reader difference two
    rows that were never comparable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    baseline_name: str = Field(min_length=1)
    results: list[AblationResult] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_one_baseline_and_one_control(self) -> Self:
        names = [result.config.name for result in self.results]
        if not self.results:
            return self
        if self.baseline_name not in names:
            raise ValueError(
                f"the baseline {self.baseline_name!r} is not among the results "
                f"({', '.join(names)}); every delta here is measured against it"
            )
        assert_control_present([result.config for result in self.results])
        duplicated = sorted({name for name in names if names.count(name) > 1})
        if duplicated:
            raise ValueError(f"duplicate configuration name(s): {', '.join(duplicated)}")
        return self

    @property
    def baseline(self) -> AblationResult | None:
        return next(
            (result for result in self.results if result.config.name == self.baseline_name), None
        )

    @property
    def control(self) -> AblationResult | None:
        return next((result for result in self.results if result.config.is_control), None)

    def deltas(self) -> dict[str, float]:
        """Each configuration's macro-F2 minus the baseline's."""
        base = self.baseline
        if base is None:  # pragma: no cover - guarded by the validator
            return {}
        return {
            result.config.name: result.macro_f2 - base.macro_f2
            for result in self.results
            if result.config.name != self.baseline_name
        }

    def structural_retrieval_earns_itself(self) -> bool | None:
        """Whether the structural baseline beat the flat-window control.

        ``None`` when the control has not been run — which is a different
        answer from "no", and is the one this project must never report as a
        yes.

        ``None`` too when either row was measured ``retrieval_only``. Those
        rows carry the analyzer-only score in every configuration, so
        comparing them would reliably return ``False``: a confident "structural
        retrieval does not earn itself", produced by an experiment in which no
        model ever read either context. Use :meth:`structural_retrieval_covers_more`
        for what a retrieval-only grid can actually answer.
        """
        base, control = self.baseline, self.control
        if base is None or control is None:
            return None
        if AblationMode.RETRIEVAL_ONLY in {base.mode, control.mode}:
            return None
        return base.macro_f2 > control.macro_f2

    def structural_retrieval_covers_more(self) -> bool | None:
        """Whether structural retrieval put more of the decisive code on the page.

        The question a grid can answer with no model and no API key. ``None``
        when the control has not run or when either row measured no coverage.
        """
        base, control = self.baseline, self.control
        if base is None or control is None:
            return None
        if base.evidence_coverage is None or control.evidence_coverage is None:
            return None
        return base.evidence_coverage > control.evidence_coverage


class Scorer(Protocol):
    """Measures one configuration.

    Injected rather than imported, so an ablation can be tested without running
    a suite and so this module never grows a second opinion about how a run is
    scored.
    """

    # Positional-only: an implementation is free to call the argument what it
    # reads best as, and :class:`~caudit.eval.ablation_runner.SuiteScorer`
    # already has a ``config`` of its own that this would shadow.
    def __call__(self, ablation: AblationConfig, /) -> AblationResult: ...


def run_grid(
    configs: Iterable[AblationConfig],
    score: Scorer,
    *,
    name: str,
    baseline_name: str,
    policy_versions: Mapping[str, str],
) -> AblationSuite:
    """Score every configuration in the grid, in order.

    Deterministic given a deterministic scorer: the configurations are visited
    in the order the grid built them, and nothing here reads a clock or a
    random source. That is what makes T-13-10 — the same grid twice with a warm
    cache producing identical results — a meaningful check rather than a
    coincidence.
    """
    results = [_with_policies(score(config), policy_versions) for config in configs]
    return AblationSuite(name=name, baseline_name=baseline_name, results=results)


def _with_policies(result: AblationResult, policy_versions: Mapping[str, str]) -> AblationResult:
    if result.policy_versions:
        return result
    return result.model_copy(update={"policy_versions": dict(sorted(policy_versions.items()))})


def write_suite(suite: AblationSuite, path: Path) -> Path:
    """Record a grid's results. Sorted keys, so two runs diff cleanly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.loads(suite.model_dump_json())
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path

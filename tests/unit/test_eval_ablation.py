"""Part 13's ablations: T-13-09 to T-13-11 (AC-13-8, AC-13-9).

Two properties, and the second is the one the project has most to lose from:
a grid varies exactly one factor per row, and it always contains the
flat-window control that asks whether compiler-aware retrieval earns its
complexity at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from caudit.config.loader import Config
from caudit.eval.ablation import (
    ABLATABLE_FIELDS,
    AblationConfig,
    AblationResult,
    AblationSuite,
    RetrievalVariant,
    TierMode,
    ablation_grid,
    assert_control_present,
    differing_fields,
    run_grid,
    vary,
    write_suite,
)

POLICIES = {"matching": "1", "prompt": "2", "retrieval": "1"}


def _baseline(**overrides: object) -> AblationConfig:
    fields: dict[str, object] = {
        "name": "baseline",
        "token_budget": 24_000,
        "caller_depth": 2,
        "expansion_policy_version": "1",
    }
    fields.update(overrides)
    return AblationConfig.model_validate(fields)


def _result(config: AblationConfig, macro_f2: float = 0.6) -> AblationResult:
    return AblationResult(
        config=config,
        macro_f2=macro_f2,
        evidence_validity_rate=1.0,
        citation_resolution_rate=1.0,
        confirmed_count=4,
        review_required_count=1,
        tokens=1000,
        wall_time_s=10.0,
    )


# ------------------------------------------------------------------- T-13-09


def test_a_budget_grid_varies_only_the_budget() -> None:
    """T-13-09 (AC-13-8): a row that changed two things cannot be attributed."""
    baseline = _baseline()
    grid = ablation_grid(baseline, token_budgets=[8_000, 48_000])

    budget_rows = [config for config in grid if config.name.startswith("token_budget=")]
    assert len(budget_rows) == 2
    for config in budget_rows:
        assert differing_fields(baseline, config) == ["token_budget"]

    assert {config.token_budget for config in budget_rows} == {8_000, 48_000}


def test_varying_an_unknown_field_is_refused() -> None:
    """A typo would otherwise build a row identical to the baseline."""
    with pytest.raises(ValueError, match="not an ablatable factor"):
        vary(_baseline(), "tokenn_budget", 8_000)
    assert "token_budget" in ABLATABLE_FIELDS


def test_varying_a_field_to_the_value_it_already_has_is_refused() -> None:
    """A row identical to the baseline reports 'no effect' convincingly."""
    with pytest.raises(ValueError, match="changes nothing"):
        vary(_baseline(), "token_budget", 24_000)


def test_the_grid_skips_values_the_baseline_already_uses() -> None:
    grid = ablation_grid(_baseline(), token_budgets=[24_000, 8_000])
    assert sum(1 for config in grid if config.token_budget == 24_000) == 2  # baseline + control


def test_a_configuration_applies_only_the_fields_it_names() -> None:
    """AC-13-8: an ablation measures its factor, not two hand-built configs."""
    config = _baseline(token_budget=8_000, tier_mode=TierMode.ADJUDICATION_ONLY)
    original = Config()
    applied = config.apply_to(original)

    assert applied.token_budget.per_run == 8_000
    assert applied.llm.triage_enabled is False
    assert applied.llm.allow_escalation is False
    # Everything the ablation does not name is untouched.
    assert applied.exclude_globs == original.exclude_globs
    assert applied.token_budget.per_candidate == original.token_budget.per_candidate
    assert applied.policy_versions.prompt == original.policy_versions.prompt


def test_the_tier_modes_map_onto_the_two_switches_that_exist() -> None:
    original = Config()
    with_escalation = _baseline(tier_mode=TierMode.WITH_ESCALATION).apply_to(original)
    triage_only = _baseline(tier_mode=TierMode.TRIAGE_ONLY).apply_to(original)

    assert with_escalation.llm.triage_enabled and with_escalation.llm.allow_escalation
    assert triage_only.llm.triage_enabled and not triage_only.llm.allow_escalation


# ------------------------------------------------------------------- T-13-11


def test_the_flat_window_control_is_added_even_when_nobody_asked() -> None:
    """T-13-11 (AC-13-9): leaving it out is the easiest flattering table."""
    grid = ablation_grid(_baseline(), token_budgets=[8_000])
    controls = [config for config in grid if config.is_control]

    assert len(controls) == 1
    assert differing_fields(_baseline(), controls[0]) == ["retrieval_variant"]


def test_a_set_without_a_control_is_refused() -> None:
    """AC-13-9: a suite comparing structural retrieval with itself measures tuning."""
    with pytest.raises(ValueError, match="no flat_window control"):
        assert_control_present([_baseline()])


def test_a_suite_reports_whether_structural_retrieval_beat_the_control() -> None:
    """The question parts 06 and 09 exist to have answered."""
    baseline = _baseline()
    control = vary(baseline, "retrieval_variant", RetrievalVariant.FLAT_WINDOW)

    won = AblationSuite(
        name="retrieval",
        baseline_name="baseline",
        results=[_result(baseline, 0.72), _result(control, 0.61)],
    )
    assert won.structural_retrieval_earns_itself() is True
    assert won.deltas()[control.name] == pytest.approx(-0.11)

    lost = AblationSuite(
        name="retrieval",
        baseline_name="baseline",
        results=[_result(baseline, 0.58), _result(control, 0.63)],
    )
    assert lost.structural_retrieval_earns_itself() is False


def test_an_unrun_control_is_not_reported_as_a_win() -> None:
    """``None`` is a different answer from "no", and must never read as "yes"."""
    suite = AblationSuite(name="empty", baseline_name="baseline")
    assert suite.structural_retrieval_earns_itself() is None
    assert suite.deltas() == {}


def test_a_suite_whose_baseline_is_missing_is_refused() -> None:
    control = vary(_baseline(), "retrieval_variant", RetrievalVariant.FLAT_WINDOW)
    with pytest.raises(ValidationError, match="is not among the results"):
        AblationSuite(name="s", baseline_name="baseline", results=[_result(control)])


def test_duplicate_configuration_names_are_refused() -> None:
    baseline = _baseline()
    control = vary(baseline, "retrieval_variant", RetrievalVariant.FLAT_WINDOW)
    with pytest.raises(ValidationError, match="duplicate configuration name"):
        AblationSuite(
            name="s",
            baseline_name="baseline",
            results=[_result(baseline), _result(baseline), _result(control)],
        )


# ------------------------------------------------------------------- T-13-10


def test_running_the_same_grid_twice_produces_identical_results() -> None:
    """T-13-10 (AC-13-8): deterministic given a deterministic scorer."""
    grid = ablation_grid(_baseline(), token_budgets=[8_000], caller_depths=[0, 4])
    scores = {config.name: 0.5 + index / 100 for index, config in enumerate(grid)}

    def score(config: AblationConfig) -> AblationResult:
        return _result(config, scores[config.name])

    first = run_grid(grid, score, name="grid", baseline_name="baseline", policy_versions=POLICIES)
    second = run_grid(grid, score, name="grid", baseline_name="baseline", policy_versions=POLICIES)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert [result.config.name for result in first.results] == [c.name for c in grid]


def test_every_result_records_the_policy_versions_it_was_produced_under() -> None:
    """AC-13-11: a result that cannot name its policy cannot be compared."""
    grid = ablation_grid(_baseline(), token_budgets=[8_000])
    suite = run_grid(
        grid,
        lambda config: _result(config),
        name="grid",
        baseline_name="baseline",
        policy_versions=POLICIES,
    )
    assert all(result.policy_versions == POLICIES for result in suite.results)


def test_a_result_that_already_names_its_policy_is_left_alone() -> None:
    """A scorer that recorded the truth is not overwritten by the runner."""
    grid = [_baseline(), vary(_baseline(), "retrieval_variant", RetrievalVariant.FLAT_WINDOW)]
    own = {"prompt": "9"}

    suite = run_grid(
        grid,
        lambda config: _result(config).model_copy(update={"policy_versions": own}),
        name="grid",
        baseline_name="baseline",
        policy_versions=POLICIES,
    )
    assert all(result.policy_versions == own for result in suite.results)


def test_a_suite_is_written_with_sorted_keys(tmp_path: Path) -> None:
    grid = ablation_grid(_baseline())
    suite = run_grid(
        grid,
        lambda config: _result(config),
        name="grid",
        baseline_name="baseline",
        policy_versions=POLICIES,
    )
    path = write_suite(suite, tmp_path / "ablation.json")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["baseline_name"] == "baseline"
    assert any(row["config"]["retrieval_variant"] == "flat_window" for row in payload["results"])


def test_the_result_row_carries_quality_validity_cost_and_latency() -> None:
    """AC-13-8: four axes, so a cheaper configuration cannot hide a worse one."""
    name, macro_f2, validity, tokens, wall = _result(_baseline(), 0.66).row()
    assert name == "baseline"
    assert macro_f2 == pytest.approx(0.66)
    assert validity == pytest.approx(1.0)
    assert tokens == 1000
    assert wall == pytest.approx(10.0)

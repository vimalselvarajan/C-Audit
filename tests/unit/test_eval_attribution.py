"""Naïve Gemini controls and the cumulative attribution matrix."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.cli.attribution_cmd import run_attribution
from caudit.config.loader import Config
from caudit.eval.attribution import AttributionStage, AttributionStatus
from caudit.llm.provider import ProviderRequest
from caudit.model.adjudication import ProviderResponse, Usage
from caudit.retrieval.budget import DEFAULT_TOKENIZER


class _ControlProvider:
    def __init__(self, verdict: str = "confirmed") -> None:
        self.verdict = verdict
        self.requests: list[ProviderRequest] = []

    def adjudicate(self, request: ProviderRequest) -> ProviderResponse:
        self.requests.append(request)
        if str(request.tier) == "triage":
            text = json.dumps(
                {
                    "disposition": "adjudicate",
                    "ambiguous": False,
                    "impact": _impact(),
                    "rationale": "the compact tier routes this candidate onward",
                }
            )
        elif (
            request.prompt.prompt_version.startswith("naive-control") and request.structured_output
        ):
            text = json.dumps(
                {
                    "verdict": self.verdict,
                    "cwe": "CWE-787" if self.verdict == "confirmed" else None,
                    "rationale": "the fixed source window supports this classification",
                }
            )
        elif request.prompt.prompt_version.startswith("naive-control"):
            text = (
                f"VERDICT: {self.verdict}\n"
                f"CWE: {'CWE-787' if self.verdict == 'confirmed' else 'none'}\n"
                "RATIONALE: the fixed source window supports this classification"
            )
        else:
            text = json.dumps(_adjudication(request, self.verdict))
        return ProviderResponse(
            tier=request.tier,
            model_id=request.model_id,
            text=text,
            usage=Usage(input_tokens=100, output_tokens=20),
            finish_reason="STOP",
        )

    def token_count(self, text: str) -> int:
        return DEFAULT_TOKENIZER.count(text)


def _impact() -> dict[str, str]:
    return {
        "kind": "memory_corruption",
        "severity": "high",
        "description": "memory can be overwritten",
        "evidence_supports": "the cited operation writes memory",
    }


def _adjudication(request: ProviderRequest, verdict: str) -> dict[str, object]:
    cited = list(request.prompt.evidence_ids[:1])
    return {
        "verdict": verdict,
        "cited_evidence_ids": cited,
        "cwe": "CWE-787" if verdict == "confirmed" else None,
        "cwe_rationale": "the operation may exceed the destination bound",
        "trigger_conditions": ["the input exceeds the destination"],
        "impact": _impact(),
        "reachability": "unknown",
        "exploitability": "unknown",
        "remediation": {"strategy": "enforce a bound", "rationale": "prevent overflow"},
        "maintainability_impact": {
            "ownership": "local",
            "complexity": "small",
            "coupling": "unknown",
            "regression_risk": "low",
            "effort": "low",
        },
        "unresolved_assumptions": ["input size is attacker controlled"],
        "quoted_evidence": [],
        "asserted_call_edges": [],
        "confidence_self_report": "high" if verdict == "confirmed" else "review_required",
    }


def _config() -> Config:
    return Config.model_validate(
        {
            "cloud_consent": True,
            "llm": {
                "cache_enabled": False,
                "max_attempts": 1,
                "max_transport_attempts": 1,
            },
        }
    )


def test_a0_through_a2_share_identity_and_differ_only_on_structure(tmp_path: Path) -> None:
    provider = _ControlProvider()

    run = run_attribution(
        config=_config(),
        suite="mini",
        out_dir=tmp_path,
        through=AttributionStage.A2,
        provider=provider,
    )

    measured = [row for row in run.matrix.rows if row.status is AttributionStatus.MEASURED]
    assert [row.stage for row in measured] == [
        AttributionStage.A0,
        AttributionStage.A1,
        AttributionStage.A2,
    ]
    assert len({run.matrix.invariant.candidate_set_hash}) == 1
    assert run.matrix.invariant.model_id == "gemini-3.5-flash-lite"
    assert run.matrix.invariant.thinking_level == "low"
    assert run.matrix.invariant.max_output_tokens == 4096
    assert any(not request.structured_output for request in provider.requests)
    assert any(request.structured_output for request in provider.requests)
    assert all(request.prompt.evidence_ids == () for request in provider.requests)
    assert run.matrix.rows[6].status is AttributionStatus.DEFERRED
    assert run.matrix.rows[7].status is AttributionStatus.DEFERRED
    assert {item.name for item in run.matrix.leave_one_out} == {
        "A7-minus-verifier",
        "A7-minus-structural-retrieval",
    }
    assert run.matrix_path.is_file()
    assert all(path.is_file() for path in run.reports.values())


def test_naive_rejection_moves_candidates_to_review_without_deleting_them(
    tmp_path: Path,
) -> None:
    run = run_attribution(
        config=_config(),
        suite="mini",
        out_dir=tmp_path,
        through=AttributionStage.A2,
        provider=_ControlProvider(verdict="rejected"),
    )

    a0 = run.matrix.rows[0]
    a2 = run.matrix.rows[2]
    assert a0.confirmed_count is not None and a0.confirmed_count > 0
    assert a2.confirmed_count == 0
    assert a0.review_required_count is not None
    assert a2.review_required_count == a0.confirmed_count + a0.review_required_count


@pytest.mark.needs_libclang
def test_cumulative_runner_reaches_a5_with_all_prior_rows_measured(tmp_path: Path) -> None:
    run = run_attribution(
        config=_config(),
        suite="mini",
        out_dir=tmp_path,
        through=AttributionStage.A5,
        provider=_ControlProvider(),
    )

    assert [row.status for row in run.matrix.rows[:6]] == [AttributionStatus.MEASURED] * 6
    assert run.matrix.rows[3].capabilities[-1] == "issued evidence identifiers"
    assert "verification" in run.matrix.rows[4].capabilities[-1]
    assert "routing" in run.matrix.rows[5].capabilities[-1]


@pytest.mark.parametrize("stage", [AttributionStage.A6, AttributionStage.A7])
def test_unimplemented_evidence_tool_stages_are_refused(
    stage: AttributionStage, tmp_path: Path
) -> None:
    from caudit.errors import UsageError

    with pytest.raises(UsageError, match="predeclared but not implemented"):
        run_attribution(
            config=_config(),
            suite="mini",
            out_dir=tmp_path,
            through=stage,
            provider=_ControlProvider(),
        )

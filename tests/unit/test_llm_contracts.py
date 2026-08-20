"""Small contracts the rest of part 10 leans on.

Each of these is an invariant some other test assumes without checking: that a
duplicated citation is refused, that a template asking for something assembly
does not supply is an error rather than a literal ``{{NAME}}`` in a request,
that a cassette turn cannot both answer and fail, and that a cache entry which
no longer validates costs a call rather than the run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.llm.cache import CacheEntry, cache_key
from caudit.llm.cassette import Cassette, CassetteTurn, TurnFailure
from caudit.llm.prompts import PromptError, _substitute
from caudit.llm.schema import flatten_response_schema
from caudit.llm.service import ResponseCache, RunAccount, Tier, Usage
from caudit.model.adjudication import Adjudication, TriageDisposition, TriageResult, Verdict
from caudit.model.finding import Impact, ImpactKind, Severity

_VALID = {
    "verdict": "rejected",
    "cited_evidence_ids": ["ev-1", "ev-2"],
    "cwe": None,
    "cwe_rationale": "no weakness",
    "trigger_conditions": [],
    "impact": {
        "kind": "incorrect_result",
        "severity": "low",
        "description": "d",
        "evidence_supports": "e",
    },
    "reachability": "unknown",
    "exploitability": "unknown",
    "remediation": {"strategy": "s", "rationale": "r"},
    "maintainability_impact": {
        "ownership": "o",
        "complexity": "c",
        "coupling": "k",
        "regression_risk": "g",
    },
    "unresolved_assumptions": [],
    "confidence_self_report": "medium",
}


# ------------------------------------------------------------- the proposal


def test_the_same_evidence_id_cannot_be_cited_twice() -> None:
    """Two citations of one region is one citation, said twice."""
    with pytest.raises(ValueError, match="more than once"):
        Adjudication.model_validate(_VALID | {"cited_evidence_ids": ["ev-1", "ev-1"]})


def test_a_blank_citation_is_not_a_citation() -> None:
    with pytest.raises(ValueError, match="blank id"):
        Adjudication.model_validate(_VALID | {"cited_evidence_ids": ["ev-1", "  "]})


def test_a_rejection_is_a_complete_answer(tmp_path: Path) -> None:
    proposal = Adjudication.model_validate(_VALID)
    assert proposal.verdict is Verdict.REJECTED
    assert proposal.cwe is None
    assert proposal.unresolved_assumptions == []


def test_the_routing_table_reads_a_rejection_as_a_dismissal() -> None:
    derived = TriageResult.from_verdict(
        Verdict.REJECTED,
        Impact(
            kind=ImpactKind.INCORRECT_RESULT,
            severity=Severity.LOW,
            description="d",
            evidence_supports="e",
        ),
        rationale="the analyzer was wrong",
    )
    assert derived.disposition is TriageDisposition.DISMISS
    assert derived.ambiguous is False


def test_usage_adds_without_losing_either_side() -> None:
    total = Usage(input_tokens=10, output_tokens=2) + Usage(input_tokens=5, output_tokens=1)
    assert total == Usage(input_tokens=15, output_tokens=3)


# ------------------------------------------------------------------ prompts


def test_a_template_asking_for_something_assembly_cannot_supply_is_an_error() -> None:
    """Better than shipping a literal ``{{WHATEVER}}`` in a request body."""
    with pytest.raises(PromptError, match="WHATEVER"):
        _substitute("before {{WHATEVER}} after", {"TIER": "triage"})


def test_substitution_leaves_unrelated_braces_alone() -> None:
    rendered = _substitute("if (x) { y(); } {{TIER}}", {"TIER": "triage"})
    assert rendered == "if (x) { y(); } triage"


# ----------------------------------------------------------------- cassettes


def test_a_turn_either_answers_or_fails() -> None:
    with pytest.raises(ValueError, match="never both, never neither"):
        CassetteTurn()
    with pytest.raises(ValueError, match="never both, never neither"):
        CassetteTurn(text="{}", fails=TurnFailure.UNAVAILABLE)


def test_a_cassette_round_trips_through_disk(tmp_path: Path) -> None:
    """Committed recordings are read back by the same model that wrote them."""
    original = Cassette(
        name="round-trip",
        description="a recording",
        turns=[CassetteTurn(text="{}", usage=Usage(input_tokens=1, output_tokens=2))],
    )
    path = original.write(tmp_path / "sub" / "cassette.json")
    assert Cassette.load(path) == original


def test_every_committed_cassette_parses() -> None:
    """A recording that no longer loads is a test that silently stops running."""
    from tests.conftest import CASSETTE_ROOT

    files = sorted(CASSETTE_ROOT.glob("*.json"))
    assert files, "the committed cassettes have gone missing"
    for path in files:
        text = path.read_text(encoding="utf-8")
        # Placeholders are resolved at load time; this only checks the shape.
        cassette = Cassette.model_validate_json(text.replace("${EVIDENCE_ID:0}", "ev-x"))
        assert cassette.turns
        assert cassette.description, f"{path.name} does not say what it is for"


# --------------------------------------------------------------------- cache


def test_a_cache_entry_replays_down_the_normal_path() -> None:
    entry = CacheEntry(
        key="k",
        tier=Tier.ADJUDICATION,
        model_id="m",
        prompt_version="1",
        schema_version="1.5.0",
        prompt_fingerprint="f",
        payload=_VALID,
        usage=Usage(input_tokens=4, output_tokens=5),
        finish_reason="STOP",
        created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    response = entry.as_response()
    assert response.from_cache
    assert Adjudication.model_validate_json(response.text).verdict is Verdict.REJECTED
    assert response.usage.input_tokens == 4


def test_a_cache_entry_whose_payload_no_longer_validates_is_a_miss(
    tmp_path: Path,
) -> None:
    """A schema change must cost a call, never a wrong answer."""
    from caudit.llm.service import adjudicate, response_cache
    from tests.conftest import (
        cassette_provider,
        granted_consent,
        no_sleep,
        retrieval_context,
    )

    config = Config.model_validate(
        {
            "llm": {
                "triage_enabled": False,
                "cache_enabled": True,
                "cache_dir": str(tmp_path / "cache"),
            }
        }
    )
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=response_cache(config),
        sleeper=no_sleep,
    )

    stored = next((tmp_path / "cache").glob("*.json"))
    payload = json.loads(stored.read_text(encoding="utf-8"))
    # A field the current model no longer accepts.
    payload["payload"]["severity_shortcut"] = "high"
    stored.write_text(json.dumps(payload), encoding="utf-8")

    second, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    outcome = adjudicate(
        context,
        config=config,
        provider=second,
        consent=granted_consent(),
        account=RunAccount(config=config),
        cache=response_cache(config),
        sleeper=no_sleep,
    )
    assert second.calls == 1, "an unusable entry must cost a call"
    assert outcome.accepted
    assert not outcome.from_cache


def test_a_cache_with_no_directory_is_simply_disabled() -> None:
    cache = ResponseCache(None)
    assert not cache.enabled
    assert cache.path_for("k") is None
    assert cache.get("k") is None
    assert "disabled" in cache.describe()


def test_the_cache_key_is_domain_separated() -> None:
    """Its digest cannot collide with an evidence id or a finding id."""
    from caudit.model.ids import evidence_id
    from tests.conftest import make_region

    key = cache_key(prompt="p", model_id="m", prompt_version="1", schema_version="1")
    assert key != evidence_id(make_region(), "primary_code")
    assert len(key) == 64


# -------------------------------------------------------------- accounting


def test_the_account_describes_itself_without_summing_anything_it_should_not() -> None:
    config = Config()
    account = RunAccount(config=config)
    account.charge(Tier.ADJUDICATION, Usage(input_tokens=100, output_tokens=20))
    described = account.describe()
    assert "1 call" in described
    assert "120 reported tokens" in described


def test_a_tiers_cost_uses_that_tiers_price() -> None:
    from caudit.config.loader import TierPricing
    from caudit.llm.service import TierAccount

    account = TierAccount(tier=Tier.TRIAGE, model_id="m")
    account.usage = Usage(input_tokens=1_000_000, output_tokens=500_000)
    price = TierPricing(input_per_million_usd=2.0, output_per_million_usd=8.0)
    assert account.cost_usd(price) == pytest.approx(2.0 + 4.0)


# ------------------------------------------------------------------- schema


def test_an_anyof_the_flattener_does_not_recognise_is_left_alone() -> None:
    """Collapsing only applies to the nullable shape pydantic actually emits."""
    schema = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
    assert flatten_response_schema(schema) == schema


def test_a_nullable_branch_that_is_not_an_object_is_left_alone() -> None:
    schema = {"anyOf": ["not a schema", {"type": "null"}]}
    assert flatten_response_schema(schema) == schema

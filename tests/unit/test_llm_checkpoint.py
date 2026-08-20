"""Atomic checkpoint identity, persistence, and account restoration."""

from pathlib import Path

import pytest

from caudit.application.pipeline import CandidateOutcome
from caudit.config.loader import Config
from caudit.llm.accounting import RunAccount
from caudit.llm.checkpoint import (
    CheckpointError,
    CheckpointStore,
    checkpoint_identity,
    restore_account,
)
from caudit.model.adjudication import Tier, Usage
from caudit.model.evidence import Producer, Provenance
from tests.conftest import make_candidate, make_finding


def _provenance() -> list[Provenance]:
    return [
        Provenance(
            producer=Producer.CLANG_TIDY,
            tool_name="clang-tidy",
            tool_version="18",
            rule_id="clang-analyzer-security.insecureAPI.strcpy",
        )
    ]


def test_checkpoint_round_trips_final_state_and_both_ledgers(tmp_path: Path) -> None:
    provenance = _provenance()
    candidate = make_candidate(provenance)
    outcome = CandidateOutcome(
        candidate=candidate,
        finding=make_finding(provenance, region=candidate.region),
        resumed=True,
    )
    config = Config()
    identity = checkpoint_identity([candidate], config)
    account = RunAccount(config=config)
    account.charge(
        Tier.ADJUDICATION,
        Usage(
            input_tokens=100,
            output_tokens=20,
            thinking_tokens=5,
            total_tokens=125,
        ),
    )

    path = CheckpointStore(tmp_path / "checkpoint.json").save(
        identity=identity,
        outcomes=[outcome],
        account=account,
        retrieval_spent=77,
        retrieval_starved=["later-candidate"],
    )
    loaded = CheckpointStore(path).load(identity)

    assert loaded is not None
    assert loaded.entries[0].candidate == candidate
    assert loaded.entries[0].finding == outcome.finding
    assert loaded.entries[0].adjudicated
    assert loaded.retrieval_spent == 77
    assert loaded.retrieval_starved == ["later-candidate"]
    assert not path.with_suffix(".json.tmp").exists()

    restored = RunAccount(config=config)
    restore_account(restored, loaded)
    assert restored.total_tokens == 125
    assert restored.calls == 1
    assert restored.quota_tokens == 125
    assert restored.quota_requests == 0


def test_changed_experiment_identity_refuses_without_overwriting(tmp_path: Path) -> None:
    provenance = _provenance()
    candidate = make_candidate(provenance)
    config = Config()
    path = tmp_path / "checkpoint.json"
    store = CheckpointStore(path)
    store.save(
        identity=checkpoint_identity([candidate], config),
        outcomes=[],
        account=RunAccount(config=config),
        retrieval_spent=0,
        retrieval_starved=[],
    )
    before = path.read_bytes()

    with pytest.raises(CheckpointError, match="does not match"):
        store.load("f" * 64)
    assert path.read_bytes() == before


def test_quota_snapshot_refresh_does_not_change_continuation_identity() -> None:
    provenance = _provenance()
    candidate = make_candidate(provenance)
    before = Config.model_validate(
        {"llm": {"quota_snapshot": {"source": "AI Studio", "requests_per_day": 20}}}
    )
    after = Config.model_validate(
        {"llm": {"quota_snapshot": {"source": "AI Studio", "requests_per_day": 50}}}
    )

    assert checkpoint_identity([candidate], before) == checkpoint_identity([candidate], after)

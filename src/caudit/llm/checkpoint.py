"""Atomic per-candidate checkpoints for quota-safe continuation."""

from __future__ import annotations

import json
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.llm.accounting import RunAccount
from caudit.model.adjudication import Tier, Usage
from caudit.model.candidate import Candidate
from caudit.model.finding import Finding, Limitation
from caudit.model.manifest import ModelRecord

__all__ = [
    "CheckpointEntry",
    "CheckpointError",
    "CheckpointState",
    "CheckpointStore",
    "checkpoint_identity",
    "restore_account",
]


class CheckpointError(CauditError):
    """A checkpoint is corrupt or belongs to a different experiment."""


class _Outcome(Protocol):
    @property
    def candidate(self) -> Candidate: ...

    @property
    def finding(self) -> Finding: ...

    @property
    def limitations(self) -> tuple[Limitation, ...]: ...

    @property
    def adjudicated(self) -> bool: ...


class CheckpointEntry(BaseModel):
    """Source-free final state for one completed candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: Candidate
    finding: Finding
    adjudicated: bool = False
    limitations: list[Limitation] = Field(default_factory=list)

    @classmethod
    def from_outcome(cls, outcome: _Outcome) -> CheckpointEntry:
        return cls(
            candidate=outcome.candidate,
            finding=outcome.finding,
            adjudicated=outcome.adjudicated,
            limitations=list(outcome.limitations),
        )


class CheckpointState(BaseModel):
    """Completed prefix plus both run-level budget ledgers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    identity: str = Field(min_length=64, max_length=64)
    entries: list[CheckpointEntry] = Field(default_factory=list)
    models: list[ModelRecord] = Field(default_factory=list)
    quota_tokens: int = Field(default=0, ge=0)
    refused: list[str] = Field(default_factory=list)
    retrieval_spent: int = Field(default=0, ge=0)
    retrieval_starved: list[str] = Field(default_factory=list)


def checkpoint_identity(candidates: Sequence[Candidate], config: Config) -> str:
    """Hash inputs that affect answers, excluding the provider quota window."""

    config_payload = config.model_dump(mode="json")
    llm = dict(config_payload["llm"])
    llm.pop("quota_snapshot", None)
    config_payload["llm"] = llm
    payload = {
        "candidates": [
            candidate.model_dump(mode="json")
            for candidate in sorted(candidates, key=lambda item: item.candidate_id)
        ],
        "config": config_payload,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return sha256(b"caudit/checkpoint/v1\x00" + encoded).hexdigest()


class CheckpointStore:
    """Read and atomically replace one continuation checkpoint."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self, identity: str) -> CheckpointState | None:
        if not self.path.exists():
            return None
        try:
            state = CheckpointState.model_validate_json(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CheckpointError(
                f"adjudication checkpoint is unreadable: {self.path}: {exc}"
            ) from exc
        if state.identity != identity:
            raise CheckpointError(
                f"adjudication checkpoint does not match this candidate/config identity: "
                f"{self.path}",
                hint="Use a new output directory for the changed experiment; the old "
                "checkpoint is preserved as evidence.",
            )
        return state

    def save(
        self,
        *,
        identity: str,
        outcomes: Sequence[_Outcome],
        account: RunAccount,
        retrieval_spent: int,
        retrieval_starved: Sequence[str],
    ) -> Path:
        state = CheckpointState(
            identity=identity,
            entries=[CheckpointEntry.from_outcome(outcome) for outcome in outcomes],
            models=account.records(),
            quota_tokens=account.quota_tokens,
            refused=list(account.refused),
            retrieval_spent=retrieval_spent,
            retrieval_starved=list(retrieval_starved),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                json.loads(state.model_dump_json()),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)
        return self.path


def restore_account(account: RunAccount, state: CheckpointState) -> None:
    """Restore cumulative reported usage while starting a fresh quota window."""

    for record in state.models:
        tier = Tier(record.tier)
        current = account.accounts[tier]
        if current.model_id != record.model_id:
            raise CheckpointError(
                f"checkpoint model {record.model_id!r} disagrees with configured "
                f"{current.model_id!r} for tier {tier}"
            )
        current.calls = record.calls
        current.cached_calls = record.cached_calls
        current.retry_count = record.retry_count
        current.unreported_usage_calls = record.unreported_usage_calls
        current.usage = Usage(
            input_tokens=record.input_tokens,
            output_tokens=record.output_tokens,
            thinking_tokens=record.thinking_tokens,
            cached_input_tokens=record.cached_input_tokens,
            tool_use_tokens=record.tool_use_tokens,
            total_tokens=record.total_tokens,
        )
    account.quota_tokens = state.quota_tokens
    account.quota_requests = 0
    account.refused = list(state.refused)
    account.reservation_stop = None

"""Immutable identity for one evaluation experiment."""

from __future__ import annotations

import platform
import sys
from collections.abc import Mapping
from enum import StrEnum
from importlib import metadata

from pydantic import BaseModel, ConfigDict, Field

from caudit.config.loader import Config
from caudit.eval.case import TruthFrame
from caudit.eval.identity import canonical_hash
from caudit.llm.capabilities import CAPABILITY_PROFILE_VERSION
from caudit.llm.prompts import load_template
from caudit.llm.schema import adjudication_response_schema, triage_response_schema
from caudit.model.adjudication import Tier
from caudit.report.manifest import config_fingerprint

__all__ = [
    "CacheMode",
    "ExperimentCondition",
    "ExperimentManifest",
    "RetryPolicy",
    "build_experiment_manifest",
]


class ExperimentCondition(StrEnum):
    """The one intended difference between otherwise identical paired runs."""

    ANALYZER_CONTROL = "analyzer_control"
    ADJUDICATED = "adjudicated"
    NAIVE_LLM_CONTROL = "naive_llm_control"
    ATTRIBUTION_A0 = "attribution_a0"
    ATTRIBUTION_A1 = "attribution_a1"
    ATTRIBUTION_A2 = "attribution_a2"
    ATTRIBUTION_A3 = "attribution_a3"
    ATTRIBUTION_A4 = "attribution_a4"
    ATTRIBUTION_A5 = "attribution_a5"
    ATTRIBUTION_A6 = "attribution_a6"
    ATTRIBUTION_A7 = "attribution_a7"


class CacheMode(StrEnum):
    """Whether the response cache was available to the run."""

    DISABLED = "disabled"
    ENABLED = "enabled"


class RetryPolicy(BaseModel):
    """Schema and transport retry settings that can change a run's outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_schema_attempts: int = Field(ge=1)
    max_transport_attempts: int = Field(ge=1)
    backoff_seconds: float = Field(ge=0.0)
    backoff_multiplier: float = Field(ge=1.0)
    backoff_jitter_seconds: float = Field(default=0.0, ge=0.0)
    request_timeout_seconds: float = Field(gt=0.0)


class ExperimentManifest(BaseModel):
    """Everything that must agree before two scores may be differenced."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    condition: ExperimentCondition
    candidate_set_hash: str = Field(min_length=64, max_length=64)
    candidate_count: int = Field(ge=0)
    corpus_hash: str = Field(min_length=64, max_length=64)
    corpus_revision: str = Field(min_length=1)
    config_hash: str = Field(min_length=64, max_length=64)
    analyzer_versions: dict[str, str] = Field(default_factory=dict)
    model_ids: dict[str, str]
    policy_versions: dict[str, str]
    sdk_versions: dict[str, str]
    prompt_hashes: dict[str, str]
    schema_hashes: dict[str, str]
    cache_mode: CacheMode
    retry_policy: RetryPolicy
    model_policy: dict[str, dict[str, object]] = Field(default_factory=dict)
    capability_profile_version: str = CAPABILITY_PROFILE_VERSION
    quota_snapshot: dict[str, object] = Field(default_factory=dict)
    runtime: dict[str, str]
    truth_frame: TruthFrame

    def comparable_values(self) -> dict[str, object]:
        """All fields except the experimental condition itself."""
        payload = self.model_dump(mode="json")
        payload.pop("condition", None)
        return payload


def build_experiment_manifest(
    *,
    config: Config,
    condition: ExperimentCondition,
    candidate_set_hash: str,
    candidate_count: int,
    corpus_hash: str,
    corpus_revision: str,
    analyzer_versions: Mapping[str, str],
    policy_versions: Mapping[str, str],
    truth_frame: TruthFrame,
    prompt_hashes: Mapping[str, str] | None = None,
    schema_hashes: Mapping[str, str] | None = None,
) -> ExperimentManifest:
    """Build a complete, content-addressed experiment record."""
    prompt_version = config.policy_versions.prompt
    effective_prompt_hashes = (
        dict(prompt_hashes)
        if prompt_hashes is not None
        else {str(tier): canonical_hash(load_template(tier, prompt_version)) for tier in Tier}
    )
    effective_schema_hashes = (
        dict(schema_hashes)
        if schema_hashes is not None
        else {
            "adjudication": canonical_hash(adjudication_response_schema()),
            "triage": canonical_hash(triage_response_schema()),
        }
    )
    llm = config.llm
    return ExperimentManifest(
        condition=condition,
        candidate_set_hash=candidate_set_hash,
        candidate_count=candidate_count,
        corpus_hash=corpus_hash,
        corpus_revision=corpus_revision,
        config_hash=config_fingerprint(config),
        analyzer_versions=dict(sorted(analyzer_versions.items())),
        model_ids={key: str(value) for key, value in sorted(config.models.model_dump().items())},
        policy_versions=dict(sorted(policy_versions.items())),
        sdk_versions=_sdk_versions(),
        prompt_hashes=dict(sorted(effective_prompt_hashes.items())),
        schema_hashes=dict(sorted(effective_schema_hashes.items())),
        cache_mode=CacheMode.ENABLED if llm.cache_enabled else CacheMode.DISABLED,
        retry_policy=RetryPolicy(
            max_schema_attempts=llm.max_attempts,
            max_transport_attempts=llm.max_transport_attempts,
            backoff_seconds=llm.backoff_seconds,
            backoff_multiplier=llm.backoff_multiplier,
            backoff_jitter_seconds=llm.backoff_jitter_seconds,
            request_timeout_seconds=llm.request_timeout_seconds,
        ),
        model_policy=dict(sorted(llm.model_policy.model_dump(mode="json").items())),
        capability_profile_version=CAPABILITY_PROFILE_VERSION,
        quota_snapshot=llm.quota_snapshot.model_dump(mode="json"),
        runtime={
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "byteorder": sys.byteorder,
        },
        truth_frame=truth_frame,
    )


def _sdk_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for distribution in ("caudit", "google-genai", "libclang", "pydantic"):
        try:
            versions[distribution] = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            versions[distribution] = "not-installed"
    return versions

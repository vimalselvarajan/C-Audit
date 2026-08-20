"""Typed configuration contracts.

Precedence, highest first: **CLI > env (``CAUDIT_*``) > config file >
packaged defaults**. Every effective value remembers which layer produced it,
so ``--print-config`` can show provenance rather than a flat dump.

Two rules make this safe rather than convenient:

* An unknown key is a :class:`~caudit.errors.ConfigError`, never a silent
  ignore. Config that looks applied but is not is worse than no config.
* Policy versions (prompt, retrieval, matching) are configuration, not
  constants, so a report can name the policy that produced it.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnalyzerConfig",
    "Config",
    "ConfigSource",
    "IndexConfig",
    "IntakeConfig",
    "LLMConfig",
    "ModelTierConfig",
    "PolicyVersions",
    "PricingConfig",
    "RetrievalConfig",
    "RetrievalVariantName",
    "TierPricing",
    "TokenBudget",
]

ENV_PREFIX: Final = "CAUDIT_"
#: Nesting separator inside an environment variable name:
#: ``CAUDIT_MODELS__TRIAGE`` sets ``models.triage``.
ENV_NEST: Final = "__"


class ConfigSource(StrEnum):
    """Which layer supplied an effective value."""

    DEFAULT = "default"
    FILE = "file"
    ENV = "env"
    CLI = "cli"


class ModelTierConfig(BaseModel):
    """Model ids live here, never in the architecture, and are recorded per run."""

    model_config = ConfigDict(extra="forbid")

    triage: str = "gemini-flash-lite-latest"
    adjudication: str = "gemini-flash-latest"
    escalation: str = "gemini-pro-latest"


class PolicyVersions(BaseModel):
    """Versions of the policies that shape a run's output."""

    model_config = ConfigDict(extra="forbid")

    #: ``2`` added the two checkable claims part 11 verifies — exact
    #: quotations and asserted call edges. The templates changed with it, and
    #: ``v1`` is kept on disk so a run pinned to it still gets the instructions
    #: it names rather than the current ones.
    prompt: str = "2"
    retrieval: str = "1"
    matching: str = "1"


class TokenBudget(BaseModel):
    """Hard ceilings. Part 09 spends against these; part 10 refuses to exceed them."""

    model_config = ConfigDict(extra="forbid")

    per_candidate: int = Field(default=24_000, gt=0)
    per_run: int = Field(default=2_000_000, gt=0)
    max_file_bytes: int = Field(default=2_000_000, gt=0)


class IntakeConfig(BaseModel):
    """Repository intake (part 05): what gets scanned, and when to refuse.

    ``coverage_floor`` is an admitted guess. It is configurable, printed in
    every stop message, and revisited against real repositories in part 13 —
    so a user who disagrees with it can say so, and a reader of a report can
    see which number the run was held to.
    """

    model_config = ConfigDict(extra="forbid")

    #: Minimum share of in-scope source files the compilation database must
    #: describe. Below this the run stops rather than reporting on a fraction
    #: of the tree while looking complete.
    coverage_floor: float = Field(default=0.60, ge=0.0, le=1.0)
    #: Turns a below-floor stop into a recorded limitation. An explicit
    #: decision by the user, never a fallback.
    allow_partial_coverage: bool = False
    #: Vendored and generated code are excluded by default; these opt back in.
    include_third_party: bool = False
    include_generated: bool = False
    #: Restrict the scan to these repository-relative paths. Empty means every
    #: translation unit the database describes.
    targets: list[str] = Field(default_factory=list)
    #: Recursion cap for ``@response`` file expansion.
    response_file_depth: int = Field(default=8, ge=1, le=64)


class IndexConfig(BaseModel):
    """Clang indexing (part 06): how TUs are parsed, and what is never inferred.

    ``resource_dir`` is the one escape hatch, and it is deliberately manual.
    The ``libclang`` wheel ships the shared library without Clang's builtin
    headers, so a TU that includes ``<stddef.h>`` fails to parse. C Audit will
    not go looking for a resource directory on its own — that would be
    guessing an include path — so the parse failure names the fix and the user
    supplies the path.
    """

    model_config = ConfigDict(extra="forbid")

    #: Worker processes. ``0`` means one per CPU, capped, and never more than
    #: there are translation units to parse.
    jobs: int = Field(default=0, ge=0, le=64)
    #: Wall-clock ceiling for one translation unit. Exceeding it is a recorded
    #: limitation naming the file, never a silent skip.
    per_tu_timeout_seconds: float = Field(default=120.0, gt=0.0)
    #: Parse in this process instead of workers. Faster for one TU and easier
    #: to debug, but nothing can interrupt a runaway parse, so the per-TU
    #: timeout does not apply.
    in_process: bool = False
    #: Clang's builtin header directory, as printed by
    #: ``clang -print-resource-dir``. Never discovered automatically.
    resource_dir: str | None = None
    #: Where parsed translation units are cached between runs. ``None`` uses
    #: the run's output directory.
    cache_dir: str | None = None


class AnalyzerConfig(BaseModel):
    """Candidate generation (part 07): which analyzers run, and how patiently.

    The binaries are named here rather than discovered, for the same reason
    include paths are not guessed: a run that silently picked up whichever
    ``clang`` was first on ``PATH`` is not reproducible, and the manifest has
    to record what actually ran.
    """

    model_config = ConfigDict(extra="forbid")

    #: The curated check profile: a packaged name, or a path to a YAML file.
    profile: str = "security"
    #: Worker threads. ``0`` means one per CPU, never more than there is work.
    jobs: int = Field(default=0, ge=0, le=64)
    #: Wall-clock ceiling for one analyzer on one translation unit. Exceeding
    #: it is a recorded limitation naming both, never a silent skip.
    per_unit_timeout_seconds: float = Field(default=300.0, gt=0.0)
    enable_diagnostics: bool = True
    enable_csa: bool = True
    enable_tidy: bool = True
    clang: str = "clang"
    clang_tidy: str = "clang-tidy"
    #: Where raw analyzer output is retained for provenance. ``None`` puts it
    #: under the run's output directory.
    raw_output_dir: str | None = None


#: The retrieval variants, spelled as a ``Literal`` so a bad value fails at
#: configuration load rather than half way through a scan.
#:
#: The enum this mirrors is
#: :class:`~caudit.retrieval.policy.RetrievalVariant`, and it lives there
#: because that is where the variants are implemented. It cannot be imported
#: here: ``retrieval.policy`` reads :class:`Config`, so the dependency only
#: runs one way. T-09-20 asserts the two spellings agree, which is the price of
#: the duplication and is cheaper than the import cycle.
RetrievalVariantName = Literal["structural", "structural_plus_semantic", "flat_window"]


class RetrievalConfig(BaseModel):
    """Evidence expansion (part 09): how far out, and by what method.

    These were policy defaults with no way to set them until part 13's
    ablation grid needed to vary caller depth and retrieval variant on a real
    run. An experiment that cannot set the factor it varies measures nothing,
    so the knobs are configuration now — and, being configuration, they are
    layered, printable, and recorded like everything else.
    """

    model_config = ConfigDict(extra="forbid")

    #: ``structural`` is compiler-aware retrieval and the only variant a scan
    #: should normally use. ``flat_window`` is part 13's control: a line window
    #: with no index consulted, which may cut a function in half and says so in
    #: the context's limitations. ``structural_plus_semantic`` is refused —
    #: named, so a grid can ask for it and be told it does not exist.
    variant: RetrievalVariantName = "structural"
    caller_depth: int = Field(default=2, ge=0, le=8)
    callee_depth: int = Field(default=1, ge=0, le=8)
    include_cleanup_paths: bool = True
    include_global_decls: bool = True
    max_units: int = Field(default=64, ge=1, le=4096)
    type_closure_depth: int = Field(default=2, ge=1, le=16)
    #: Lines either side of the diagnostic, under ``flat_window`` only.
    flat_window_lines: int = Field(default=40, ge=1, le=2000)


class TierPricing(BaseModel):
    """What one tier's model costs, per million tokens.

    Zero by default, and deliberately so: a published price belongs to a
    vendor's catalogue, not to this repository, and a stale number baked into
    the source would produce a confident cost report that is wrong. A tier
    left at zero contributes nothing to the cost ceiling, and the run says so
    rather than pretending the calls were free.
    """

    model_config = ConfigDict(extra="forbid")

    input_per_million_usd: float = Field(default=0.0, ge=0.0)
    output_per_million_usd: float = Field(default=0.0, ge=0.0)


class PricingConfig(BaseModel):
    """Prices per tier, mirroring :class:`ModelTierConfig`."""

    model_config = ConfigDict(extra="forbid")

    triage: TierPricing = Field(default_factory=TierPricing)
    adjudication: TierPricing = Field(default_factory=TierPricing)
    escalation: TierPricing = Field(default_factory=TierPricing)


class LLMConfig(BaseModel):
    """Adjudication (part 10): how a model is called, and how it is refused.

    Nothing here enables the network on its own. ``cloud_consent`` is the only
    switch that does, it lives on :class:`Config` beside the exclusion globs it
    belongs with, and every value below applies equally to a run that was
    consented to and one that was not.
    """

    model_config = ConfigDict(extra="forbid")

    #: Attempts at a schema-valid response, including the first. The validation
    #: error is fed back between attempts; after the last one the candidate
    #: becomes review-required rather than being parsed out of prose.
    max_attempts: int = Field(default=3, ge=1, le=10)
    #: Attempts at reaching the provider at all — rate limits, timeouts, and
    #: transport failures. Counted separately from schema retries because a
    #: 429 says nothing about the response and a bad response says nothing
    #: about the connection.
    max_transport_attempts: int = Field(default=3, ge=1, le=10)
    backoff_seconds: float = Field(default=1.0, ge=0.0, le=60.0)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    request_timeout_seconds: float = Field(default=120.0, gt=0.0)
    #: Run the cheap tier first to discard obvious non-issues. Disabling it
    #: sends every candidate straight to adjudication, which costs more.
    triage_enabled: bool = True
    #: Allow the escalation tier at all. When false an ambiguous high-impact
    #: candidate stays with the adjudication tier's answer instead.
    allow_escalation: bool = True
    #: Responses are cached on the content of the request, so a repeated run
    #: over an unchanged revision costs nothing and replays exactly.
    cache_enabled: bool = True
    #: Where cached responses live. ``None`` puts them under the run's output
    #: directory.
    cache_dir: str | None = None
    #: Persist assembled prompts and raw responses alongside the parsed result.
    #: Off by default — the spec's posture is that source and prompts are not
    #: retained — and recorded in the manifest when it is on.
    retain_raw: bool = False
    #: Stop calling once reported usage has cost this much. ``None`` means no
    #: cost ceiling is configured, in which case ``token_budget.per_run``
    #: bounds the run on its own.
    max_run_cost_usd: float | None = Field(default=None, ge=0.0)
    pricing: PricingConfig = Field(default_factory=PricingConfig)


class Config(BaseModel):
    """The effective configuration for one run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    llvm_version: str = "18"
    models: ModelTierConfig = Field(default_factory=ModelTierConfig)
    policy_versions: PolicyVersions = Field(default_factory=PolicyVersions)
    exclude_globs: list[str] = Field(
        default_factory=lambda: [
            "third_party/**",
            "3rdparty/**",
            "external/**",
            "vendor/**",
            "**/node_modules/**",
            "build/**",
            "**/*.pb.cc",
            "**/*.pb.h",
            "**/generated/**",
        ]
    )
    token_budget: TokenBudget = Field(default_factory=TokenBudget)
    intake: IntakeConfig = Field(default_factory=IntakeConfig)
    index: IndexConfig = Field(default_factory=IndexConfig)
    retrieval: RetrievalConfig = Field(default_factory=RetrievalConfig)
    analyzers: AnalyzerConfig = Field(default_factory=AnalyzerConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    #: Sending source regions to a hosted model requires an explicit opt-in.
    cloud_consent: bool = False

    @property
    def llvm_major(self) -> int:
        return int(self.llvm_version.split(".", 1)[0])

"""LLM adjudication (part 10).

:func:`adjudicate` asks a model to do the one thing it is better at than the
analyzers: connect dispersed evidence into an explanation, decide whether a
candidate is real, and say what would fix it. Everything around that call
exists to make sure it can only speak in typed, schema-valid claims that cite
evidence it was actually given.

The order is the safety argument, and it is not an implementation detail:

1. **consent**, or nothing leaves the process at all;
2. **retrieval's answer is respected** — a candidate part 09 could not fit
   inside its budget is never asked about on a fragment;
3. **assembly**, where exclusion is enforced and secrets are scrubbed;
4. **the call**, retried only for the failures a retry can fix;
5. **validation**, which is ``model_validate_json`` and nothing else, so prose
   never becomes a finding;
6. **the citation check**, cheap here and authoritative in part 11.

Nothing here decides anything. Every path out of this module produces either a
proposal for part 11 to verify or a reason the candidate needs review, and the
two are never merged.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from caudit.config.loader import Config
from caudit.llm.accounting import RunAccount, StopReason, TierAccount
from caudit.llm.attempts import (
    AdjudicationOutcome,
    Attempt,
    AttemptOutcome,
    request_adjudication,
    request_triage,
)
from caudit.llm.cache import CacheEntry, ResponseCache, cache_key
from caudit.llm.cassette import Cassette, CassetteProvider
from caudit.llm.consent import (
    ConsentDecision,
    ConsentError,
    ConsentSource,
    consent_state,
    record_consent,
    require_consent,
)
from caudit.llm.prompts import AssembledPrompt, assemble, prompt_paths
from caudit.llm.provider import (
    LLMProvider,
    ProviderError,
    ProviderRefusedError,
    ProviderRequest,
    ProviderTokenizer,
    ProviderUnavailableError,
)
from caudit.llm.redaction import PrivacyError, RedactionReport
from caudit.llm.routing import RoutingPolicy, escalation_input, route
from caudit.llm.schema import adjudication_response_schema, triage_response_schema
from caudit.model.adjudication import (
    Adjudication,
    ProviderResponse,
    Tier,
    TriageDisposition,
    TriageResult,
    Usage,
    Verdict,
)
from caudit.model.finding import (
    Impact,
    ImpactKind,
    Limitation,
    LimitationKind,
    ReviewReason,
    Severity,
)
from caudit.retrieval.context import EvidenceContext

__all__ = [
    "Adjudication",
    "AdjudicationOutcome",
    "AssembledPrompt",
    "Attempt",
    "AttemptOutcome",
    "CacheEntry",
    "Cassette",
    "CassetteProvider",
    "ConsentDecision",
    "ConsentError",
    "ConsentSource",
    "DryRunReport",
    "LLMProvider",
    "PrivacyError",
    "ProviderError",
    "ProviderRefusedError",
    "ProviderRequest",
    "ProviderResponse",
    "ProviderTokenizer",
    "ProviderUnavailableError",
    "RedactionReport",
    "ResponseCache",
    "RoutingPolicy",
    "RunAccount",
    "StopReason",
    "Tier",
    "TierAccount",
    "TriageDisposition",
    "TriageResult",
    "Usage",
    "Verdict",
    "adjudicate",
    "adjudication_response_schema",
    "cache_key",
    "consent_state",
    "dry_run_prompts",
    "record_consent",
    "require_consent",
    "response_cache",
    "route",
    "triage_response_schema",
]

#: What the triage tier is assumed to have said when it could not be asked or
#: would not answer. Deliberately the cautious-but-cheap corner of the routing
#: table: the candidate still goes to the adjudication tier, and the expensive
#: tier is not spent on an impact estimate nobody made.
_UNTRIAGED_IMPACT = Impact(
    kind=ImpactKind.UNDEFINED_BEHAVIOR,
    severity=Severity.MEDIUM,
    description="The triage tier did not answer, so impact was not assessed.",
    evidence_supports="Nothing: this is the absence of a triage result, not a finding.",
)


def response_cache(config: Config, out_dir: Path | None = None) -> ResponseCache:
    """The cache for one run, honouring ``llm.cache_enabled`` and ``llm.cache_dir``."""
    configured = config.llm.cache_dir
    directory = Path(configured) if configured else (out_dir / "llm-cache" if out_dir else None)
    return ResponseCache(
        directory,
        enabled=config.llm.cache_enabled,
        retain_raw=config.llm.retain_raw,
    )


def adjudicate(
    context: EvidenceContext,
    *,
    config: Config,
    provider: LLMProvider,
    consent: ConsentDecision,
    account: RunAccount | None = None,
    cache: ResponseCache | None = None,
    triage: TriageResult | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> AdjudicationOutcome:
    """Ask a model about one candidate, under every constraint the spec names.

    Returns an outcome in every case. A refusal — no consent, no context, no
    budget, no valid answer — is an outcome carrying a
    :class:`~caudit.model.finding.ReviewReason`, never an exception and never a
    silently dropped candidate.
    """
    require_consent(consent)
    ledger = account if account is not None else RunAccount(config=config)
    tier = Tier.ADJUDICATION

    if not context.is_adjudicable:
        return _refused(
            context,
            ledger,
            tier,
            reason=context.review_reason or ReviewReason.CONTEXT_BUDGET_EXCEEDED,
            limitation=_no_context_limitation(context),
        )

    stopped = ledger.stop_reason()
    if stopped is not None:
        return _refused(
            context,
            ledger,
            tier,
            reason=ReviewReason.RUN_BUDGET_EXHAUSTED,
            limitation=ledger.refuse(context.candidate.candidate_id, stopped),
        )

    prompt_version = config.policy_versions.prompt
    schema = adjudication_response_schema()
    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version=prompt_version,
        exclude_globs=config.exclude_globs,
        tokenizer=ProviderTokenizer(provider),
        response_fields=_required_fields(schema),
    )

    ceiling = config.token_budget.per_candidate
    if prompt.token_estimate > ceiling:
        return _refused(
            context,
            ledger,
            tier,
            reason=ReviewReason.CONTEXT_BUDGET_EXCEEDED,
            limitation=_oversize_limitation(context, prompt, ceiling),
            prompt=prompt,
        )

    attempts: list[Attempt] = []
    decided = triage
    if decided is None and config.llm.triage_enabled:
        decided, triage_attempts = _run_triage(
            context,
            provider=provider,
            config=config,
            account=ledger,
            cache=cache,
            sleeper=sleeper,
            prompt_version=prompt_version,
        )
        attempts.extend(triage_attempts)
    if decided is None:
        decided = TriageResult(
            disposition=TriageDisposition.ADJUDICATE,
            ambiguous=True,
            impact=_UNTRIAGED_IMPACT,
            rationale="the triage tier did not produce a usable answer",
        )

    tier = route(
        context.candidate,
        context,
        decided,
        policy=RoutingPolicy.from_config(config.llm),
    )
    if tier is Tier.TRIAGE:
        # The cheap tier said this is not worth the expensive one. It does not
        # get to remove the candidate from the report: it only decides which
        # tier answers, and the analyzer's own claim stands untouched.
        return _refused(
            context,
            ledger,
            tier,
            reason=ReviewReason.ANALYZER_ONLY,
            limitation=_dismissed_limitation(context, decided),
            prompt=prompt,
            attempts=attempts,
        )

    if tier is Tier.ESCALATION:
        prompt = _reassemble(context, config, provider, Tier.ESCALATION, prompt_version, schema)

    outcome = request_adjudication(
        provider,
        prompt,
        tier=tier,
        config=config.llm,
        account=ledger,
        response_schema=schema,
        schema_version=_schema_version(),
        cache=cache,
        sleeper=sleeper,
        limitations=list(context.limitations),
    )
    outcome = _prepend(outcome, attempts)

    if outcome.adjudication is None or tier is Tier.ESCALATION:
        return outcome
    return _maybe_escalate(
        outcome,
        context,
        config=config,
        provider=provider,
        account=ledger,
        cache=cache,
        sleeper=sleeper,
        prompt_version=prompt_version,
        schema=schema,
    )


# ------------------------------------------------------------------- staging


def _run_triage(
    context: EvidenceContext,
    *,
    provider: LLMProvider,
    config: Config,
    account: RunAccount,
    cache: ResponseCache | None,
    sleeper: Callable[[float], None],
    prompt_version: str,
) -> tuple[TriageResult | None, list[Attempt]]:
    schema = triage_response_schema()
    prompt = assemble(
        context,
        tier=Tier.TRIAGE,
        prompt_version=prompt_version,
        exclude_globs=config.exclude_globs,
        tokenizer=ProviderTokenizer(provider),
        response_fields=_required_fields(schema),
    )
    return request_triage(
        provider,
        prompt,
        config=config.llm,
        account=account,
        response_schema=schema,
        schema_version=_schema_version(),
        cache=cache,
        sleeper=sleeper,
    )


def _maybe_escalate(
    outcome: AdjudicationOutcome,
    context: EvidenceContext,
    *,
    config: Config,
    provider: LLMProvider,
    account: RunAccount,
    cache: ResponseCache | None,
    sleeper: Callable[[float], None],
    prompt_version: str,
    schema: dict[str, object],
) -> AdjudicationOutcome:
    """Ask the stronger tier when the same routing table says to.

    The adjudication tier's own verdict and impact go back through
    :func:`~caudit.llm.routing.route`, so escalation is decided by the table
    that chose the first tier rather than by a second rule beside it.
    """
    proposal = outcome.adjudication
    if proposal is None:  # pragma: no cover - guarded by the caller
        return outcome
    tier = route(
        context.candidate,
        context,
        escalation_input(proposal),
        policy=RoutingPolicy.from_config(config.llm),
    )
    if tier is not Tier.ESCALATION:
        return outcome
    if account.stop_reason() is not None:
        return outcome

    prompt = _reassemble(context, config, provider, Tier.ESCALATION, prompt_version, schema)
    escalated = request_adjudication(
        provider,
        prompt,
        tier=Tier.ESCALATION,
        config=config.llm,
        account=account,
        response_schema=schema,
        schema_version=_schema_version(),
        cache=cache,
        sleeper=sleeper,
        limitations=list(context.limitations),
    )
    if escalated.adjudication is None:
        # The stronger tier could not answer. The first answer stands, and the
        # failed escalation is recorded rather than discarded — a run that
        # tried twice is a different run from one that tried once.
        return _prepend(outcome, [], tail=escalated.attempts)
    return _prepend(escalated, outcome.attempts)


def _reassemble(
    context: EvidenceContext,
    config: Config,
    provider: LLMProvider,
    tier: Tier,
    prompt_version: str,
    schema: dict[str, object],
) -> AssembledPrompt:
    return assemble(
        context,
        tier=tier,
        prompt_version=prompt_version,
        exclude_globs=config.exclude_globs,
        tokenizer=ProviderTokenizer(provider),
        response_fields=_required_fields(schema),
    )


# ------------------------------------------------------------------- refusals


def _refused(
    context: EvidenceContext,
    account: RunAccount,
    tier: Tier,
    *,
    reason: ReviewReason,
    limitation: Limitation,
    prompt: AssembledPrompt | None = None,
    attempts: Sequence[Attempt] = (),
) -> AdjudicationOutcome:
    """An outcome with no proposal, and the reason there is none."""
    return AdjudicationOutcome(
        candidate_id=context.candidate.candidate_id,
        tier=tier,
        model_id=account.model_id(tier),
        review_reason=reason,
        attempts=list(attempts),
        prompt_fingerprint=prompt.fingerprint if prompt else "",
        redactions=prompt.redactions if prompt else RedactionReport(),
        limitations=[
            *(prompt.limitations if prompt else []),
            *context.limitations,
            limitation,
        ],
    )


def _prepend(
    outcome: AdjudicationOutcome,
    head: Sequence[Attempt],
    tail: Sequence[Attempt] = (),
) -> AdjudicationOutcome:
    if not head and not tail:
        return outcome
    return outcome.model_copy(update={"attempts": [*head, *outcome.attempts, *tail]})


def _no_context_limitation(context: EvidenceContext) -> Limitation:
    return Limitation(
        kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
        detail=(
            "no model was asked about this candidate because retrieval could not "
            f"assemble a context for it ({context.describe()}). Sending a fragment "
            "would produce a confident answer to a different question"
        ),
        affects=str(context.candidate.region.path),
    )


def _oversize_limitation(
    context: EvidenceContext, prompt: AssembledPrompt, ceiling: int
) -> Limitation:
    return Limitation(
        kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
        detail=(
            f"the assembled request is {prompt.token_estimate} tokens against a "
            f"per-candidate budget of {ceiling}. Nothing was sent: the instructions and "
            "the response schema are counted against the same budget as the code, and "
            "trimming the code to make room is the one thing that is never done"
        ),
        affects=str(context.candidate.region.path),
    )


def _dismissed_limitation(context: EvidenceContext, triage: TriageResult) -> Limitation:
    return Limitation(
        kind=LimitationKind.NO_EVIDENCE_EXPANSION,
        detail=(
            "the triage tier judged this candidate not worth full adjudication: "
            f"{triage.rationale}. It remains in the report on the analyzer's word "
            "alone; triage decides which tier answers, never what is reported"
        ),
        affects=str(context.candidate.region.path),
    )


def _required_fields(schema: dict[str, object]) -> list[str]:
    """The response schema's required field names, for the prompt text."""
    required = schema.get("required")
    return [str(name) for name in required] if isinstance(required, list) else []


def _schema_version() -> str:
    from caudit.model.finding import SCHEMA_VERSION

    return SCHEMA_VERSION


# -------------------------------------------------------------------- dry run


@dataclass
class DryRunReport:
    """What ``--dry-run-prompts`` wrote, and what it would have sent."""

    directory: Path
    written: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    redactions: RedactionReport = field(default_factory=RedactionReport)
    total_tokens: int = 0
    limitations: list[Limitation] = field(default_factory=list)

    def describe(self) -> str:
        return (
            f"{len(self.written)} prompt(s) written to {self.directory}, "
            f"{self.total_tokens} tokens, {self.redactions.describe()}; "
            f"{len(self.skipped)} candidate(s) had no context"
        )


def dry_run_prompts(
    contexts: Iterable[EvidenceContext],
    *,
    config: Config,
    out_dir: Path,
    tiers: Sequence[Tier] = (Tier.TRIAGE, Tier.ADJUDICATION),
) -> DryRunReport:
    """Assemble every prompt and write it to disk. Sends nothing.

    This is how a user audits what *would* be transmitted before allowing it,
    so it runs the real assembly path — the same exclusion filtering, the same
    scrubbing, the same second check — and touches no provider at all. It does
    not need consent, because consent is about transmission and nothing here
    transmits.
    """
    report = DryRunReport(directory=out_dir)
    schemas = {
        Tier.TRIAGE: triage_response_schema(),
        Tier.ESCALATION: adjudication_response_schema(),
        Tier.ADJUDICATION: adjudication_response_schema(),
    }
    for context in contexts:
        if not context.is_adjudicable:
            report.skipped.append(context.candidate.candidate_id)
            report.limitations.append(_no_context_limitation(context))
            continue
        for tier in tiers:
            schema = schemas[tier]
            prompt = assemble(
                context,
                tier=tier,
                prompt_version=config.policy_versions.prompt,
                exclude_globs=config.exclude_globs,
                response_fields=_required_fields(schema),
            )
            path = prompt_paths(out_dir, context.candidate.candidate_id, tier)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(prompt.text, encoding="utf-8", newline="\n")
            report.written.append(path)
            report.redactions = report.redactions.merged_with(prompt.redactions)
            report.total_tokens += prompt.token_estimate
            report.limitations.extend(prompt.limitations)
    return report

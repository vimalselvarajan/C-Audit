"""Token and cost accounting, and the ceilings that stop a run.

Every number here comes from what the provider *reported*, never from a local
estimate. That is the whole point: an estimate bounds a quantity nobody bills,
so a run held to one can still produce a surprising invoice. Part 09's
:class:`~caudit.retrieval.budget.RunLedger` estimates what would be sent and
uses that to decide what to retrieve; this counts what was sent and uses that
to decide whether to keep going.

The two share the configured ``token_budget.per_run`` ceiling and keep separate
counters, deliberately. They measure different quantities — retrieved context
against billed tokens, the second of which includes output and scaffolding the
first never saw — and charging both to one counter would make the ceiling bind
at roughly half the number the user set.

Hitting a ceiling stops further calls. It never shrinks a context to fit one
more candidate in: squeezing more questions through by giving each one less
code is how a run ends up with many confident answers built on partial
functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from caudit.config.loader import Config, TierPricing
from caudit.model.adjudication import Tier, Usage
from caudit.model.finding import Limitation, LimitationKind
from caudit.model.manifest import ModelRecord

__all__ = ["RunAccount", "StopReason", "TierAccount"]

_PER_MILLION = 1_000_000


@dataclass
class TierAccount:
    """One tier's usage. ``calls`` counts requests that reached the provider."""

    tier: Tier
    model_id: str
    calls: int = 0
    #: Requests answered from the cache. Counted apart from ``calls`` because
    #: they cost nothing and reached no network.
    cached_calls: int = 0
    usage: Usage = field(default_factory=Usage)

    def cost_usd(self, pricing: TierPricing) -> float:
        return (
            self.usage.input_tokens * pricing.input_per_million_usd
            + self.usage.output_tokens * pricing.output_per_million_usd
        ) / _PER_MILLION

    def as_record(self) -> ModelRecord:
        return ModelRecord(
            tier=str(self.tier),
            model_id=self.model_id,
            calls=self.calls,
            input_tokens=self.usage.input_tokens,
            output_tokens=self.usage.output_tokens,
        )


@dataclass(frozen=True)
class StopReason:
    """Why no further call will be made."""

    kind: str
    detail: str


@dataclass
class RunAccount:
    """Cumulative provider usage for one run, and the ceilings on it."""

    config: Config
    accounts: dict[Tier, TierAccount] = field(default_factory=dict)
    #: Candidate ids that were never asked about because a ceiling had bound.
    refused: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.accounts:
            return
        models = self.config.models
        self.accounts = {
            Tier.TRIAGE: TierAccount(tier=Tier.TRIAGE, model_id=models.triage),
            Tier.ADJUDICATION: TierAccount(tier=Tier.ADJUDICATION, model_id=models.adjudication),
            Tier.ESCALATION: TierAccount(tier=Tier.ESCALATION, model_id=models.escalation),
        }

    # ------------------------------------------------------------- recording

    def model_id(self, tier: Tier) -> str:
        """The configured id for a tier. Never a literal in this package."""
        return self.accounts[tier].model_id

    def charge(self, tier: Tier, usage: Usage, *, cached: bool = False) -> None:
        """Record one answer. A cached answer costs nothing and is counted apart."""
        account = self.accounts[tier]
        if cached:
            account.cached_calls += 1
            return
        account.calls += 1
        account.usage = account.usage + usage

    def refuse(self, candidate_id: str, reason: StopReason) -> Limitation:
        """Record a candidate the ceiling would not pay for."""
        self.refused.append(candidate_id)
        return Limitation(
            kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
            detail=(
                f"no model was asked about this candidate: {reason.detail}. Nothing in "
                "this report is a statement about it"
            ),
            affects=candidate_id,
        )

    # -------------------------------------------------------------- ceilings

    @property
    def total_tokens(self) -> int:
        return sum(
            account.usage.input_tokens + account.usage.output_tokens
            for account in self.accounts.values()
        )

    @property
    def calls(self) -> int:
        return sum(account.calls for account in self.accounts.values())

    def cost_usd(self) -> float:
        """Total spend from reported usage and the configured price table."""
        pricing = self.config.llm.pricing
        return sum(
            account.cost_usd(getattr(pricing, str(account.tier)))
            for account in self.accounts.values()
        )

    @property
    def priced(self) -> bool:
        """Whether any tier has a non-zero price configured."""
        pricing = self.config.llm.pricing
        return any(
            tier.input_per_million_usd or tier.output_per_million_usd
            for tier in (pricing.triage, pricing.adjudication, pricing.escalation)
        )

    def stop_reason(self) -> StopReason | None:
        """The ceiling that has bound, or ``None`` while the run may continue."""
        ceiling = self.config.llm.max_run_cost_usd
        if ceiling is not None:
            spent = self.cost_usd()
            if spent >= ceiling:
                return StopReason(
                    kind="cost_ceiling",
                    detail=(
                        f"the run's cost ceiling of ${ceiling:.4f} was reached "
                        f"(${spent:.4f} of reported usage across {self.calls} call(s))"
                    ),
                )
        budget = self.config.token_budget.per_run
        if self.total_tokens >= budget:
            return StopReason(
                kind="token_ceiling",
                detail=(
                    f"the run's {budget}-token ceiling was reached "
                    f"({self.total_tokens} reported across {self.calls} call(s))"
                ),
            )
        return None

    @property
    def exhausted(self) -> bool:
        return self.stop_reason() is not None

    # --------------------------------------------------------------- reading

    def records(self) -> list[ModelRecord]:
        """One :class:`ModelRecord` per tier, for the run manifest.

        Every configured tier is recorded, including the ones that were never
        called: ``calls=0`` says a model was configured and not consulted,
        which is a fact about the run, where an absent row says nothing.
        """
        return [self.accounts[tier].as_record() for tier in Tier]

    def limitations(self) -> list[Limitation]:
        """What the ceilings cost this run, if anything."""
        limitations: list[Limitation] = []
        ceiling = self.config.llm.max_run_cost_usd
        if ceiling is not None and not self.priced:
            limitations.append(
                Limitation(
                    kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
                    detail=(
                        f"a cost ceiling of ${ceiling:.4f} is configured but every tier's "
                        "price is zero, so the ceiling cannot bind and only the token "
                        "budget limited this run. Set llm.pricing.<tier>.* to enforce it"
                    ),
                    affects=None,
                )
            )
        reason = self.stop_reason()
        if reason is not None:
            limitations.append(
                Limitation(
                    kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
                    detail=(
                        f"adjudication stopped early: {reason.detail}. "
                        f"{len(self.refused)} candidate(s) were never sent"
                    ),
                    affects=None,
                )
            )
        return limitations

    def describe(self) -> str:
        return f"{self.calls} call(s), {self.total_tokens} reported tokens, ${self.cost_usd():.4f}"

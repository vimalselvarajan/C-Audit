# ruff: noqa: E501, UP031
from __future__ import annotations

from dataclasses import dataclass, field

from caudit.config.loader import Config, TierPricing
from caudit.model.adjudication import Tier, Usage
from caudit.model.finding import Limitation, LimitationKind
from caudit.model.manifest import ModelRecord

__all__ = ["QuotaReservation", "RunAccount", "StopReason", "TierAccount"]
_PER_MILLION = 1_000_000


@dataclass
class TierAccount:
    tier: Tier
    model_id: str
    calls: int = 0
    cached_calls: int = 0
    retry_count: int = 0
    unreported_usage_calls: int = 0
    usage: Usage = field(default_factory=Usage)

    def cost_usd(self, pricing: TierPricing) -> float:
        u = self.usage
        return (
            u.input_tokens * pricing.input_per_million_usd
            + u.output_tokens * pricing.output_per_million_usd
            + u.thinking_tokens * pricing.thinking_per_million_usd
            + u.cached_input_tokens * pricing.cached_input_per_million_usd
            + u.tool_use_tokens * pricing.tool_use_per_million_usd
        ) / _PER_MILLION

    def as_record(self) -> ModelRecord:
        u = self.usage
        return ModelRecord(
            tier=str(self.tier),
            model_id=self.model_id,
            calls=self.calls,
            cached_calls=self.cached_calls,
            retry_count=self.retry_count,
            unreported_usage_calls=self.unreported_usage_calls,
            input_tokens=u.input_tokens,
            output_tokens=u.output_tokens,
            thinking_tokens=u.thinking_tokens,
            cached_input_tokens=u.cached_input_tokens,
            tool_use_tokens=u.tool_use_tokens,
            total_tokens=u.total_tokens,
        )


@dataclass(frozen=True)
class StopReason:
    kind: str
    detail: str


@dataclass(frozen=True)
class QuotaReservation:
    tier: Tier
    tokens: int


@dataclass
class RunAccount:
    config: Config
    accounts: dict[Tier, TierAccount] = field(default_factory=dict)
    refused: list[str] = field(default_factory=list)
    quota_tokens: int = 0
    quota_requests: int = 0
    reservation_stop: StopReason | None = None

    def __post_init__(self) -> None:
        if not self.accounts:
            m = self.config.models
            self.accounts = {
                Tier.TRIAGE: TierAccount(Tier.TRIAGE, m.triage),
                Tier.ADJUDICATION: TierAccount(Tier.ADJUDICATION, m.adjudication),
                Tier.ESCALATION: TierAccount(Tier.ESCALATION, m.escalation),
            }

    def model_id(self, tier: Tier) -> str:
        return self.accounts[tier].model_id

    def reserve(self, tier: Tier, tokens: int) -> QuotaReservation | None:
        tokens = max(0, tokens)
        q = self.config.llm.quota_snapshot
        r = _limit(q.requests_per_minute, q.requests_per_day)
        t = _limit(q.tokens_per_minute, q.tokens_per_day)
        if r is not None and self.quota_requests >= r:
            self.reservation_stop = StopReason("quota_requests", "provider request quota reached")
            return None
        if t is not None and self.quota_tokens + tokens > t:
            self.reservation_stop = StopReason("quota_tokens", "provider token quota reached")
            return None
        self.quota_requests += 1
        self.quota_tokens += tokens
        self.reservation_stop = None
        return QuotaReservation(tier, tokens)

    def charge(
        self,
        tier: Tier,
        usage: Usage,
        *,
        cached: bool = False,
        reservation: QuotaReservation | None = None,
    ) -> None:
        a = self.accounts[tier]
        if cached:
            a.cached_calls += 1
            return
        a.calls += 1
        a.usage = a.usage + usage
        if usage.total_tokens == 0:
            a.unreported_usage_calls += 1
        self.quota_tokens = (
            self.quota_tokens + usage.total_tokens
            if reservation is None
            else max(0, self.quota_tokens - reservation.tokens) + usage.total_tokens
        )

    def record_retry(self, tier: Tier) -> None:
        self.accounts[tier].retry_count += 1

    @property
    def retries(self) -> int:
        return sum(a.retry_count for a in self.accounts.values())

    def refuse(self, candidate_id: str, reason: StopReason) -> Limitation:
        self.refused.append(candidate_id)
        return Limitation(
            kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
            detail="no model was asked: " + reason.detail,
            affects=candidate_id,
        )

    @property
    def total_tokens(self) -> int:
        return sum(a.usage.total_tokens for a in self.accounts.values())

    @property
    def calls(self) -> int:
        return sum(a.calls for a in self.accounts.values())

    def cost_usd(self) -> float:
        p = self.config.llm.pricing
        return sum(a.cost_usd(getattr(p, str(a.tier))) for a in self.accounts.values())

    @property
    def priced(self) -> bool:
        return any(
            v for tier in self.config.llm.pricing.model_dump().values() for v in tier.values()
        )

    def stop_reason(self) -> StopReason | None:
        if self.reservation_stop is not None:
            return self.reservation_stop
        if (
            self.config.llm.max_run_cost_usd is not None
            and self.cost_usd() >= self.config.llm.max_run_cost_usd
        ):
            return StopReason(
                "cost_ceiling",
                "the run cost ceiling of $%.4f was reached ($%.4f of reported usage)"
                % (self.config.llm.max_run_cost_usd, self.cost_usd()),
            )
        if self.total_tokens >= self.config.token_budget.per_run:
            return StopReason("token_ceiling", "token ceiling reached")
        return None

    @property
    def exhausted(self) -> bool:
        return self.stop_reason() is not None

    def records(self) -> list[ModelRecord]:
        return [self.accounts[t].as_record() for t in Tier]

    def limitations(self) -> list[Limitation]:
        items: list[Limitation] = []
        if self.config.llm.max_run_cost_usd is not None and not self.priced:
            items.append(
                Limitation(
                    kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
                    detail="a cost ceiling is configured but every llm.pricing tier is zero, so it cannot bind",
                    affects=None,
                )
            )
        reason = self.stop_reason()
        if reason is not None:
            items.append(
                Limitation(
                    kind=LimitationKind.TOKEN_BUDGET_EXHAUSTED,
                    detail="adjudication stopped early: " + reason.detail,
                    affects=None,
                )
            )
        return items

    def describe(self) -> str:
        return (
            f"{self.calls} call(s), {self.total_tokens} reported tokens, USD {self.cost_usd():.4f}"
        )


def _limit(*values: int | None) -> int | None:
    known = [v for v in values if v is not None]
    return min(known) if known else None

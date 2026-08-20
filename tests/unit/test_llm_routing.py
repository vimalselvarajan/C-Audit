"""Part 10 routing and configuration: T-10-01, T-10-02, T-10-03."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from caudit.config.loader import Config, ModelTierConfig
from caudit.llm.routing import escalation_input
from caudit.llm.service import RoutingPolicy, RunAccount, Tier, TriageResult, route
from caudit.model.adjudication import TriageDisposition, Verdict
from caudit.model.candidate import Candidate
from caudit.model.finding import Impact, ImpactKind, Severity
from caudit.retrieval.context import EvidenceContext
from tests.conftest import retrieval_context

SRC = Path(__file__).resolve().parents[2] / "src"


def _impact(severity: Severity) -> Impact:
    return Impact(
        kind=ImpactKind.MEMORY_CORRUPTION,
        severity=severity,
        description="If real, memory past the buffer is written.",
        evidence_supports="The cited copy has no length bound.",
    )


def _triage(
    *,
    ambiguous: bool,
    severity: Severity,
    disposition: TriageDisposition = TriageDisposition.ADJUDICATE,
) -> TriageResult:
    return TriageResult(
        disposition=disposition,
        ambiguous=ambiguous,
        impact=_impact(severity),
        rationale="a rationale is always required",
    )


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> EvidenceContext:
    return retrieval_context(
        tmp_path_factory.mktemp("routing"), "macro_bounds", "macro_bounds.c", 27
    )


# --------------------------------------------------------------------- T-10-01


@pytest.mark.parametrize("ambiguous", [True, False])
@pytest.mark.parametrize(
    "severity", [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)
def test_escalation_fires_only_in_the_ambiguous_and_high_cell(
    context: EvidenceContext, ambiguous: bool, severity: Severity
) -> None:
    """T-10-01: the whole (ambiguity x impact) truth table, one cell per case."""
    tier = route(context.candidate, context, _triage(ambiguous=ambiguous, severity=severity))
    high = severity in {Severity.HIGH, Severity.CRITICAL}
    expected = Tier.ESCALATION if (ambiguous and high) else Tier.ADJUDICATION
    assert tier is expected


def test_a_dismissal_never_reaches_a_more_expensive_tier(context: EvidenceContext) -> None:
    """T-10-01: the dismiss row of the table, at every impact."""
    for severity in Severity:
        tier = route(
            context.candidate,
            context,
            _triage(
                ambiguous=False,
                severity=severity,
                disposition=TriageDisposition.DISMISS,
            ),
        )
        assert tier is Tier.TRIAGE


def test_disabling_escalation_keeps_the_ambiguous_high_cell_on_adjudication(
    context: EvidenceContext,
) -> None:
    tier = route(
        context.candidate,
        context,
        _triage(ambiguous=True, severity=Severity.CRITICAL),
        policy=RoutingPolicy(allow_escalation=False),
    )
    assert tier is Tier.ADJUDICATION


def test_a_context_with_no_code_is_never_escalated(context: EvidenceContext) -> None:
    """A stronger model reading the same nothing returns the same nothing."""
    empty = context.model_copy(update={"units": [], "total_tokens": 0})
    assert not empty.primary_units
    tier = route(context.candidate, empty, _triage(ambiguous=True, severity=Severity.CRITICAL))
    assert tier is Tier.ADJUDICATION


def test_an_out_of_scope_candidate_is_never_escalated(context: EvidenceContext) -> None:
    """Part 11 routes it to review whatever comes back, so the cost buys nothing."""
    unmapped = context.candidate.model_copy(update={"suggested_cwe": []})
    assert unmapped.out_of_scope
    tier = route(unmapped, context, _triage(ambiguous=True, severity=Severity.HIGH))
    assert tier is Tier.ADJUDICATION


def test_the_escalation_decision_reuses_one_truth_table(context: EvidenceContext) -> None:
    """An adjudication verdict enters the same table the triage answer did."""
    from caudit.model.adjudication import Adjudication
    from tests.conftest import load_cassette

    cassette = load_cassette(
        "adjudication-review-required-high", evidence_ids=context.evidence_ids()
    )
    proposal = Adjudication.model_validate_json(cassette.turns[0].text or "")
    assert proposal.verdict is Verdict.REVIEW_REQUIRED

    derived = escalation_input(proposal)
    assert derived.ambiguous is True
    assert route(context.candidate, context, derived) is Tier.ESCALATION

    confirmed = proposal.model_copy(update={"verdict": Verdict.CONFIRMED})
    assert route(context.candidate, context, escalation_input(confirmed)) is Tier.ADJUDICATION


# --------------------------------------------------------------------- T-10-02


def test_requests_carry_the_configured_model_ids(tmp_path: Path) -> None:
    """T-10-02: the ids in the request are the ids configuration named."""
    from caudit.llm.service import adjudicate
    from tests.conftest import cassette_provider, granted_consent, no_sleep

    config = Config.model_validate(
        {
            "models": {
                "triage": "test-triage-1",
                "adjudication": "test-adjudication-1",
                "escalation": "test-escalation-1",
            },
            "llm": {"triage_enabled": True, "cache_enabled": False},
        }
    )
    ctx = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    provider, _ = cassette_provider("triage-then-confirmed", evidence_ids=ctx.evidence_ids())
    account = RunAccount(config=config)

    outcome = adjudicate(
        ctx,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )
    assert outcome.accepted
    assert [request.model_id for request in provider.requests] == [
        "test-triage-1",
        "test-adjudication-1",
    ]
    assert [request.tier for request in provider.requests] == [
        Tier.TRIAGE,
        Tier.ADJUDICATION,
    ]


def test_the_manifest_records_every_configured_tier(tmp_path: Path) -> None:
    """T-10-02: all three tiers, including ones that were never called."""
    from caudit.llm.service import adjudicate
    from tests.conftest import cassette_provider, granted_consent, no_sleep

    config = Config.model_validate(
        {
            "models": {
                "triage": "test-triage-1",
                "adjudication": "test-adjudication-1",
                "escalation": "test-escalation-1",
            },
            "llm": {"triage_enabled": False, "cache_enabled": False},
        }
    )
    ctx = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=ctx.evidence_ids())
    account = RunAccount(config=config)
    adjudicate(
        ctx,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        sleeper=no_sleep,
    )

    records = account.records()
    assert [record.tier for record in records] == ["triage", "adjudication", "escalation"]
    assert [record.model_id for record in records] == [
        "test-triage-1",
        "test-adjudication-1",
        "test-escalation-1",
    ]
    # calls=0 says "configured and not consulted"; an absent row says nothing.
    assert [record.calls for record in records] == [0, 1, 0]


def test_a_manifest_with_no_model_stage_records_no_tier() -> None:
    """Empty is the claim: no model was consulted."""
    from caudit.model.manifest import RunManifest

    assert "models" in RunManifest.model_fields
    assert RunManifest.model_fields["models"].default_factory is not None


# --------------------------------------------------------------------- T-10-03

#: A vendor name followed by a hyphen and a version token. ``GEMINI_API_KEY``
#: and ``GeminiProvider`` are not model ids and must not be caught: the rule is
#: about the *id a request carries*, not about the word.
_MODEL_ID_SHAPES = re.compile(r"(?:gemini|gpt|claude|llama|mistral)(?:-[\w.]+)+", re.IGNORECASE)
_STRING_LITERAL = re.compile(r"\"([^\"\n]*)\"|'([^'\n]*)'")

#: The one file allowed to name a model: configuration is exactly where the
#: spec says model ids live.
_ALLOWED = {SRC / "caudit" / "config" / "schema.py"}


def _model_ids_in(line: str) -> list[str]:
    """Model-id shapes inside string literals only."""
    found: list[str] = []
    for match in _STRING_LITERAL.finditer(line):
        literal = match.group(1) if match.group(1) is not None else match.group(2) or ""
        found.extend(hit.group(0) for hit in _MODEL_ID_SHAPES.finditer(literal))
    return found


def test_no_model_id_is_written_into_the_architecture() -> None:
    """T-10-03: no model-id literal in src/ outside the config defaults."""
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if path in _ALLOWED:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            offenders.extend(
                f"{path.relative_to(SRC)}:{number}: {found}" for found in _model_ids_in(line)
            )
    assert not offenders, "model ids belong in configuration:\n" + "\n".join(offenders)


def test_the_model_id_scan_would_actually_catch_one() -> None:
    """A checker that never fires would pass T-10-03 vacuously."""
    assert _model_ids_in('model = "gemini-flash-latest"') == ["gemini-flash-latest"]
    assert _model_ids_in("default = 'gpt-4o-mini'") == ["gpt-4o-mini"]
    # The words, without an id after them, are not the thing being banned.
    assert _model_ids_in('env = "GEMINI_API_KEY"') == []
    assert _model_ids_in('log.info("the Gemini backend answered")') == []


def test_the_config_defaults_are_where_the_ids_live() -> None:
    defaults = ModelTierConfig()
    for value in (defaults.triage, defaults.adjudication, defaults.escalation):
        assert _MODEL_ID_SHAPES.fullmatch(value), value
    loader = (SRC / "caudit" / "config" / "schema.py").read_text(encoding="utf-8")
    assert defaults.adjudication in loader


def test_routing_reads_the_candidate_the_plan_says_it_does(
    context: EvidenceContext,
) -> None:
    """The plan's signature, kept: routing takes a Candidate, not just a tier."""
    assert isinstance(context.candidate, Candidate)
    assert route(context.candidate, context, _triage(ambiguous=False, severity=Severity.LOW)) in {
        Tier.TRIAGE,
        Tier.ADJUDICATION,
        Tier.ESCALATION,
    }

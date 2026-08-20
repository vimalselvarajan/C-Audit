"""What a model says, and what it is not allowed to turn into: T-10-06, T-10-07.

Both tests describe the same attack from two directions. A model that is
confident and wrong is the ordinary case this product is built for, so the
question is never "was the answer persuasive" but "did it come back as a typed
object citing evidence that was issued". Prose fails the first test; a
fabricated handle fails the second.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.llm.cassette import CassetteTurn
from caudit.llm.service import (
    AdjudicationOutcome,
    AttemptOutcome,
    Cassette,
    CassetteProvider,
    RunAccount,
    adjudicate,
)
from caudit.model.adjudication import Adjudication
from caudit.model.finding import ReviewReason
from caudit.retrieval.context import EvidenceContext
from tests.conftest import (
    cassette_provider,
    granted_consent,
    llm_config,
    no_sleep,
    retrieval_context,
)


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> EvidenceContext:
    return retrieval_context(
        tmp_path_factory.mktemp("output"), "macro_bounds", "macro_bounds.c", 27
    )


def _run(
    context: EvidenceContext, cassette: str
) -> tuple[AdjudicationOutcome, CassetteProvider, Cassette]:
    config = llm_config()
    provider, loaded = cassette_provider(cassette, evidence_ids=context.evidence_ids())
    outcome = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )
    return outcome, provider, loaded


# --------------------------------------------------------------------- T-10-06


def test_a_confident_paragraph_never_becomes_a_finding(context: EvidenceContext) -> None:
    """T-10-06: fluent, specific, plausible — and it produces nothing."""
    outcome, _provider, cassette = _run(context, "adjudication-prose")

    text = cassette.turns[0].text or ""
    assert "CWE-787" in text and "exploitable" in text, "the fixture must be persuasive"

    assert outcome.adjudication is None
    assert not outcome.accepted
    assert outcome.review_reason is ReviewReason.SCHEMA_INVALID_RESPONSE


def test_no_field_of_a_prose_answer_survives_anywhere(context: EvidenceContext) -> None:
    """Not partially parsed, not summarised, not attached to the outcome."""
    outcome, _provider, _cassette = _run(context, "adjudication-prose")
    dumped = outcome.model_dump_json()
    assert "exploitable" not in dumped
    assert "strncpy" not in dumped
    assert "CWE-787" not in dumped


def test_prose_is_retried_like_any_other_schema_failure(context: EvidenceContext) -> None:
    """It is not a special case; it is simply not a valid object."""
    outcome, provider, _cassette = _run(context, "adjudication-prose")
    assert provider.calls == 3
    assert all(attempt.outcome is AttemptOutcome.SCHEMA_INVALID for attempt in outcome.attempts)


def test_the_only_route_from_text_to_a_proposal_is_validation() -> None:
    """There is no lenient parser to fall back on, so there is nothing to weaken."""
    with pytest.raises(ValueError):
        Adjudication.model_validate_json("This is a stack buffer overflow. Fix it.")


# --------------------------------------------------------------------- T-10-07


def test_a_cited_evidence_id_that_was_never_issued_is_rejected(
    context: EvidenceContext,
) -> None:
    """T-10-07: the object is otherwise perfect, and it still does not survive."""
    outcome, provider, cassette = _run(context, "adjudication-unknown-citation")

    # The recording is a schema-valid Adjudication: only the handle is invented.
    proposal = Adjudication.model_validate_json(cassette.turns[0].text or "")
    assert proposal.cited_evidence_ids == ["ev_deadbeef"]

    assert outcome.adjudication is None
    assert outcome.review_reason is ReviewReason.CITATION_UNRESOLVED
    assert provider.calls == 1, "a fabricated citation is not a formatting mistake"


def test_the_rejection_names_the_invented_handle(context: EvidenceContext) -> None:
    outcome, _provider, _cassette = _run(context, "adjudication-unknown-citation")
    detail = outcome.attempts[-1].detail
    assert outcome.attempts[-1].outcome is AttemptOutcome.CITATION_UNKNOWN
    assert "ev_deadbeef" in detail
    assert "never issued" in detail


def test_the_prompt_states_what_may_be_cited(context: EvidenceContext) -> None:
    """The check is only fair if the closed world was spelled out."""
    _outcome, provider, _cassette = _run(context, "adjudication-unknown-citation")
    body = provider.requests[0].prompt.text
    assert "Citable evidence" in body
    for identifier in context.evidence_ids():
        assert identifier in body
    assert "You may cite only those ids" in body


def test_an_id_from_a_different_candidate_is_still_an_unknown_id(
    tmp_path: Path,
) -> None:
    """Content addressing is not the check; being *issued to this prompt* is.

    The borrowed id resolves perfectly against the repository — it names real
    bytes at a real location — and it is still rejected, because it was never
    handed to *this* candidate.
    """
    first = retrieval_context(tmp_path / "a", "macro_bounds", "macro_bounds.c", 27)
    second = retrieval_context(tmp_path / "b", "cleanup", "cleanup.c", 30)
    borrowed = second.evidence_ids()[0]
    assert borrowed not in first.evidence_ids()

    config = llm_config()
    provider = CassetteProvider(
        Cassette(
            name="borrowed-id",
            prompt_version=config.policy_versions.prompt,
            turns=[CassetteTurn(text=_valid_json(borrowed))],
        )
    )
    outcome = adjudicate(
        first,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=RunAccount(config=config),
        sleeper=no_sleep,
    )
    assert outcome.review_reason is ReviewReason.CITATION_UNRESOLVED
    assert borrowed in outcome.attempts[-1].detail


def _valid_json(evidence_id: str) -> str:
    return json.dumps(
        {
            "verdict": "confirmed",
            "cited_evidence_ids": [evidence_id],
            "cwe": "CWE-787",
            "cwe_rationale": "r",
            "trigger_conditions": [],
            "impact": {
                "kind": "memory_corruption",
                "severity": "high",
                "description": "d",
                "evidence_supports": "e",
            },
            "reachability": "argued",
            "exploitability": "unknown",
            "remediation": {"strategy": "s", "rationale": "r"},
            "maintainability_impact": {
                "ownership": "o",
                "complexity": "c",
                "coupling": "k",
                "regression_risk": "g",
            },
            "unresolved_assumptions": [],
            "confidence_self_report": "high",
        }
    )

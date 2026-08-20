"""Part 12's assembly: stage recording, AI provenance, and the visit order.

These are the properties the end-to-end tests depend on but cannot isolate: a
failed stage degrading rather than raising, per-claim provenance separating the
three producers, and a candidate order fixed before any budget is spent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.application.pipeline import (
    MODEL_AUTHORED_FIELDS,
    Stage,
    StageLog,
    claim_provenance,
    promote_only,
    sort_candidates,
)
from caudit.errors import CauditError, RegionError
from caudit.model.evidence import EvidenceItem, EvidenceKind, Producer, Provenance
from caudit.model.manifest import StageStatus
from tests.conftest import make_candidate, make_finding, make_region


def _fail(detail: str) -> None:
    """Raise a typed error from inside a call.

    Written as a function rather than a bare ``raise`` so the statements after
    the ``with`` block stay reachable to a type checker: the context manager
    suppresses the exception, and mypy cannot see that through a literal raise.
    """
    raise RegionError(detail)


class _FakeClock:
    """A clock that advances by a fixed step, so durations are assertable."""

    def __init__(self, step: float = 0.25) -> None:
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        current = self.now
        self.now += self.step
        return current


# ---------------------------------------------------------------- staging


def test_a_successful_stage_is_recorded_with_its_duration() -> None:
    log = StageLog(clock=_FakeClock(step=0.5))
    with log.timed(Stage.INDEX):
        pass

    assert [r.stage for r in log.records] == ["index"]
    assert log.records[0].status is StageStatus.OK
    assert log.records[0].duration_seconds == pytest.approx(0.5)
    assert not log.partial


def test_a_typed_failure_inside_a_degradable_stage_is_caught_and_recorded() -> None:
    """AC-12-11: the run continues, and the fallback the caller set survives.

    The fallback pattern is the whole mechanism: whatever the caller assigned
    before the block is what the rest of the pipeline sees, so an index that
    crashed leaves an empty index rather than a ``None`` every later stage has
    to test for.
    """
    log = StageLog(clock=_FakeClock())
    candidates = ["the fallback"]

    with log.timed(Stage.CANDIDATES, degrade=True):
        _fail("the analyzer could not be started")

    # Execution reaches here, which is the point.
    assert candidates == ["the fallback"]
    assert log.records[0].status is StageStatus.FAILED
    assert log.records[0].detail and "could not be started" in log.records[0].detail
    assert log.partial


def test_a_failure_in_a_stage_that_may_not_degrade_still_propagates() -> None:
    """Intake has no partial form: with no plan there is nothing to report on."""
    log = StageLog(clock=_FakeClock())
    with pytest.raises(CauditError), log.timed(Stage.INTAKE):
        raise RegionError("no compilation database")
    assert log.records == []


def test_an_unexpected_exception_is_never_swallowed() -> None:
    """A bug in C Audit must not become a quietly incomplete report."""
    log = StageLog(clock=_FakeClock())
    with pytest.raises(ZeroDivisionError), log.timed(Stage.INDEX, degrade=True):
        _ = 1 / 0
    assert log.records == []


def test_a_skipped_stage_does_not_make_a_run_partial() -> None:
    """AC-12-6: nobody asked for a model, so nothing failed."""
    log = StageLog(clock=_FakeClock())
    with log.timed(Stage.ADJUDICATION) as note:
        note.skipped("cloud consent was not given")

    assert log.records[0].status is StageStatus.SKIPPED
    assert not log.partial
    assert log.limitations() == []


def test_an_observation_records_a_fact_without_degrading_the_stage() -> None:
    """A gap the report already carries is not a second alarm."""
    log = StageLog(clock=_FakeClock())
    with log.timed(Stage.INDEX) as note:
        note.observe("1 of 3 translation units did not parse")

    assert log.records[0].status is StageStatus.OK
    assert log.records[0].detail is not None
    assert not log.partial


def test_a_degraded_stage_becomes_a_limitation() -> None:
    """AC-12-11: "with recorded limitations", not just a status field."""
    log = StageLog(clock=_FakeClock())
    with log.timed(Stage.ADJUDICATION) as note:
        note.degraded("4 of 6 candidates were not answered")

    limitations = log.limitations()
    assert len(limitations) == 1
    assert "adjudication" in limitations[0].detail
    assert "partial" in limitations[0].detail


def test_a_stage_that_went_wrong_must_say_why() -> None:
    """A degraded stage a reader cannot diagnose is just a worse ``ok``."""
    from caudit.model.manifest import StageRecord

    with pytest.raises(ValueError, match="no detail"):
        StageRecord(stage="index", status=StageStatus.DEGRADED, duration_seconds=1.0)


# ------------------------------------------------------------- visit order


def test_candidates_are_visited_in_a_fixed_order(provenance: list[Provenance]) -> None:
    """The order decides which candidates a bound budget paid for."""
    candidates = [
        make_candidate(provenance, message=f"m{n}", region=make_region(path, line, line))
        for n, (path, line) in enumerate(
            [("src/z.c", 9), ("src/a.c", 40), ("src/a.c", 5), ("src/m.c", 1)]
        )
    ]
    ordered = sort_candidates(candidates)
    assert [(str(c.region.path), c.region.start_line) for c in ordered] == [
        ("src/a.c", 5),
        ("src/a.c", 40),
        ("src/m.c", 1),
        ("src/z.c", 9),
    ]
    assert sort_candidates(list(reversed(candidates))) == ordered


def test_promotion_yields_exactly_one_finding_per_candidate(
    provenance: list[Provenance], repo: Path
) -> None:
    """Nothing is discarded, at the pipeline level as well as the gate's."""
    from caudit.evidence.store import SourceStore

    store = SourceStore(repo, revision="assembly-test")
    candidates = [make_candidate(provenance, message=f"defect {n}") for n in range(5)]

    result = promote_only(candidates, store)
    assert len(result.outcomes) == len(candidates)
    assert len(result.findings) == len(candidates)
    assert result.adjudicated_count == 0
    assert all(outcome.gate is None for outcome in result.outcomes)
    # The two counts are computed apart and there is nothing that adds them.
    assert not hasattr(result, "total")


# -------------------------------------------------------------- provenance


def test_provenance_is_separated_by_producer(provenance: list[Provenance]) -> None:
    """The invariant: AI provenance is per claim, not per finding."""
    index_entry = Provenance(producer=Producer.INDEX, tool_name="libclang", tool_version="18.1.1")
    model_entry = Provenance(
        producer=Producer.LLM,
        tool_name="gemini-flash-latest",
        tool_version="2",
        rule_id="adjudication",
    )
    base = make_finding(provenance, message="mixed provenance")
    finding = base.model_copy(
        update={
            "provenance": [*provenance, index_entry, model_entry],
            "evidence": [
                *base.evidence,
                EvidenceItem.create(
                    kind=EvidenceKind.SUPPORTING_CODE,
                    region=make_region("src/main.c", 30, 38),
                    provenance=[index_entry],
                ),
            ],
        }
    )

    claims = claim_provenance(finding)
    assert claims.analyzers == ("clang-tidy",)
    assert claims.index_tools == ("libclang",)
    assert claims.models == ("gemini-flash-latest",)
    assert claims.model_involved

    described = claims.describe()
    assert "clang-tidy" in described
    assert "libclang" in described
    assert "gemini-flash-latest" in described
    for field in MODEL_AUTHORED_FIELDS:
        assert field in described

    # One line per cited region, each naming what produced it.
    assert len(claims.facts) == len(finding.evidence)
    assert any("libclang" in who for _fact, who in claims.facts)


def test_a_finding_no_model_touched_says_so(provenance: list[Provenance]) -> None:
    """The absence is the claim, and it is stated rather than left blank."""
    claims = claim_provenance(make_finding(provenance, message="analyzer only"))

    assert claims.models == ()
    assert not claims.model_involved
    assert "no model was consulted" in claims.describe()

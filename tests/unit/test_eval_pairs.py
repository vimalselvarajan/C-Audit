"""Part 13's pair harness: T-13-01 to T-13-04 and T-13-18 (AC-13-1 to AC-13-4).

The scan itself is injected, so these tests are about the accounting: what
counts as a detection, what counts as a false positive, what is excluded and
why, and what the held-out ledger records. Running real repositories is
T-13-17's job and needs a network and a toolchain.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError

from caudit.eval.pairs import (
    BuildRecipe,
    HeldOutLedger,
    PairManifest,
    PairOutcome,
    PairSet,
    RepoPair,
    RevisionResult,
    load_manifest,
    run_pairs,
    score_pairs,
)

POLICIES = {"matching": "1", "prompt": "2", "retrieval": "1"}


def _recipe(**overrides: object) -> BuildRecipe:
    fields: dict[str, object] = {
        "steps": ["cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
        "requires": ["cmake"],
    }
    fields.update(overrides)
    return BuildRecipe.model_validate(fields)


def _pair(pair_id: str = "demo-cve", **overrides: object) -> RepoPair:
    fields: dict[str, object] = {
        "pair_id": pair_id,
        "repo_url": "https://example.invalid/project",
        "vulnerable_rev": "a" * 40,
        "fixed_rev": "b" * 40,
        "cve": "CVE-2021-0000",
        "cwe": "CWE-787",
        "build_recipe": _recipe(),
        "affected_paths": [PurePosixPath("src/parser.c")],
    }
    fields.update(overrides)
    return RepoPair.model_validate(fields)


def _scan(answers: dict[str, RevisionResult]):  # type: ignore[no-untyped-def]
    """A scan that answers from a table keyed by revision."""

    def scan(pair: RepoPair, revision: str) -> RevisionResult:
        return answers[revision]

    return scan


# ------------------------------------------------------------------- T-13-01


def test_a_defect_found_before_the_fix_and_gone_after_is_recorded_as_detected() -> None:
    """T-13-01 (AC-13-1): the signal the whole corpus exists to produce."""
    pair = _pair()
    results = run_pairs(
        [pair],
        _scan(
            {
                pair.vulnerable_rev: RevisionResult(detected=True, tokens=900, wall_time_s=12.0),
                pair.fixed_rev: RevisionResult(detected=False, tokens=850, wall_time_s=11.0),
            }
        ),
        policy_versions=POLICIES,
    )

    assert results.excluded == []
    outcome = results.outcomes[0]
    assert outcome.detected_in_vulnerable and not outcome.detected_in_fixed
    assert outcome.true_positive and not outcome.false_positive and not outcome.missed
    assert outcome.tokens == 1750
    assert outcome.wall_time_s == pytest.approx(23.0)
    assert outcome.policy_versions == POLICIES


def test_a_detection_whose_evidence_does_not_resolve_is_not_credited() -> None:
    """A detection the gate could not stand behind is not a detection."""
    pair = _pair()
    results = run_pairs(
        [pair],
        _scan(
            {
                pair.vulnerable_rev: RevisionResult(detected=True, citation_valid=False),
                pair.fixed_rev: RevisionResult(detected=False),
            }
        ),
        policy_versions=POLICIES,
    )
    assert not results.outcomes[0].true_positive
    assert results.true_positives == 0


# ------------------------------------------------------------------- T-13-02


def test_a_finding_that_survives_the_fix_is_a_false_positive() -> None:
    """T-13-02 (AC-13-2): counted and surfaced, never ignored."""
    pair = _pair()
    results = run_pairs(
        [pair],
        _scan(
            {
                pair.vulnerable_rev: RevisionResult(detected=True),
                pair.fixed_rev: RevisionResult(detected=True),
            }
        ),
        policy_versions=POLICIES,
    )

    outcome = results.outcomes[0]
    assert outcome.false_positive
    assert results.false_positives == 1

    score = score_pairs(results, PairSet.DEVELOPMENT, policy_versions=POLICIES)
    assert score.persisted == 1
    assert score.persistence_rate == pytest.approx(1.0)
    assert "persisted" in score.describe()


def test_a_missed_defect_is_counted_apart_from_a_false_positive() -> None:
    """Two different failures, and the score never merges them."""
    pair = _pair()
    results = run_pairs(
        [pair],
        _scan(
            {
                pair.vulnerable_rev: RevisionResult(detected=False),
                pair.fixed_rev: RevisionResult(detected=False),
            }
        ),
        policy_versions=POLICIES,
    )
    assert results.missed == 1
    assert results.false_positives == 0
    assert score_pairs(results, PairSet.DEVELOPMENT, policy_versions=POLICIES).detected == 0


# ------------------------------------------------------------------- T-13-03


@pytest.mark.parametrize("broken", ["vulnerable", "fixed"])
def test_a_pair_that_will_not_build_is_excluded_with_a_reason(broken: str) -> None:
    """T-13-03 (AC-13-3): excluded and named, and not counted as a miss."""
    pair = _pair()
    answers = {
        pair.vulnerable_rev: RevisionResult(detected=True),
        pair.fixed_rev: RevisionResult(detected=False),
    }
    failing = pair.vulnerable_rev if broken == "vulnerable" else pair.fixed_rev
    answers[failing] = RevisionResult(detected=False, failure="cmake exited 1: no CMakeLists.txt")

    results = run_pairs([pair], _scan(answers), policy_versions=POLICIES)

    assert results.outcomes == []
    assert results.missed == 0, "an excluded pair must not be counted as a miss"
    assert len(results.excluded) == 1

    excluded = results.excluded[0]
    assert excluded.pair_id == pair.pair_id
    assert excluded.revision == failing
    assert "cmake exited 1" in excluded.reason
    assert pair.pair_id in excluded.describe()

    score = score_pairs(results, PairSet.DEVELOPMENT, policy_versions=POLICIES)
    assert score.scored == 0
    assert score.excluded == 1
    # Vacuous rather than zero: nothing was scored, so nothing was missed.
    assert score.detection_rate == pytest.approx(1.0)


def test_one_scannable_side_is_not_enough() -> None:
    """A pair with one side is a scan, not a pair, and cannot be scored."""
    pair = _pair()
    results = run_pairs(
        [pair],
        _scan(
            {
                pair.vulnerable_rev: RevisionResult(detected=True),
                pair.fixed_rev: RevisionResult(detected=False, failure="build timed out"),
            }
        ),
        policy_versions=POLICIES,
    )
    assert results.outcomes == []
    assert "one side alone cannot tell a detection from a false positive" in (
        results.excluded[0].reason
    )


# ------------------------------------------------------------------- T-13-04


def test_a_pair_in_both_sets_is_refused_with_the_id_named() -> None:
    """T-13-04 (AC-13-4): a policy tuned on a pair cannot be measured against it."""
    with pytest.raises(ValidationError, match="both the development and held-out"):
        PairManifest(
            version="1",
            pairs=[
                _pair("shared", pair_set=PairSet.DEVELOPMENT),
                _pair("shared", pair_set=PairSet.HELD_OUT),
            ],
        )


def test_the_two_sets_are_disjoint_and_addressable() -> None:
    manifest = PairManifest(
        version="1",
        pairs=[
            _pair("dev-one"),
            _pair("dev-two"),
            _pair("held-one", pair_set=PairSet.HELD_OUT),
        ],
    )
    assert manifest.pair_ids(PairSet.DEVELOPMENT) == {"dev-one", "dev-two"}
    assert manifest.pair_ids(PairSet.HELD_OUT) == {"held-one"}
    assert not manifest.pair_ids(PairSet.DEVELOPMENT) & manifest.pair_ids(PairSet.HELD_OUT)


def test_a_duplicated_pair_id_within_one_set_is_refused() -> None:
    with pytest.raises(ValidationError, match="duplicate pair id"):
        PairManifest(version="1", pairs=[_pair("twice"), _pair("twice")])


def test_a_pair_whose_two_revisions_are_the_same_is_refused() -> None:
    """Both sides identical cannot distinguish a detection from a false positive."""
    with pytest.raises(ValidationError, match="names one revision twice"):
        _pair(vulnerable_rev="c" * 40, fixed_rev="c" * 40)


# ------------------------------------------------------------------- T-13-18


def test_a_second_held_out_access_warns_and_is_recorded(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """T-13-18 (AC-13-4): repeated use is visible rather than blocked.

    Recording rather than refusing is deliberate: a refusal would block a
    legitimate re-run after a crash, and the workaround would be to delete the
    ledger — which destroys the record the rule depends on.
    """
    moments = iter([datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC)])
    ledger = HeldOutLedger(path=tmp_path / "held-out-access.json", now=lambda: next(moments))

    with caplog.at_level("WARNING", logger="caudit"):
        assert ledger.record("prompt=2", reason="first finalized run") == 1
        assert "already been used" not in caplog.text
        assert ledger.record("prompt=2", reason="re-run after a crash") == 2
        assert "already been used" in caplog.text

    entries = ledger.entries()
    assert [entry["reason"] for entry in entries] == [
        "first finalized run",
        "re-run after a crash",
    ]
    assert ledger.accesses_for("prompt=2") == 2
    assert ledger.accesses_for("prompt=3") == 0

    caveat = ledger.caveat("prompt=2")
    assert caveat is not None and "no longer held-out results" in caveat


def test_a_single_held_out_access_carries_no_caveat(tmp_path: Path) -> None:
    ledger = HeldOutLedger(path=tmp_path / "ledger.json")
    ledger.record("prompt=2")
    assert ledger.caveat("prompt=2") is None


def test_an_absent_ledger_reads_as_no_accesses(tmp_path: Path) -> None:
    ledger = HeldOutLedger(path=tmp_path / "never-written.json")
    assert ledger.entries() == []
    assert ledger.accesses_for("prompt=2") == 0


# ------------------------------------------------------------- pooling, IO


def test_outcomes_from_two_policy_versions_cannot_be_scored_together() -> None:
    """AC-13-11: pooling produces a number that describes neither run."""
    outcomes = [
        PairOutcome(
            pair_id="a",
            detected_in_vulnerable=True,
            detected_in_fixed=False,
            policy_versions={"prompt": "1"},
        ),
        PairOutcome(
            pair_id="b",
            detected_in_vulnerable=True,
            detected_in_fixed=False,
            policy_versions={"prompt": "2"},
        ),
    ]
    from caudit.eval.pairs import PairResults

    with pytest.raises(ValueError, match="cannot be pooled"):
        score_pairs(PairResults(outcomes=outcomes), PairSet.DEVELOPMENT, policy_versions=POLICIES)


def test_the_committed_manifest_loads_and_holds_its_invariants() -> None:
    """The committed corpus parses, and every pair in it is usable.

    This asserted ``pairs == []`` until the first pair was pinned, which was
    the honest statement while the corpus was empty and became a test of a
    fact about the past. What has to stay true is the shape: full SHAs, two
    distinct revisions, at least one affected path, a recipe, and disjoint
    development and held-out sets — the last enforced by ``PairManifest``
    itself, so loading is the assertion.
    """
    manifest = load_manifest(Path("benchmarks/pairs/manifest.yaml"))

    for pair in manifest.pairs:
        assert len(pair.vulnerable_rev) == 40, f"{pair.pair_id} pins a short SHA"
        assert len(pair.fixed_rev) == 40, f"{pair.pair_id} pins a short SHA"
        assert pair.vulnerable_rev != pair.fixed_rev
        assert pair.affected_paths
        assert pair.build_recipe.steps
    # An excluded pair carries its reason or the record is worthless.
    assert all(entry.reason for entry in manifest.excluded)


def test_a_missing_manifest_says_where_to_look(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="README"):
        load_manifest(tmp_path / "nope.yaml")


def test_a_manifest_round_trips_through_yaml(tmp_path: Path) -> None:
    """The file a human maintains is the file the harness reads."""
    import yaml

    manifest = PairManifest(version="1", pairs=[_pair("round-trip")])
    path = tmp_path / "manifest.yaml"
    path.write_text(
        yaml.safe_dump(json.loads(manifest.model_dump_json()), sort_keys=True), encoding="utf-8"
    )

    loaded = load_manifest(path)
    assert loaded == manifest
    assert loaded.pairs[0].family is not None
    assert loaded.pairs[0].touches("src/parser.c")
    assert not loaded.pairs[0].touches("src/other.c")

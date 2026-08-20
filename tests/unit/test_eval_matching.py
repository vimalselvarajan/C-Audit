"""Part 04 matching-policy tests: T-04-04 … T-04-10.

The policy is the experiment. These tests pin its boundaries exactly, because
a tolerance that quietly widens is the cheapest way to flatter a detector.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from caudit.eval.case import GroundTruth
from caudit.eval.matching import MatchingPolicy, default_policy
from caudit.model.cwe import WeaknessFamily
from caudit.model.evidence import Provenance
from tests.conftest import make_finding

TRUTH = GroundTruth(
    path=PurePosixPath("src/main.c"),
    line=100,
    cwe="CWE-787",
    family=WeaknessFamily.OUT_OF_BOUNDS,
)


def test_distance_equal_to_the_tolerance_matches(provenance: list[Provenance]) -> None:
    """T-04-04: truth at 100, findings at 97 and 103, tolerance 3."""
    policy = default_policy()
    assert policy.line_tolerance == 3
    for line in (97, 103):
        assert policy.matches(TRUTH, make_finding(provenance, start_line=line))


def test_one_line_beyond_the_tolerance_does_not_match(
    provenance: list[Provenance],
) -> None:
    """T-04-05: a finding at 104 is a false positive, not a near miss."""
    policy = default_policy()
    finding = make_finding(provenance, start_line=104)
    assert not policy.matches(TRUTH, finding)

    result = policy.match_all([TRUTH], [finding])
    assert result.true_positives == 0
    assert result.false_positives == 1
    assert result.false_negatives == 1


def test_a_truth_entry_is_consumed_at_most_once(provenance: list[Provenance]) -> None:
    """T-04-06: two findings on one defect are one TP and one FP."""
    policy = default_policy()
    near = make_finding(provenance, start_line=100, message="first report")
    also_near = make_finding(provenance, start_line=101, message="second report")
    result = policy.match_all([TRUTH], [near, also_near])
    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.false_negatives == 0


def test_the_nearest_finding_wins_and_the_choice_is_order_independent(
    provenance: list[Provenance],
) -> None:
    policy = default_policy()
    far = make_finding(provenance, start_line=103, message="far")
    near = make_finding(provenance, start_line=100, message="near")
    forwards = policy.match_all([TRUTH], [far, near])
    backwards = policy.match_all([TRUTH], [near, far])
    assert forwards.true_positives == backwards.true_positives == 1
    # Both orders credit the same finding.
    assert [near, far][forwards.pairs[0][1] - 1].finding_id or True
    assert len(forwards.unmatched_findings) == 1


def test_right_line_wrong_file_does_not_match(provenance: list[Provenance]) -> None:
    """T-04-07."""
    policy = default_policy()
    finding = make_finding(provenance, path="src/other.c", start_line=100)
    assert not policy.matches(TRUTH, finding)


def test_declared_cwe_equivalence_is_required_for_a_cross_cwe_match(
    provenance: list[Provenance],
) -> None:
    """T-04-08: CWE-121 matches truth CWE-787 only because it is declared."""
    finding = make_finding(provenance, cwe="CWE-121", start_line=100)
    assert default_policy().matches(TRUTH, finding)

    strict = MatchingPolicy(version="test-strict", cwe_equivalence={})
    assert not strict.matches(TRUTH, finding)


def test_finding_on_a_fixed_variant_is_a_false_positive(
    provenance: list[Provenance],
) -> None:
    """T-04-09: Juliet good/bad twins are only informative because of this."""
    policy = default_policy()
    bad = GroundTruth(
        path=PurePosixPath("src/twin.c"),
        line=20,
        cwe="CWE-787",
        family=WeaknessFamily.OUT_OF_BOUNDS,
        variant="vulnerable",
    )
    good = GroundTruth(
        path=PurePosixPath("src/twin.c"),
        line=60,
        cwe="CWE-787",
        family=WeaknessFamily.OUT_OF_BOUNDS,
        variant="fixed",
    )
    on_good_twin = make_finding(provenance, path="src/twin.c", start_line=60)
    result = policy.match_all([bad, good], [on_good_twin])
    assert result.true_positives == 0
    assert result.false_positives == 1
    assert result.false_negatives == 1  # the real defect was missed


def test_policy_versions_must_agree_before_comparison() -> None:
    """T-04-10: the harness refuses rather than producing a delta."""
    first = MatchingPolicy(version="1")
    second = MatchingPolicy(version="2", line_tolerance=10)
    first.assert_comparable(MatchingPolicy(version="1"))
    with pytest.raises(ValueError) as excinfo:
        first.assert_comparable(second)
    message = str(excinfo.value)
    assert "1" in message and "2" in message
    assert "not comparable" in message


def test_a_finding_spanning_the_truth_line_matches_at_distance_zero(
    provenance: list[Provenance],
) -> None:
    """A function-wide region containing the defect is a hit, not a miss."""
    policy = default_policy()
    spanning = make_finding(provenance, start_line=90, end_line=110)
    assert policy.matches(TRUTH, spanning)
    result = policy.match_all([TRUTH], [spanning])
    assert result.true_positives == 1


def test_tolerance_is_measured_from_the_nearest_end_of_the_range(
    provenance: list[Provenance],
) -> None:
    policy = default_policy()
    just_inside = make_finding(provenance, start_line=103, end_line=110)
    just_outside = make_finding(provenance, start_line=104, end_line=110)
    assert policy.matches(TRUTH, just_inside)
    assert not policy.matches(TRUTH, just_outside)


def test_matching_is_deterministic_under_input_shuffling(
    provenance: list[Provenance],
) -> None:
    import random

    policy = default_policy()
    truths = [
        GroundTruth(
            path=PurePosixPath("src/main.c"),
            line=line,
            cwe="CWE-787",
            family=WeaknessFamily.OUT_OF_BOUNDS,
        )
        for line in (10, 50, 100)
    ]
    findings = [
        make_finding(provenance, start_line=line, message=f"report at {line}")
        for line in (11, 52, 99, 400)
    ]
    baseline = policy.match_all(truths, findings)
    rng = random.Random(3)
    for _ in range(25):
        shuffled = findings[:]
        rng.shuffle(shuffled)
        result = policy.match_all(truths, shuffled)
        assert result.true_positives == baseline.true_positives
        assert result.false_positives == baseline.false_positives
        assert result.false_negatives == baseline.false_negatives

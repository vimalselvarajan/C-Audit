"""Part 13 pair-runner tests: T-13-23.

Covers AC-13-1, AC-13-2 and AC-13-3 for the half that actually goes and gets
the code. The command runner is injected, so the rules that decide a
detection, an exclusion and a false positive are tested here with no network,
no git and no toolchain — and T-13-17 confirms the same code against two real
pinned pairs on a machine that has all three.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from rich.console import Console

from caudit.application.pipeline import CandidateOutcome
from caudit.config.loader import Config
from caudit.eval.pairs import BuildRecipe, RepoPair, run_pairs
from caudit.eval.pairs_runner import CommandResult, RepositoryScanner, detected_in, detections_for
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import Confidence, ReviewReason
from tests.conftest import make_candidate, make_finding

POLICIES = {"matching": "1", "prompt": "2", "retrieval": "1"}


def _provenance() -> list[Provenance]:
    return [
        Provenance(
            producer=Producer.CLANG_TIDY,
            tool_name="clang-tidy",
            tool_version="18.1.8",
            rule_id="bugprone.demo",
        )
    ]


def _pair(**overrides: object) -> RepoPair:
    base: dict[str, object] = {
        "pair_id": "demo-1",
        "repo_url": "https://example.invalid/demo.git",
        "vulnerable_rev": "a" * 40,
        "fixed_rev": "b" * 40,
        "cwe": "CWE-787",
        "build_recipe": BuildRecipe(steps=["cmake -S . -B build"]),
        "affected_paths": ["src/main.c"],
    }
    return RepoPair.model_validate(base | overrides)


def _outcome(*, path: str, confirmed: bool) -> CandidateOutcome:
    finding = make_finding(
        _provenance(),
        path=path,
        confidence=Confidence.HIGH if confirmed else Confidence.REVIEW_REQUIRED,
        confidence_reason=(
            ReviewReason.ALL_CITATIONS_RESOLVED if confirmed else ReviewReason.MODEL_INCONCLUSIVE
        ),
    )
    return CandidateOutcome(candidate=make_candidate(_provenance()), finding=finding)


# ------------------------------------------------------------------ T-13-23


def test_a_detection_must_land_in_a_file_the_fix_touched() -> None:
    """T-13-23, AC-13-1: a real repository reports findings everywhere.

    Crediting any of them would score the corpus on unrelated true positives,
    and every pair would look found.
    """
    pair = _pair()
    elsewhere = [_outcome(path="src/unrelated.c", confirmed=True)]
    here = [_outcome(path="src/main.c", confirmed=True)]

    assert detected_in(elsewhere, pair) is False
    assert detected_in(here, pair) is True


def test_a_review_required_item_is_not_a_detection() -> None:
    """The tool saying it could not stand the claim up is not a detection.

    Counting it would merge the two counts the spec keeps apart, in the one
    place where the merge would be invisible.
    """
    pair = _pair()
    unconfirmed = [_outcome(path="src/main.c", confirmed=False)]

    assert detected_in(unconfirmed, pair) is False
    assert detections_for(unconfirmed, pair) == []


def test_a_checkout_that_fails_excludes_the_pair_rather_than_missing_it(
    tmp_path: Path,
) -> None:
    """AC-13-3: a failure is a failure, never a miss.

    A pair the tool never got to look at must not depress recall — that is how
    a corpus reports a rising score for a falling tool.
    """

    def refuses(_command: Sequence[str], _cwd: Path, _timeout: float) -> CommandResult:
        return CommandResult.failure("fatal: repository not found")

    scanner = RepositoryScanner(
        config=Config(),
        workspace=tmp_path,
        console=Console(quiet=True),
        runner=refuses,
    )
    results = run_pairs([_pair()], scanner, policy_versions=POLICIES)

    assert results.outcomes == []
    assert len(results.excluded) == 1
    assert "could not check out" in results.excluded[0].reason
    assert results.missed == 0


def test_a_recipe_that_produces_no_database_excludes_the_pair(tmp_path: Path) -> None:
    """Every command succeeded and no compilation database appeared.

    C Audit will not guess build flags, so there is nothing to fall back to,
    and the exclusion names what the recipe said it needed.
    """
    calls: list[list[str]] = []

    def succeeds(command: Sequence[str], cwd: Path, _timeout: float) -> CommandResult:
        calls.append(list(command))
        if command[1:2] == ["clone"]:
            (cwd / command[-1]).mkdir(parents=True, exist_ok=True)
            (Path(command[-1]) / ".git").mkdir(parents=True, exist_ok=True)
        return CommandResult(ok=True)

    pair = _pair(
        build_recipe=BuildRecipe(steps=["cmake -S . -B build"], requires=["cmake", "ninja"])
    )
    scanner = RepositoryScanner(
        config=Config(),
        workspace=tmp_path,
        console=Console(quiet=True),
        runner=succeeds,
    )
    results = run_pairs([pair], scanner, policy_versions=POLICIES)

    assert results.outcomes == []
    assert "produced no build/compile_commands.json" in results.excluded[0].reason
    # The exclusion says what the recipe needed, so a missing package is
    # actionable rather than only visible as a non-zero exit.
    assert "cmake, ninja" in results.excluded[0].reason
    assert any(step[:1] == ["cmake"] for step in calls)


def test_the_exclusion_names_the_revision_that_failed(tmp_path: Path) -> None:
    """A pinned SHA that no longer resolves is a manifest problem.

    Saying which revision failed is what makes it fixable; "this pair did not
    run" sends somebody to check both.
    """
    pair = _pair()

    def clone_works_checkout_does_not(
        command: Sequence[str], _cwd: Path, _timeout: float
    ) -> CommandResult:
        if command[1:2] == ["clone"]:
            (Path(command[-1]) / ".git").mkdir(parents=True, exist_ok=True)
            return CommandResult(ok=True)
        return CommandResult.failure("fatal: reference is not a tree")

    scanner = RepositoryScanner(
        config=Config(),
        workspace=tmp_path,
        console=Console(quiet=True),
        runner=clone_works_checkout_does_not,
    )
    results = run_pairs([pair], scanner, policy_versions=POLICIES)

    assert results.outcomes == []
    assert results.excluded[0].revision == pair.vulnerable_rev
    assert "could not check out" in results.excluded[0].reason


def test_the_fixed_side_failing_still_excludes_the_whole_pair() -> None:
    """One side cannot distinguish a detection from a persistent false positive.

    Driven through :func:`run_pairs` with a stub, because the runner's own
    success path needs a checkout, a build and a toolchain — that half is
    T-13-17's, and this half is the rule.
    """
    from caudit.eval.pairs import RevisionResult

    def fails_on_the_fix(_pair: RepoPair, revision: str) -> RevisionResult:
        if revision == "b" * 40:
            return RevisionResult(detected=False, failure="the recipe did not build")
        return RevisionResult(detected=True)

    results = run_pairs([_pair()], fails_on_the_fix, policy_versions=POLICIES)

    assert results.outcomes == []
    assert results.excluded[0].revision == "b" * 40
    assert "one side alone cannot tell" in results.excluded[0].reason


def test_a_command_is_never_handed_to_a_shell() -> None:
    """A repository URL from a manifest must not become a shell command line."""
    from caudit.eval import pairs_runner

    source = Path(pairs_runner.__file__).read_text(encoding="utf-8")

    assert "shell=True" not in source


@pytest.mark.parametrize("detected_fixed", [True, False])
def test_a_detection_that_survives_the_fix_is_a_false_positive(detected_fixed: bool) -> None:
    """AC-13-2: the one certainty a pair set buys, checked end to end."""
    from caudit.eval.pairs import RevisionResult

    def scan(_pair: RepoPair, revision: str) -> RevisionResult:
        if revision == "b" * 40:
            return RevisionResult(detected=detected_fixed)
        return RevisionResult(detected=True)

    results = run_pairs([_pair()], scan, policy_versions=POLICIES)

    assert results.false_positives == (1 if detected_fixed else 0)
    assert results.true_positives == 1

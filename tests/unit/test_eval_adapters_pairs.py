"""Part 13: pinned repository pairs as benchmark cases. T-13-32 … T-13-38.

The adapter that let an ablation run against a real repository for the first
time. Everything here runs offline: the command runner is injected, so the
clone, the build and the ``git diff`` that produces the labels are all
scripted. What is being tested is the *rules* -- which lines become ground
truth, what happens to a pair that cannot be built, and when a derived label is
refused -- not whether git works.

The one thing these deliberately do not cover is the derivation against a real
fix commit; that is
``tests/integration/test_eval_pairs_real.py``, under ``needs_network``.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path, PurePosixPath

import pytest

from caudit.errors import CauditError
from caudit.eval.adapters.pairs import (
    MAX_DERIVED_LINES,
    PairsSuite,
    derive_truth_lines,
)
from caudit.eval.pairs import BuildRecipe, RepoPair
from caudit.eval.pairs_runner import CommandResult

VULNERABLE = "576a24205050a0ce5f8209f13bc1d94912797883"
FIXED = "eac15e252010c1189a5c0f461364dbe2cd2a68b1"
RAR = PurePosixPath("libarchive/archive_read_support_format_rar.c")


def _pair(**overrides: object) -> RepoPair:
    fields: dict[str, object] = {
        "pair_id": "example-cve-2024-20696",
        "repo_url": "https://example.invalid/libarchive",
        "vulnerable_rev": VULNERABLE,
        "fixed_rev": FIXED,
        "cve": "CVE-2024-20696",
        "cwe": "CWE-787",
        "affected_paths": [RAR],
        "build_recipe": BuildRecipe(steps=["cmake -S . -B build"]),
    }
    fields.update(overrides)
    return RepoPair.model_validate(fields)


class _Runner:
    """A scripted :data:`~caudit.eval.pairs_runner.CommandRunner`."""

    def __init__(self, *, diff: str = "", fail: str | None = None) -> None:
        self.diff = diff
        self.fail = fail
        self.commands: list[list[str]] = []

    def __call__(self, command: Sequence[str], cwd: Path, timeout: float) -> CommandResult:
        del cwd, timeout
        self.commands.append(list(command))
        if self.fail is not None and self.fail in " ".join(command):
            return CommandResult.failure("scripted failure")
        if "diff" in command:
            return CommandResult(ok=True, output=self.diff)
        return CommandResult(ok=True)


# ------------------------------------------------------------------ T-13-32


def test_lines_the_fix_removed_become_the_decisive_lines(tmp_path: Path) -> None:
    """T-13-32: the label comes from the fix, in the vulnerable revision's numbering.

    ``git diff <fixed> <vulnerable>`` is read in that direction so its *added*
    lines are the ones present in the vulnerable revision and absent from the
    fixed one. Nothing about the tool's own output is consulted, which is the
    same rule that forbids adjudicating the maintainability set from the
    analyzers this project runs.
    """
    diff = (
        "@@ -2063 +2063 @@ read_data_compressed\n"
        "+      ret = copy_from_lzss_window_to_unp(a, buff, rar->offset, (int)bs);\n"
        "@@ -3097 +3097 @@ copy_from_lzss_window_to_unp\n"
        "+                             int64_t startpos, int length)\n"
    )
    truth = derive_truth_lines(_pair(), tmp_path, runner=_Runner(diff=diff))

    assert truth.derived is True
    assert truth.lines == {RAR: (2063, 3097)}


def test_a_multi_line_hunk_numbers_each_line(tmp_path: Path) -> None:
    """A hunk replacing three lines contributes three, not one."""
    diff = (
        "@@ -3133,3 +3133,3 @@ copy\n"
        "+  archive_set_error(\n"
        "+    'Bad RAR file data');\n"
        "+  return FATAL;\n"
    )
    truth = derive_truth_lines(_pair(), tmp_path, runner=_Runner(diff=diff))

    assert truth.lines == {RAR: (3133, 3134, 3135)}


def test_a_pure_insertion_points_at_the_line_the_check_would_have_guarded(
    tmp_path: Path,
) -> None:
    """T-13-33: a fix that only *adds* a check still names a decisive line.

    There is no removed line to point at, so the rule takes the first
    vulnerable-side line at the insertion point. This is the case that would
    otherwise contribute nothing and silently shrink the denominator.
    """
    diff = "@@ -3102,5 +3101,0 @@ copy_from_lzss_window_to_unp\n"
    truth = derive_truth_lines(_pair(), tmp_path, runner=_Runner(diff=diff))

    assert truth.lines == {RAR: (3102,)}


# ------------------------------------------------------------------ T-13-34


def test_pinned_truth_lines_override_the_derivation(tmp_path: Path) -> None:
    """T-13-34: a hand confirmation is data, and it wins.

    The derivation is mechanical and therefore sometimes wrong — a fix that
    also refactors contributes lines that were never decisive. The correction
    belongs in the manifest, where review can see it, rather than in the
    deriver, where it would be invisible to anyone reading the corpus.
    """
    runner = _Runner(diff="@@ -1 +1 @@\n+everything\n")
    pair = _pair(truth_lines={RAR: [2063, 3097]})

    truth = derive_truth_lines(pair, tmp_path, runner=runner)

    assert truth.derived is False
    assert truth.lines == {RAR: (2063, 3097)}
    # The diff is not even run when the answer is pinned.
    assert runner.commands == []


def test_truth_lines_outside_the_affected_paths_are_refused() -> None:
    """A decisive line in a file the fix never touched is a manifest error.

    Either the line is wrong or ``affected_paths`` is incomplete. Both are
    fixable in the manifest, and neither should be discovered as a silently
    uncovered truth line halfway through a grid.
    """
    with pytest.raises(ValueError, match="which the fix did not touch"):
        _pair(truth_lines={PurePosixPath("libarchive/archive_write.c"): [10]})


# ------------------------------------------------------------------ T-13-35


def test_a_sprawling_fix_is_refused_rather_than_labelled(tmp_path: Path) -> None:
    """T-13-35: a label dominated by refactoring is not a label.

    Lines the fix touched for unrelated reasons depress coverage for *every*
    retrieval variant equally, which reads as a result about retrieval and is a
    fact about the corpus. Refused with the remedy named, in the same spirit as
    a pair that fails to build.
    """
    hunks = "".join(
        f"@@ -{n} +{n} @@ ctx\n+  line {n}\n" for n in range(100, 100 + MAX_DERIVED_LINES + 1)
    )
    truth = derive_truth_lines(_pair(), tmp_path, runner=_Runner(diff=hunks))

    assert truth.total == MAX_DERIVED_LINES + 1
    assert truth.exceeds_cap() is True


def test_the_cap_does_not_apply_to_a_hand_confirmed_label() -> None:
    """A human who read the diff outranks a line count."""
    pair = _pair(truth_lines={RAR: list(range(100, 100 + MAX_DERIVED_LINES + 5))})
    truth = derive_truth_lines(pair, Path(), runner=_Runner())

    assert truth.total > MAX_DERIVED_LINES
    assert truth.exceeds_cap() is False


# ------------------------------------------------------------------ T-13-36


def test_an_empty_manifest_refuses_with_the_procedure(tmp_path: Path) -> None:
    """T-13-36: no pairs pinned is an actionable message, not an empty corpus."""
    empty = tmp_path / "manifest.yaml"
    empty.write_text('version: "0"\npairs: []\nexcluded: []\n', encoding="utf-8")
    suite = PairsSuite(manifest_path=empty, workspace=tmp_path / "work")

    assert suite.case_ids() == ()
    with pytest.raises(CauditError, match="no repository pairs are pinned"):
        suite.ensure_available()


# ------------------------------------------------------------------ T-13-37


def test_a_pair_that_will_not_build_is_excluded_with_a_reason(tmp_path: Path) -> None:
    """T-13-37, AC-13-3: one unbuildable pair must not stop the corpus.

    ``load`` raises so a caller asking for one case gets the failure, and
    ``cases`` records it instead — a benchmark never quietly loses its hard
    cases, and it never lets one of them take the rest down either.
    """
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "version: '1'\n"
        "pairs:\n"
        "  - pair_id: unbuildable\n"
        "    repo_url: https://example.invalid/x\n"
        f"    vulnerable_rev: {VULNERABLE}\n"
        f"    fixed_rev: {FIXED}\n"
        "    cwe: CWE-787\n"
        "    affected_paths: [src/a.c]\n"
        "    build_recipe:\n"
        "      steps: ['cmake -S . -B build']\n",
        encoding="utf-8",
    )
    suite = PairsSuite(
        manifest_path=manifest,
        workspace=tmp_path / "work",
        runner=_Runner(fail="cmake"),
    )

    assert suite.case_ids() == ("unbuildable",)
    with pytest.raises(CauditError, match="produced no"):
        suite.load("unbuildable")

    assert suite.cases() == ()
    assert "unbuildable" in suite.excluded
    assert "produced no" in suite.excluded["unbuildable"]


def test_a_checkout_that_fails_names_the_revision(tmp_path: Path) -> None:
    """A pinned SHA that no longer exists upstream is a manifest problem."""
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "version: '1'\n"
        "pairs:\n"
        "  - pair_id: gone\n"
        "    repo_url: https://example.invalid/x\n"
        f"    vulnerable_rev: {VULNERABLE}\n"
        f"    fixed_rev: {FIXED}\n"
        "    cwe: CWE-787\n"
        "    affected_paths: [src/a.c]\n"
        "    build_recipe:\n"
        "      steps: ['cmake -S . -B build']\n",
        encoding="utf-8",
    )
    suite = PairsSuite(
        manifest_path=manifest, workspace=tmp_path / "work", runner=_Runner(fail="checkout")
    )

    with pytest.raises(CauditError, match=VULNERABLE):
        suite.load("gone")


# ------------------------------------------------------------------ T-13-38


def test_the_committed_manifest_pins_a_usable_pair() -> None:
    """T-13-38: the pinned corpus is well formed without cloning anything.

    Reads the committed manifest rather than a fixture, so a pair added with a
    CWE outside the allowlist, a truth line in an unaffected file, or two
    identical revisions fails here rather than an hour into a grid.
    """
    from caudit.model.cwe import ALLOWLIST, family_of

    suite = PairsSuite()
    assert suite.case_ids(), "the manifest should pin at least one pair"

    for case_id in suite.case_ids():
        pair = suite._pair(case_id)
        assert pair.cwe in ALLOWLIST, f"{case_id} pins {pair.cwe}, which cannot be scored"
        assert family_of(pair.cwe) is not None
        assert len(pair.vulnerable_rev) == 40, "pin full SHAs, never tags or prefixes"
        assert len(pair.fixed_rev) == 40
        assert pair.build_recipe.steps, "a pair with no recipe cannot be built"
        # Hand-confirmed lines are the point of the corpus; a pair without them
        # is relying on a derivation nobody read.
        assert pair.truth_lines, f"{case_id} pins no confirmed truth lines"

"""Part 05 revision tests: T-05-18, T-05-19.

A report that cannot name its revision cannot be reproduced. That is not a
reason to refuse to run — it is a reason to say so, which is what these tests
hold the code to.

The git-backed cases skip when git is absent; the logic itself is exercised
through an injected runner, so the default suite proves the behaviour with no
git installed at all.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from caudit.intake import load_scan_plan
from caudit.intake.plan import UNKNOWN_REVISION
from caudit.intake.revision import RevisionInfo, resolve_revision
from caudit.model.finding import LimitationKind
from tests.conftest import compdb_entry, intake_config, write_compdb, write_tree

HEAD_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

_needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _fake_runner(responses: dict[str, str | None]):  # type: ignore[no-untyped-def]
    def runner(args: Sequence[str], _cwd: Path) -> str | None:
        return responses.get(args[0] if args else "")

    return runner


def _init_repo(root: Path) -> None:
    """A repository with one commit, isolated from the developer's git config."""
    environment = {
        "GIT_AUTHOR_NAME": "C Audit Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "C Audit Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
        "GIT_CONFIG_GLOBAL": str(root / ".gitconfig-absent"),
        "GIT_CONFIG_SYSTEM": str(root / ".gitconfig-absent"),
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
    }
    for args in (
        ["init", "--quiet", "--initial-branch=main"],
        ["add", "-A"],
        ["commit", "--quiet", "-m", "initial"],
    ):
        subprocess.run(["git", *args], cwd=root, env=environment, check=True, capture_output=True)


def test_a_clean_repository_is_pinned() -> None:
    revision = resolve_revision(
        Path("/anywhere"),
        runner=_fake_runner({"rev-parse": f"{HEAD_SHA}\n", "status": ""}),
    )
    assert revision.revision == HEAD_SHA
    assert not revision.dirty
    assert revision.limitation is None
    assert revision.is_pinned
    assert revision.describe() == HEAD_SHA[:12]


def test_a_dirty_tree_is_pinned_and_flagged() -> None:
    revision = resolve_revision(
        Path("/anywhere"),
        runner=_fake_runner({"rev-parse": f"{HEAD_SHA}\n", "status": " M src/a.c\n"}),
    )
    assert revision.revision == HEAD_SHA
    assert revision.dirty
    assert revision.limitation is not None
    assert revision.limitation.kind is LimitationKind.REVISION_UNAVAILABLE
    assert "uncommitted changes" in revision.limitation.detail
    assert "(dirty)" in revision.describe()


def test_a_repository_with_no_commits_is_not_pinned() -> None:
    def runner(args: Sequence[str], _cwd: Path) -> str | None:
        if args[0] == "rev-parse" and args[1] == "--show-toplevel":
            return "/anywhere\n"
        if args[0] == "rev-parse":
            return None  # `git rev-parse HEAD` fails before the first commit
        return ""

    revision = resolve_revision(Path("/anywhere"), runner=runner)
    assert revision.revision == UNKNOWN_REVISION
    assert revision.limitation is not None
    assert "no resolvable HEAD" in revision.limitation.detail


def test_a_directory_outside_any_repository_is_not_pinned() -> None:
    revision = resolve_revision(Path("/anywhere"), runner=_fake_runner({}))
    assert revision.revision == UNKNOWN_REVISION
    assert not revision.dirty
    assert revision.limitation is not None
    assert revision.limitation.kind is LimitationKind.REVISION_UNAVAILABLE
    assert "cannot claim reproducibility" in revision.limitation.detail
    assert revision.describe() == "unknown revision"


@_needs_git
def test_a_git_fixture_with_an_uncommitted_change(tmp_path: Path) -> None:
    """T-05-18: real git, real commit, real edit — dirty and pinned to HEAD."""
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    _init_repo(root)

    clean = resolve_revision(root)
    assert clean.is_pinned
    assert len(clean.revision) == 40
    assert not clean.dirty

    (root / "src" / "a.c").write_text("void a(void){ /* edited */ }\n", encoding="utf-8")
    dirty = resolve_revision(root)
    assert dirty.revision == clean.revision
    assert dirty.dirty


@_needs_git
def test_the_plan_carries_the_revision(tmp_path: Path) -> None:
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    database = write_compdb(root, [compdb_entry(root, str(root / "src/a.c"))])
    _init_repo(root)

    plan = load_scan_plan(root, database, intake_config())
    assert len(plan.revision) == 40
    assert plan.is_reproducible


def test_a_plain_directory_yields_unknown_and_a_limitation(tmp_path: Path) -> None:
    """T-05-19: no `.git`, no crash — a plan that admits what it cannot claim."""
    root = write_tree(tmp_path, {"src/a.c": "void a(void){}\n"})
    database = write_compdb(root, [compdb_entry(root, str(root / "src/a.c"))])

    plan = load_scan_plan(
        root,
        database,
        intake_config(),
        git_runner=lambda _args, _cwd: None,
    )
    assert plan.revision == UNKNOWN_REVISION
    assert not plan.dirty
    assert not plan.is_reproducible
    assert LimitationKind.REVISION_UNAVAILABLE.value in plan.limitation_kinds()
    assert [unit.file.name for unit in plan.units] == ["a.c"]


def test_revision_info_defaults_are_conservative() -> None:
    info = RevisionInfo(revision=UNKNOWN_REVISION, dirty=False)
    assert info.git_root is None
    assert info.limitation is None
    assert not info.is_pinned

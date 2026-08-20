"""Pinning the revision a scan describes.

A report that cannot name the revision it was produced from cannot be
reproduced, and a report produced from a dirty tree describes code that exists
on exactly one machine. Neither is a reason to refuse to run — but both are
reasons the report must say so out loud, so both are recorded rather than
smoothed over.

The revision is resolved **once**, before any file is read. Resolving it later,
or per file, would let a commit land mid-scan and produce a report that pins a
revision none of its evidence came from.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from caudit.intake.plan import UNKNOWN_REVISION
from caudit.logging import get_logger
from caudit.model.finding import Limitation, LimitationKind

__all__ = ["GitRunner", "RevisionInfo", "resolve_revision"]

log = get_logger(__name__)

#: ``(args, cwd) -> stdout``, or ``None`` when the command failed. Injected so
#: the default test suite never needs git installed.
GitRunner = Callable[[Sequence[str], Path], str | None]

#: git is local and fast, but a corrupt repository can make it hang.
_TIMEOUT_SECONDS = 30


def _git_environment() -> dict[str, str]:
    """The parent environment with ``GIT_*`` stripped.

    An inherited ``GIT_DIR`` or ``GIT_WORK_TREE`` — set by a wrapping hook or
    another tool — would point git at a different repository and pin the wrong
    revision without any visible error.
    """
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def _run_git(args: Sequence[str], cwd: Path) -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        # Fixed argv, shell=False: nothing here is interpolated from user input
        # beyond the working directory.
        completed = subprocess.run(
            [executable, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git %s failed in %s: %s", " ".join(args), cwd, exc)
        return None
    if completed.returncode != 0:
        log.debug("git %s exited %d: %s", " ".join(args), completed.returncode, completed.stderr)
        return None
    return completed.stdout


@dataclass(frozen=True)
class RevisionInfo:
    """The scanned revision, and whether the tree matches it."""

    #: Full 40-character sha, or :data:`UNKNOWN_REVISION`.
    revision: str
    #: True when tracked files differ from HEAD, or untracked files exist.
    dirty: bool
    #: The git work tree root, when the scan root is inside one. Kept separate
    #: from the scan root: paths stay relative to the directory the user named,
    #: even when that is a subdirectory of the repository.
    git_root: Path | None = None
    limitation: Limitation | None = None

    @property
    def is_pinned(self) -> bool:
        return self.revision != UNKNOWN_REVISION

    def describe(self) -> str:
        if not self.is_pinned:
            return "unknown revision"
        return f"{self.revision[:12]}{' (dirty)' if self.dirty else ''}"


def resolve_revision(root: Path, *, runner: GitRunner = _run_git) -> RevisionInfo:
    """Resolve ``root``'s revision, or record why it could not be pinned.

    Never raises and never aborts: a directory that is not a repository is a
    perfectly reasonable thing to scan. It just cannot claim reproducibility,
    and :attr:`RevisionInfo.limitation` says so.
    """
    root = root.resolve()
    top_level = runner(["rev-parse", "--show-toplevel"], root)
    if top_level is None or not top_level.strip():
        return RevisionInfo(
            revision=UNKNOWN_REVISION,
            dirty=False,
            limitation=Limitation(
                kind=LimitationKind.REVISION_UNAVAILABLE,
                detail=(
                    f"{root} is not inside a git work tree, so the scanned revision "
                    "cannot be pinned and this report cannot claim reproducibility"
                ),
                affects=str(root),
            ),
        )

    git_root = Path(top_level.strip())
    head = runner(["rev-parse", "HEAD"], root)
    if head is None or not head.strip():
        return RevisionInfo(
            revision=UNKNOWN_REVISION,
            dirty=_is_dirty(runner, root),
            git_root=git_root,
            limitation=Limitation(
                kind=LimitationKind.REVISION_UNAVAILABLE,
                detail=(
                    f"{git_root} is a git work tree with no resolvable HEAD (no commits "
                    "yet, or a broken reference), so the revision cannot be pinned"
                ),
                affects=str(git_root),
            ),
        )

    dirty = _is_dirty(runner, root)
    limitation = None
    if dirty:
        limitation = Limitation(
            kind=LimitationKind.REVISION_UNAVAILABLE,
            detail=(
                f"the working tree at {git_root} has uncommitted changes; the scanned "
                f"source does not match commit {head.strip()[:12]} exactly"
            ),
            affects=str(git_root),
        )
    return RevisionInfo(
        revision=head.strip(), dirty=dirty, git_root=git_root, limitation=limitation
    )


def _is_dirty(runner: GitRunner, root: Path) -> bool:
    """Tracked modifications or untracked files both count.

    Untracked files are included deliberately: an untracked header on the
    include path changes what every unit compiles to.
    """
    status = runner(["status", "--porcelain", "--untracked-files=normal"], root)
    if status is None:
        return False
    return bool(status.strip())

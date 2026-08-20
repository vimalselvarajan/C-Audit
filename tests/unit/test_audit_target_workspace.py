"""Housekeeping contract for user-controlled repositories under audit-targets."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
PRE_COMMIT = ROOT / ".pre-commit-config.yaml"

AUDIT_TARGET_PROBES = (
    "audit-targets/example/.git/HEAD",
    "audit-targets/example/build/compile_commands.json",
    "audit-targets/example/src/main.cpp",
)


@pytest.mark.parametrize("relative", AUDIT_TARGET_PROBES)
def test_audit_target_contents_are_gitignored(relative: str) -> None:
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", "--no-index", relative],
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0, f"{relative} is not ignored by the parent repository"


def test_make_guard_rejects_a_forcibly_staged_audit_target(tmp_path: Path) -> None:
    if shutil.which("make") is None:  # pragma: no cover
        pytest.skip("make is not on PATH")

    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    relative = "audit-targets/example/src/main.cpp"
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text("int main() { return 0; }\n", encoding="utf-8")
    subprocess.run(["git", "add", "--force", relative], cwd=tmp_path, check=True)

    result = subprocess.run(
        ["make", "-f", str(MAKEFILE), "guard"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert relative in result.stdout


def _hooks() -> dict[str, dict[str, Any]]:
    document = cast(
        dict[str, Any],
        yaml.safe_load(PRE_COMMIT.read_text(encoding="utf-8")),
    )
    repositories = cast(list[dict[str, Any]], document["repos"])
    hooks: dict[str, dict[str, Any]] = {}
    for repository in repositories:
        for hook in cast(list[dict[str, Any]], repository["hooks"]):
            hooks[cast(str, hook["id"])] = hook
    return hooks


@pytest.mark.parametrize(
    "hook_id",
    ("ruff", "ruff-format", "trailing-whitespace", "end-of-file-fixer"),
)
def test_mutating_hooks_exclude_audit_targets(hook_id: str) -> None:
    hook = _hooks()[hook_id]
    exclude = cast(str, hook.get("exclude", ""))
    assert exclude
    assert re.search(exclude, "audit-targets/example/src/main.py")


def test_nested_repository_hook_covers_both_workspace_types() -> None:
    hook = _hooks()["no-nested-repos"]
    files = cast(str, hook["files"])
    assert re.search(files, "audit-targets/example/src/main.cpp")
    assert re.search(files, "inspiration_repos/example/src/main.cpp")
    assert not re.search(files, "caudit-report/example/report.md")

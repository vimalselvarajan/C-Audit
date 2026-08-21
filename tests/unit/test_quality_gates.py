"""Part 01 quality-gate tests: T-01-15.

`make check` has to fail independently on a lint error, a type error, and
coverage below the floor — and CI has to invoke the same target, or a green
local run means nothing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
VENV_BIN = REPO_ROOT / ".venv" / "bin"


def _tool(name: str) -> list[str]:
    candidate = VENV_BIN / name
    if candidate.exists():
        return [str(candidate)]
    return [sys.executable, "-m", name]


def test_ruff_fails_on_a_lint_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("import os\n\n\ndef f():\n    return 1\n", encoding="utf-8")
    result = subprocess.run(
        [*_tool("ruff"), "check", "--isolated", "--select", "F", str(bad)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode != 0
    assert "F401" in result.stdout


def test_mypy_fails_on_a_type_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad_types.py"
    bad.write_text(
        'def add(a: int, b: int) -> int:\n    return a + b\n\nadd("x", 1)\n', encoding="utf-8"
    )
    result = subprocess.run(
        [
            *_tool("mypy"),
            "--strict",
            "--no-incremental",
            "--cache-dir",
            str(tmp_path / ".mypy"),
            str(bad),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode != 0
    assert "arg-type" in result.stdout


def test_coverage_fails_below_the_floor(tmp_path: Path) -> None:
    module = tmp_path / "partial.py"
    module.write_text(
        "def covered() -> int:\n"
        "    return 1\n"
        "\n"
        "def uncovered() -> int:\n"
        "    x = 1\n"
        "    y = 2\n"
        "    z = 3\n"
        "    return x + y + z\n",
        encoding="utf-8",
    )
    driver = tmp_path / "drive.py"
    driver.write_text("import partial\npartial.covered()\n", encoding="utf-8")

    env_run = subprocess.run(
        [*_tool("coverage"), "run", "--source", str(tmp_path), str(driver)],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert env_run.returncode == 0, env_run.stderr

    report = subprocess.run(
        [*_tool("coverage"), "report", "--fail-under", "90"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert report.returncode != 0, "coverage below the floor must fail the gate"


def test_pyproject_sets_the_coverage_floor() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r"^fail_under\s*=\s*90\s*$", text, re.MULTILINE)


def test_make_check_runs_all_three_gates() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    check_line = next(line for line in makefile.splitlines() if line.startswith("check:"))
    for target in ("lint", "typecheck", "schema-check", "docs-check", "architecture-check", "test"):
        assert target in check_line, f"`make check` must run `{target}`"


def test_ci_invokes_the_same_make_target() -> None:
    """Local and CI verdicts cannot diverge if they run one command."""
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    commands = [
        step.get("run")
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if "run" in step
    ]
    assert "make check" in commands


@pytest.mark.parametrize("marker", ["needs_clang", "needs_network", "slow"])
def test_markers_are_deselected_by_default(marker: str) -> None:
    """The default suite must stay offline and toolchain-free."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    addopts = next(line for line in text.splitlines() if line.startswith("addopts"))
    assert f"not {marker}" in addopts
    assert f"{marker}:" in text, f"marker {marker} must be registered"

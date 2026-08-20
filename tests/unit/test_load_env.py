"""Part 01 housekeeping test: T-01-17.

``tools/load-env.sh`` is the whole of this project's ``.env`` support. caudit
itself has no dotenv dependency and no ``load_dotenv`` call: the shell exports
the values and :mod:`caudit.llm.gemini` reads the environment at call time, so
this script is the only thing standing between a ``.env`` file and a working
key. Nothing else in the suite executes it.

Like T-01-16, this runs the shipped file rather than a copy of its logic. The
script resolves the repository root from its own location, so the fixture
reproduces the ``tools/`` layout inside ``tmp_path`` and the real resolution
code is what gets exercised.

Three of these guard failure modes that are worse than not working:

* **Executing instead of sourcing must not kill the shell.** The detection is
  bash-only because ``$0`` equals ``BASH_SOURCE[0]`` in a sourced *non*-bash
  shell too, and acting on that false positive would run ``exit`` in the user's
  interactive session.
* **The key value is never printed.** The script reports which variable is set,
  by name. Echoing the value would put a live credential in scrollback.
* **No ``_caudit_*`` variable outlives the call.** A sourced script shares the
  caller's shell, so its locals are the user's globals.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "load-env.sh"
TEMPLATE = REPO / ".env.example"

#: Distinctive enough that a substring search for it cannot match by accident.
FAKE_KEY = "fake-key-do-not-use-4c1f9e2b"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A throwaway repo root holding the real script at its real relative path."""
    if shutil.which("bash") is None:  # pragma: no cover - bash is a dev dependency
        pytest.skip("bash is not on PATH")
    (tmp_path / "tools").mkdir()
    shutil.copy(SCRIPT, tmp_path / "tools" / "load-env.sh")
    shutil.copy(TEMPLATE, tmp_path / ".env.example")
    return tmp_path


def _bash(workspace: Path, script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_env(workspace: Path, body: str) -> None:
    (workspace / ".env").write_text(body, encoding="utf-8")


def test_sourcing_exports_the_key(workspace: Path) -> None:
    """T-01-17: the happy path -- the variable reaches the calling shell."""
    _write_env(workspace, f"GEMINI_API_KEY={FAKE_KEY}\n")
    result = _bash(workspace, 'source tools/load-env.sh; echo "exported=$GEMINI_API_KEY"')
    assert result.returncode == 0, result.stderr
    assert f"exported={FAKE_KEY}" in result.stdout


def test_sourcing_works_from_a_subdirectory(workspace: Path) -> None:
    """T-01-17: the root is resolved from the script, not from the caller's cwd."""
    _write_env(workspace, f"GEMINI_API_KEY={FAKE_KEY}\n")
    (workspace / "sub" / "deeper").mkdir(parents=True)
    result = _bash(
        workspace,
        'cd sub/deeper && source ../../tools/load-env.sh; echo "exported=$GEMINI_API_KEY"',
    )
    assert result.returncode == 0, result.stderr
    assert f"exported={FAKE_KEY}" in result.stdout


def test_the_google_fallback_is_accepted(workspace: Path) -> None:
    """T-01-17: `GOOGLE_API_KEY` is the fallback gemini.py's API_KEY_ENV names."""
    _write_env(workspace, f"GOOGLE_API_KEY={FAKE_KEY}\n")
    result = _bash(workspace, "source tools/load-env.sh")
    assert result.returncode == 0, result.stderr
    assert "GOOGLE_API_KEY is set" in result.stdout


def test_the_key_value_is_never_printed(workspace: Path) -> None:
    """T-01-17: the report names the variable; the value stays out of scrollback."""
    _write_env(workspace, f"GEMINI_API_KEY={FAKE_KEY}\n")
    result = _bash(workspace, "source tools/load-env.sh")
    assert FAKE_KEY not in result.stdout
    assert FAKE_KEY not in result.stderr
    assert "GEMINI_API_KEY is set" in result.stdout


def test_no_helper_variable_outlives_the_call(workspace: Path) -> None:
    """T-01-17: a sourced script's locals are the caller's globals."""
    _write_env(workspace, f"GEMINI_API_KEY={FAKE_KEY}\n")
    result = _bash(
        workspace,
        "source tools/load-env.sh >/dev/null 2>&1; "
        'printf "leftovers=%s\\n" "$(set | grep -c \'^_caudit\' || true)"',
    )
    assert "leftovers=0" in result.stdout, f"helper variables leaked: {result.stdout}"


def test_a_missing_env_file_points_at_the_template(workspace: Path) -> None:
    """T-01-17: the failure a first-time user actually hits."""
    result = _bash(workspace, "source tools/load-env.sh")
    assert result.returncode != 0
    assert "no .env" in result.stderr
    assert ".env.example" in result.stderr


def test_the_committed_template_alone_is_reported_as_incomplete(workspace: Path) -> None:
    """T-01-17: copying `.env.example` and forgetting to fill it in is not success.

    The template ships with an empty ``GEMINI_API_KEY=``, so this is the state
    every user passes through. Reporting it as loaded would send them on to a
    scan that fails much later with a less obvious message.
    """
    shutil.copy(workspace / ".env.example", workspace / ".env")
    result = _bash(workspace, "source tools/load-env.sh")
    assert result.returncode != 0
    assert "neither GEMINI_API_KEY nor GOOGLE_API_KEY is set" in result.stderr


def test_a_malformed_env_file_is_reported(workspace: Path) -> None:
    """T-01-17: `.` executes the file, so a syntax error must not pass silently."""
    _write_env(workspace, "GEMINI_API_KEY='unterminated\n")
    result = _bash(workspace, "source tools/load-env.sh")
    assert result.returncode != 0
    assert "not valid shell" in result.stderr


def test_executing_instead_of_sourcing_is_reported(workspace: Path) -> None:
    """T-01-17: a subprocess that sets a variable and exits has done nothing."""
    _write_env(workspace, f"GEMINI_API_KEY={FAKE_KEY}\n")
    result = subprocess.run(
        ["bash", "tools/load-env.sh"],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 64
    assert "must be sourced" in result.stderr
    assert FAKE_KEY not in result.stdout


def test_the_script_carries_no_shebang_and_is_not_executable() -> None:
    """T-01-17: both would advertise a way of running it that does not work."""
    assert not SCRIPT.read_text(encoding="utf-8").startswith("#!")
    assert not SCRIPT.stat().st_mode & 0o111, "load-env.sh is executable but must be sourced"


def test_allexport_is_restored_to_however_the_caller_had_it(workspace: Path) -> None:
    """T-01-17: `set +a` must not switch off an option the user turned on.

    With ``allexport`` already set, every later assignment in that shell is
    meant to be exported. A helper that clears it silently changes the
    behaviour of everything the user runs afterwards.
    """
    _write_env(workspace, f"GEMINI_API_KEY={FAKE_KEY}\n")
    on = _bash(
        workspace,
        'set -a; source tools/load-env.sh >/dev/null 2>&1; case $- in *a*) echo "allexport=on";; '
        '*) echo "allexport=off";; esac',
    )
    assert "allexport=on" in on.stdout

    off = _bash(
        workspace,
        'set +a; source tools/load-env.sh >/dev/null 2>&1; case $- in *a*) echo "allexport=on";; '
        '*) echo "allexport=off";; esac',
    )
    assert "allexport=off" in off.stdout

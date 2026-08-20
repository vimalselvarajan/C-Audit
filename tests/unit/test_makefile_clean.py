"""Part 01 housekeeping test: T-01-16.

``UNTRACKABLE`` and ``GENERATED`` in the Makefile are one decision spelled
twice. The first says which paths must never enter the index; the second says
which of them ``make clean`` deletes. They drifted once already — ``clean``
removed five of the nine categories ``UNTRACKABLE`` names, so ``caudit-report/``
and ``.hypothesis/`` survived a clean indefinitely — and nothing failed.

``UNTRACKABLE`` names three kinds of path, and only the first is deletable:
generated output, the upstream clones, and ``.env``. The drift that matters for
the third is the reverse of the original one — not a category ``clean`` forgot,
but a category ``clean`` might one day remember. Deleting the API key file is
why ``.env`` appears in ``EXEMPT_FROM_CLEAN`` and in ``PRESERVED_PROBES``.

This is the same shape of check as T-09-22, which holds the ``retrieval.variant``
``Literal`` against the enum of the same name: two spellings, one dependency
direction, and no runtime path that would notice them disagree.

The corpus below is used twice over. Every probe marked generated must be
*removed* by the real recipe, and every top-level alternative of ``UNTRACKABLE``
must be *exercised* by at least one probe — so adding a category to the regex
without teaching ``clean`` about it fails here rather than in six months.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

MAKEFILE = Path(__file__).resolve().parents[2] / "Makefile"

#: Untrackable, but deliberately *not* deleted by `clean`. The clones are
#: read-only reference material with their own upstream remotes, and re-cloning
#: four repositories is not a cost a clean target gets to impose. ``.env`` is
#: exempt for a stronger reason than cost: it holds the API key, so no later run
#: can regenerate it at any price, and a `clean` that deleted it would destroy
#: the one thing in this repository that is not reproducible from the source.
EXEMPT_FROM_CLEAN = ("^inspiration_repos/", "^audit-targets/", "^\\.env$")

#: Probes `clean` must delete, with the survivors that prove it stopped where it
#: was told to. Relative POSIX paths; directories are created via their files.
#:
#: The five ``caudit-*`` directories are one *alternative* in ``UNTRACKABLE``, so
#: the coverage test below is satisfied by any one of them. They are all listed
#: anyway: without a probe each, adding a name to the group's alternation while
#: forgetting it in ``GENERATED`` leaves that directory surviving a clean and
#: nothing fails — the same within-group drift that left ``caudit-report/``
#: behind before, one level down.
GENERATED_PROBES = (
    ".pytest_cache/CACHEDIR.TAG",
    ".mypy_cache/3.12/builtins.data.json",
    ".ruff_cache/content",
    ".hypothesis/examples/deadbeef",
    ".coverage",
    ".coverage.host.1234",
    "htmlcov/index.html",
    "caudit-report/report.md",
    "caudit-eval/metrics.json",
    "caudit-pairs/example-cve-2021-0000/vulnerable/.git/HEAD",
    "caudit-ablation/grid.json",
    "caudit-calibration/bins.json",
    "build/lib/caudit/__init__.py",
    "dist/caudit-0.1.0.tar.gz",
    "caudit.egg-info/PKG-INFO",
    "src/caudit.egg-info/SOURCES.txt",
    "src/caudit/__pycache__/model.cpython-312.pyc",
    "tests/unit/__pycache__/test_thing.cpython-312-pytest-8.4.2.pyc",
    "stray.pyo",
)

#: Probes `clean` must leave alone. `.venv/` belongs to `bootstrap`, the clones
#: belong to upstream, `.env` holds the API key, and the rest is the repository
#: itself.
PRESERVED_PROBES = (
    ".venv/lib/python3.12/site-packages/pkg/__pycache__/mod.cpython-312.pyc",
    ".venv/bin/python",
    "audit-targets/Combat-Chess/.git/HEAD",
    "audit-targets/Combat-Chess/build/compile_commands.json",
    "audit-targets/Combat-Chess/tools/__pycache__/helper.cpython-312.pyc",
    "inspiration_repos/benchmarks/RepoAudit/src/__pycache__/agent.cpython-312.pyc",
    "inspiration_repos/SWE-CI/config.toml",
    ".env",
    ".env.example",
    "src/caudit/model/finding.py",
    "Makefile",
    "README.md",
)


def _assignment(name: str) -> str:
    """The right-hand side of a ``NAME := ...`` assignment, joining continuations."""
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\s*:=\s*((?:.*\\\n)*.*)$", text, re.MULTILINE)
    assert match is not None, f"{name} is no longer assigned in the Makefile"
    return match.group(1).replace("\\\n", " ")


def _untrackable() -> str:
    """The guard regex, with make's ``$$`` unescaped back to a regex ``$``."""
    return _assignment("UNTRACKABLE").strip().replace("$$", "$")


def _alternatives(pattern: str) -> list[str]:
    """Split on top-level ``|`` only, so ``(pytest|mypy|ruff)`` stays one branch."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    escaped = False
    for char in pattern:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == "|" and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [part for part in parts if part]


def _seed(root: Path, relative_paths: tuple[str, ...]) -> None:
    for relative in relative_paths:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("probe\n", encoding="utf-8")


@pytest.fixture
def cleaned(tmp_path: Path) -> Path:
    """A seeded tree with the repository's real ``clean`` recipe run over it.

    ``clean`` is entirely CWD-relative — ``rm -rf $(GENERATED)`` and two
    ``find .`` calls — so running the real Makefile against a temporary
    directory exercises the shipped recipe rather than a copy of it.
    """
    if shutil.which("make") is None:  # pragma: no cover - make is a dev dependency
        pytest.skip("make is not on PATH")
    _seed(tmp_path, GENERATED_PROBES)
    _seed(tmp_path, PRESERVED_PROBES)
    result = subprocess.run(
        ["make", "-f", str(MAKEFILE), "clean"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"make clean failed:\n{result.stdout}\n{result.stderr}"
    return tmp_path


def test_clean_removes_every_generated_probe(cleaned: Path) -> None:
    """T-01-16: `clean` deletes every category the guard calls untrackable."""
    survived = [probe for probe in GENERATED_PROBES if (cleaned / probe).exists()]
    assert not survived, f"make clean left generated output behind: {survived}"


def test_clean_preserves_the_venv_and_independent_clones(cleaned: Path) -> None:
    """T-01-16: and stops there. A clean that re-clones upstream is not a clean."""
    missing = [probe for probe in PRESERVED_PROBES if not (cleaned / probe).exists()]
    assert not missing, f"make clean deleted paths it must never touch: {missing}"


def test_every_untrackable_category_is_covered_by_clean() -> None:
    """T-01-16: the drift guard proper — a new guard category needs a probe.

    Without this, adding ``^\\.tox/`` to ``UNTRACKABLE`` would leave ``clean``
    silently one category behind, which is exactly how the target came to be
    missing four of them.
    """
    for alternative in _alternatives(_untrackable()):
        if alternative in EXEMPT_FROM_CLEAN:
            continue
        matcher = re.compile(alternative)
        assert any(matcher.search(probe) for probe in GENERATED_PROBES), (
            f"UNTRACKABLE names {alternative!r} but no probe in GENERATED_PROBES "
            "exercises it, so nothing here checks that `make clean` removes it"
        )


def test_the_exempt_category_is_still_named_by_the_guard() -> None:
    """T-01-16: an exemption for a category the guard dropped is dead weight."""
    alternatives = _alternatives(_untrackable())
    for exempt in EXEMPT_FROM_CLEAN:
        assert exempt in alternatives, (
            f"{exempt!r} is exempted from `make clean` but UNTRACKABLE no longer "
            "names it; drop the exemption or restore the guard entry"
        )


def test_clean_is_discoverable_from_make_help() -> None:
    """T-01-16: a target with no `## ` docstring never appears in `make help`."""
    text = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^clean:.*## \S", text, re.MULTILINE), (
        "`clean:` has no `## ` help text, so `make help` does not list it"
    )

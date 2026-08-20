"""Part 06 regression: a compilation database with relative arguments still indexes.

Clang reports a path the way it appeared on its command line. A compilation
database whose ``arguments`` name the source relatively — which is what
``make``-based and Bear-generated databases produce — therefore gives libclang
relative names, and those are relative to the unit's build directory, because
that is what ``-working-directory`` told Clang.

Resolving them against the *process* working directory instead emptied the
index completely and silently. Every cursor resolved to a path outside
``repo_root``, ``_walk`` skipped it and its children, and the parse still
reported ``parsed=1, failed=0``. What came out was an index that listed the
file in ``indexed_files`` and held no symbols, no calls and no types — so
retrieval found no containing function, every candidate reached the model
carrying only its own line, and the model correctly declined to confirm
anything it could not see. On the mini suite that took the adjudicated macro-F2
from 0.6667 to 0.1667 with no other cause.

Nothing caught it because the fixtures that exercise indexing write absolute
paths into their databases, and because the failure mode is an empty result
rather than an error: there is no exception, no limitation and no parse
failure to notice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.index.store import build_index
from caudit.intake import load_scan_plan

SOURCE = """\
#include <stddef.h>

struct holder {
    char slot[8];
};

static void inner(struct holder *h)
{
    h->slot[0] = 'x';
}

void outer(struct holder *h)
{
    inner(h);
}
"""


def _project(tmp_path: Path, *, absolute: bool) -> tuple[Path, Path]:
    """A one-unit project whose database names the source either way."""
    root = tmp_path / ("abs" if absolute else "rel")
    (root / "src").mkdir(parents=True)
    (root / "src" / "unit.c").write_text(SOURCE, encoding="utf-8")

    named = str(root / "src" / "unit.c") if absolute else "src/unit.c"
    database = root / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(root / "src" / "unit.c"),
                    "arguments": ["clang", "-std=c11", "-c", named, "-o", "unit.o"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return root, database


def _index_symbols(root: Path, database: Path, resource_dir: str) -> list[str]:
    base = Config()
    config = Config.model_validate(
        {
            **base.model_dump(),
            "index": {**base.index.model_dump(), "resource_dir": resource_dir},
            "intake": {**base.intake.model_dump(), "allow_partial_coverage": True},
        }
    )
    plan = load_scan_plan(root, database, config, git_runner=lambda _a, _c: None)
    index = build_index(plan, config)
    return sorted(symbol.name for symbol in index.symbols_in("src/unit.c"))


@pytest.mark.needs_clang
def test_relative_and_absolute_databases_produce_the_same_index(
    tmp_path: Path, clang_resource_dir: str
) -> None:
    """The regression proper: how the build names a file is not a fact about it.

    Asserted as an equality against the absolute-path database rather than
    against a hardcoded symbol list, so the test says what it means — the two
    spellings describe one translation unit and must index identically.
    """
    absolute_root, absolute_db = _project(tmp_path, absolute=True)
    relative_root, relative_db = _project(tmp_path, absolute=False)

    from_absolute = _index_symbols(absolute_root, absolute_db, clang_resource_dir)
    from_relative = _index_symbols(relative_root, relative_db, clang_resource_dir)

    assert from_absolute, "the absolute-path control indexed nothing; the fixture is broken"
    assert from_relative == from_absolute, (
        "a compilation database with relative arguments indexed differently from "
        "the same unit named absolutely. An empty result here is the silent-empty-"
        f"index bug: absolute={from_absolute} relative={from_relative}"
    )


@pytest.mark.needs_clang
def test_the_containing_function_resolves_from_a_relative_database(
    tmp_path: Path, clang_resource_dir: str
) -> None:
    """What retrieval actually asks for, and what the model goes without.

    ``enclosing_function`` returning ``None`` is the exact call whose failure
    produced the ``no_evidence_expansion`` limitation on every candidate.
    """
    root, database = _project(tmp_path, absolute=False)
    base = Config()
    config = Config.model_validate(
        {
            **base.model_dump(),
            "index": {**base.index.model_dump(), "resource_dir": clang_resource_dir},
            "intake": {**base.intake.model_dump(), "allow_partial_coverage": True},
        }
    )
    plan = load_scan_plan(root, database, config, git_runner=lambda _a, _c: None)
    index = build_index(plan, config)

    enclosing = index.enclosing_function("src/unit.c", 9)
    assert enclosing is not None, "no containing function; retrieval would have nothing to expand"
    assert enclosing.name == "inner"

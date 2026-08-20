"""Part 06 blind-spot tests: T-06-09 … T-06-12, and AC-06-11.

Every test here is about the same failure mode: a run that quietly knows less
than it appears to. A file that did not parse produces no findings, which reads
exactly like a file with no bugs, so each of these asserts that the gap was
recorded and that it names the file.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from caudit.index import build_index
from caudit.index.parser import ParseRequest, ParseResult, ParseStatus, parse_request
from caudit.index.store import UnitStatus
from caudit.intake import load_scan_plan
from caudit.model.finding import LimitationKind
from tests.conftest import cpp_fixture, index_config
from tests.integration.test_index_symbols import build

pytestmark = pytest.mark.needs_libclang


def slow_for_syntax_error(request: ParseRequest) -> ParseResult:
    """Parse normally, except for one file that never finishes.

    Module level, because the worker pool pickles this by name to send it to a
    spawned process. Sleeping is how a parse that overruns is simulated
    deterministically; making libclang itself take minutes would need a fixture
    nobody could review.
    """
    if request.file.name == "syntax_error.c":
        time.sleep(60)
    return parse_request(request)


def test_inline_assembly_is_recorded_against_its_function(tmp_path: Path) -> None:
    """T-06-09: the limitation names the file *and* the symbol (AC-06-11)."""
    index = build(tmp_path, "indirect")
    recorded = [item for item in index.limitations() if item.kind is LimitationKind.INLINE_ASSEMBLY]
    assert len(recorded) == 1
    assert recorded[0].affects == "indirect.c::barrier"
    assert "opaque to the index" in recorded[0].detail


def test_a_missing_header_excludes_the_unit_and_names_the_header(tmp_path: Path) -> None:
    """T-06-10: the run continues; the header is named, not guessed at."""
    index = build(tmp_path, "broken")

    unit = index.unit("missing_header.c")
    assert unit is not None
    assert unit.status is UnitStatus.FAILED
    assert not index.is_indexed("missing_header.c")
    assert index.symbols_named("configured_limit") == []

    failures = [item for item in index.limitations() if item.kind is LimitationKind.PARSE_FAILED]
    detail = next(item.detail for item in failures if item.affects == "missing_header.c")
    assert "'generated_config.h'" in detail
    assert "C Audit does not invent include paths" in detail

    # One broken unit does not cost the run the others.
    assert index.is_indexed("healthy.c")
    assert index.symbols_named("healthy")


def test_a_syntax_error_is_excluded_with_its_first_error(tmp_path: Path) -> None:
    """T-06-11: the message a developer needs, not a bare "failed"."""
    index = build(tmp_path, "broken")
    failures = [item for item in index.limitations() if item.kind is LimitationKind.PARSE_FAILED]
    detail = next(item.detail for item in failures if item.affects == "syntax_error.c")
    assert "expected '}'" in detail
    assert "syntax_error.c" in detail
    # The path is repository-relative: an absolute build path would put the
    # machine that ran the scan into the report.
    assert str(tmp_path) not in detail


def test_a_builtin_header_failure_says_how_to_fix_it(tmp_path: Path) -> None:
    """The wheel ships no resource directory; the stop has to say so.

    Without this the first run on any real repository fails with `'stddef.h'
    file not found` and no path forward.
    """
    root = tmp_path / "sysheaders"
    root.mkdir()
    (root / "main.c").write_text("#include <stddef.h>\nint main(void){return 0;}\n")
    database = root / "compile_commands.json"
    database.write_text(
        f'[{{"directory": "{root}", "file": "{root / "main.c"}", '
        f'"arguments": ["clang", "-c", "{root / "main.c"}"]}}]'
    )
    config = index_config()
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    index = build_index(plan, config)

    kinds = {item.kind for item in index.limitations()}
    assert LimitationKind.TOOLCHAIN_UNAVAILABLE in kinds
    detail = next(
        item.detail
        for item in index.limitations()
        if item.kind is LimitationKind.TOOLCHAIN_UNAVAILABLE
    )
    assert "index.resource_dir" in detail
    assert "clang -print-resource-dir" in detail


def test_a_unit_that_overruns_its_timeout_is_named_and_the_others_survive(
    tmp_path: Path,
) -> None:
    """T-06-12: the timeout is a limitation, not a silent skip.

    Runs through the real worker pool — the timeout only exists there, because
    nothing in this process can interrupt a libclang call.
    """
    root, database = cpp_fixture(tmp_path, "broken")
    config = index_config(in_process=False, jobs=3, per_tu_timeout_seconds=1.0)
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)

    index = build_index(plan, config, execute=slow_for_syntax_error)

    timed_out = index.unit("syntax_error.c")
    assert timed_out is not None
    assert timed_out.status is UnitStatus.TIMED_OUT
    assert index.stats.timed_out == 1

    detail = next(
        item.detail
        for item in index.limitations()
        if item.affects == "syntax_error.c" and "still parsing" in item.detail
    )
    assert "index.per_tu_timeout_seconds" in detail

    # The other units were indexed regardless.
    assert index.is_indexed("healthy.c")
    assert index.symbols_named("healthy")


def test_only_a_successful_parse_is_cached(tmp_path: Path) -> None:
    """A timeout or a failure is retried next run; a success is not.

    Deliberate, and not merely conservative. A unit can fail for a reason that
    lies outside its hashed inputs — a generated header that has not been built
    yet — and caching that verdict would keep reporting a missing header after
    the user generated it.
    """
    root, database = cpp_fixture(tmp_path, "broken")
    cache = tmp_path / "cache"
    config = index_config(in_process=False, jobs=3, per_tu_timeout_seconds=1.0)
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)

    first = build_index(plan, config, cache_dir=cache, execute=slow_for_syntax_error)
    assert first.stats.timed_out == 1

    second = build_index(plan, config, cache_dir=cache)
    assert second.stats.reused == 1, "only healthy.c had a result worth keeping"
    assert second.stats.failed == 2, "the timed-out and broken units are tried again"
    assert second.unit("syntax_error.c") is not None


def test_every_limitation_names_a_file(tmp_path: Path) -> None:
    """AC-06-11, asserted across every fixture that produces one."""
    for name, language in (("indirect", "c"), ("broken", "c"), ("cpp", "c++")):
        index = build(tmp_path / name, name, language=language)
        for limitation in index.limitations():
            assert limitation.affects, f"{name}: {limitation.kind} names nothing"


def test_a_failed_unit_contributes_no_symbols_at_all(tmp_path: Path) -> None:
    """Half a symbol table is worse than none: the gap would go unnamed."""
    root, database = cpp_fixture(tmp_path, "broken")
    config = index_config()
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    index = build_index(plan, config)
    assert [str(path) for path in index.indexed_files()] == ["healthy.c"]
    assert index.stats.failed == 2


def test_parse_status_and_unit_status_are_different_questions() -> None:
    """A reused unit is indexed; the snapshot must not say how it got there."""
    from caudit.index.store import _OUTCOMES

    assert _OUTCOMES[ParseStatus.PARSED] is _OUTCOMES[ParseStatus.REUSED]
    assert _OUTCOMES[ParseStatus.TIMED_OUT] is not _OUTCOMES[ParseStatus.FAILED]

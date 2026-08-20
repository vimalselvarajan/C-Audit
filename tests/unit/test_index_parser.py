"""Parser and cache unit tests — the parts that need no libclang.

Argument adaptation is the highest-consequence pure function in part 06: an
added include path is a guessed one, and a dropped flag changes what the
compiler saw. Both failure modes are silent, so both are asserted here.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from caudit.index.limits import (
    LimitationLog,
    describe_target,
    inline_assembly,
    macro_expansion_unavailable,
    missing_header,
    parse_failed,
    parse_timed_out,
    unresolved_indirect_call,
)
from caudit.index.parser import (
    ParseDiagnostic,
    ParseRequest,
    ParseResult,
    ParseStatus,
    clang_arguments,
)
from caudit.index.store import IndexCache
from caudit.model.finding import LimitationKind


def request_for(
    arguments: tuple[str, ...] = ("clang", "-c", "-o", "a.o", "src/a.c"),
    **kwargs: object,
) -> ParseRequest:
    defaults: dict[str, object] = {
        "file": PurePosixPath("src/a.c"),
        "repo_root": Path("/repo"),
        "directory": Path("/repo/build"),
        "arguments": arguments,
        "language": "c",
    }
    defaults.update(kwargs)
    return ParseRequest(**defaults)  # type: ignore[arg-type]


def test_the_build_command_becomes_a_parse_command() -> None:
    """argv[0] out, output flags out, the two additions in — nothing else."""
    arguments = clang_arguments(
        ("clang", "-DDEBUG=1", "-I../include", "-std=c11", "-c", "-o", "a.o", "src/a.c"),
        directory=Path("/repo/build"),
    )
    assert arguments == [
        "-working-directory=/repo/build",
        "-DDEBUG=1",
        "-I../include",
        "-std=c11",
        "src/a.c",
        "-fsyntax-only",
    ]


def test_a_relative_include_needs_the_entry_directory() -> None:
    """`-I../include` means "relative to the entry's directory", not to ours.

    The value comes from the compilation database, so passing it is carrying
    the build's own statement rather than inferring anything.
    """
    arguments = clang_arguments(("cc", "-I.", "src/a.c"), directory=Path("/elsewhere"))
    assert arguments[0] == "-working-directory=/elsewhere"


def test_a_resource_directory_is_added_only_when_configured() -> None:
    """It is an include path, so it is never discovered — only supplied."""
    without = clang_arguments(("clang", "src/a.c"), directory=Path("/repo"))
    assert not any(item.startswith("-resource-dir") for item in without)

    with_dir = clang_arguments(
        ("clang", "src/a.c"), directory=Path("/repo"), resource_dir="/usr/lib/clang/18"
    )
    assert "-resource-dir=/usr/lib/clang/18" in with_dir


def test_dependency_generation_flags_do_not_reach_the_parser() -> None:
    arguments = clang_arguments(
        ("clang", "-MD", "-MF", "a.d", "-MMD", "-c", "src/a.c"), directory=Path("/repo")
    )
    assert arguments == ["-working-directory=/repo", "src/a.c", "-fsyntax-only"]


def test_an_empty_argv_still_produces_a_usable_command() -> None:
    assert clang_arguments((), directory=Path("/repo")) == [
        "-working-directory=/repo",
        "-fsyntax-only",
    ]


def test_the_cache_key_covers_the_flags_but_not_the_compiler_name() -> None:
    """Two builds of one file with different flags are two different parses."""
    debug = request_for(("clang", "-DDEBUG=1", "-c", "src/a.c"))
    release = request_for(("clang", "-DNDEBUG=1", "-c", "src/a.c"))
    renamed = request_for(("gcc", "-DDEBUG=1", "-c", "src/a.c"))

    cache = IndexCache(directory=None, libclang="18.1.1")
    assert cache.key(debug) != cache.key(release)
    assert cache.key(debug) == cache.key(renamed), "argv[0] is not passed to libclang"


def test_a_cache_with_no_directory_stores_nothing() -> None:
    cache = IndexCache(directory=None)
    request = request_for()
    assert cache.path_for(request) is None
    cache.put(request, ParseResult(file=request.file, status=ParseStatus.PARSED))
    assert cache.get(request, repo_root=Path("/repo")) is None
    assert cache.misses == 1


def test_an_entry_whose_inputs_vanished_is_not_reused(tmp_path: Path) -> None:
    cache = IndexCache(directory=tmp_path / "cache")
    request = request_for()
    cache.put(
        request,
        ParseResult(
            file=request.file,
            status=ParseStatus.PARSED,
            input_hashes={"src/a.c": "e" * 64},
        ),
    )
    assert cache.get(request, repo_root=tmp_path) is None
    assert cache.stale == 1


def test_an_entry_recording_no_inputs_is_not_reused(tmp_path: Path) -> None:
    """Nothing to check means nothing was verified; re-parse instead."""
    cache = IndexCache(directory=tmp_path / "cache")
    request = request_for()
    cache.put(request, ParseResult(file=request.file, status=ParseStatus.PARSED))
    assert cache.get(request, repo_root=tmp_path) is None


def test_parse_result_states() -> None:
    parsed = ParseResult(file=PurePosixPath("src/a.c"), status=ParseStatus.PARSED)
    assert parsed.ok
    assert parsed.reused().status is ParseStatus.REUSED
    assert parsed.reused().ok

    failed = ParseResult(
        file=PurePosixPath("src/a.c"),
        status=ParseStatus.FAILED,
        diagnostics=[
            ParseDiagnostic(severity=2, message="unused variable", path="src/a.c", line=3),
            ParseDiagnostic(severity=3, message="expected '}'", path="src/a.c", line=9),
        ],
    )
    assert not failed.ok
    assert failed.first_error is not None
    assert failed.first_error.describe() == "src/a.c:9: expected '}'"
    assert failed.reused() is failed, "a failure is never served from cache"


def test_a_warning_is_not_an_error() -> None:
    assert not ParseDiagnostic(severity=2, message="unused").is_error
    assert ParseDiagnostic(severity=3, message="error").is_error
    assert ParseDiagnostic(severity=4, message="fatal").is_error
    assert ParseDiagnostic(severity=1, message="note").describe() == "note"


@pytest.mark.parametrize(
    "limitation",
    [
        parse_failed("src/a.c", "expected '}'"),
        missing_header("src/a.c", "gen.h", builtin=False),
        missing_header("src/a.c", "stddef.h", builtin=True),
        parse_timed_out("src/a.c", 60.0),
        unresolved_indirect_call("src/a.c", 9, "dispatch", "handler"),
        inline_assembly("src/a.c", 9, "barrier"),
        macro_expansion_unavailable("src/a.c", "LIKELY"),
    ],
)
def test_every_limitation_builder_names_a_file(limitation: object) -> None:
    """AC-06-11, at the source: `affects` is mandatory in this module."""
    assert getattr(limitation, "affects", "").startswith("src/a.c")
    assert "src/a.c" in getattr(limitation, "detail", "")


def test_a_builtin_header_failure_points_at_the_resource_directory() -> None:
    detail = missing_header("src/a.c", "stddef.h", builtin=True).detail
    assert "clang -print-resource-dir" in detail
    assert "does not invent include paths" in detail

    generated = missing_header("src/a.c", "config.h", builtin=False).detail
    assert "generated by the build" in generated


def test_describe_target_forms() -> None:
    assert describe_target("src/a.c") == "src/a.c"
    assert describe_target("src/a.c", "parse") == "src/a.c::parse"


def test_the_limitation_log_deduplicates_and_orders() -> None:
    """Two runs that find the same blind spots in a different order agree."""
    first = parse_failed("src/b.c", "boom")
    second = inline_assembly("src/a.c", 3, "f")
    assert LimitationLog([first, second, first]).all() == LimitationLog([second, first]).all()
    assert len(LimitationLog([first, second, first])) == 2

    log = LimitationLog([first, second])
    assert log.of_kind(LimitationKind.INLINE_ASSEMBLY) == [second]
    assert log.kinds() == {"parse_failed", "inline_assembly"}

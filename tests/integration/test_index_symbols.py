"""Part 06 symbol tests: T-06-01 … T-06-04.

Marked ``needs_libclang`` rather than ``needs_clang``: indexing uses the
libclang wheel, which bundles its own shared library and is a hard dependency
of the package, so these run in the default suite on a machine with no LLVM
installed. Only the toolchain-dependent test at the end of this file needs a
real ``clang`` on PATH.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.index import Index, build_index
from caudit.index.symbols import SymbolKind
from caudit.intake import load_scan_plan
from tests.conftest import cpp_fixture, index_config

pytestmark = pytest.mark.needs_libclang


def build(tmp_path: Path, name: str, *, language: str = "c", **overrides: object) -> Index:
    """Copy a fixture tree, describe it, and index it."""
    root, database = cpp_fixture(tmp_path, name, language=language)
    config = index_config(**overrides)
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    return build_index(plan, config)


def test_the_symbol_table_holds_every_declaration_with_its_kind(tmp_path: Path) -> None:
    """T-06-01: functions, a global, a type, its fields, and both macros."""
    index = build(tmp_path, "basic")
    kinds = {symbol.name: symbol.kind for symbol in index.symbols_in("basic.c")}
    assert kinds == {
        "parse_header": SymbolKind.FUNCTION,
        "checksum": SymbolKind.FUNCTION,
        "total": SymbolKind.FUNCTION,
        "packets_seen": SymbolKind.VARIABLE,
        "Packet": SymbolKind.TYPE,
        "len": SymbolKind.FIELD,
        "data": SymbolKind.FIELD,
        "BUF_SZ": SymbolKind.MACRO,
        "CHECK_LEN": SymbolKind.MACRO,
    }

    parse_header = index.symbols_named("parse_header")[0]
    assert parse_header.is_definition_available
    assert parse_header.definition is not None
    assert (parse_header.definition.start_line, parse_header.definition.end_line) == (10, 30)
    # Every entry is hashed: an index that says "line 40" without one cannot
    # support the evidence gate.
    assert len(parse_header.definition.sha256) == 64


def test_a_local_variable_is_not_a_symbol(tmp_path: Path) -> None:
    """Clang keys a local's USR by byte offset, so it is not an identity."""
    index = build(tmp_path, "basic")
    assert index.symbols_named("copied") == []


def test_overloads_are_two_symbols_that_share_a_name(tmp_path: Path) -> None:
    """T-06-02: distinct USRs, and `symbols_named` returns both."""
    index = build(tmp_path, "cpp", language="c++")
    overloads = index.symbols_named("convert")
    assert len(overloads) == 2
    assert len({symbol.usr for symbol in overloads}) == 2
    assert {symbol.usr for symbol in overloads} == {"c:@F@convert#I#", "c:@F@convert#d#"}


def test_same_named_statics_in_same_named_files_do_not_collide(tmp_path: Path) -> None:
    """T-06-03: the case Clang's own USR gets wrong.

    Clang spells a file-local USR with the *basename*, so two `helper`s in
    `lib/util.c` and `app/util.c` would share one USR and one symbol. The
    repository-relative qualification is what keeps them apart.
    """
    index = build(tmp_path, "statics")
    helpers = index.symbols_named("helper")
    assert len(helpers) == 2
    assert {symbol.usr for symbol in helpers} == {
        "c:app/util.c@F@helper",
        "c:lib/util.c@F@helper",
    }
    files = {str(symbol.definition.path) for symbol in helpers if symbol.definition is not None}
    assert files == {"app/util.c", "lib/util.c"}

    # And each entry point calls its own.
    lib_entry = index.symbols_named("lib_entry")[0]
    assert [edge.callee for edge in index.callees_of(lib_entry.usr)] == ["c:lib/util.c@F@helper"]


@pytest.mark.parametrize("line", [10, 20, 30])
def test_enclosing_function_covers_the_whole_definition(tmp_path: Path, line: int) -> None:
    """T-06-04: correct at the first, a middle, and the last line."""
    index = build(tmp_path, "basic")
    enclosing = index.enclosing_function("basic.c", line)
    assert enclosing is not None
    assert enclosing.name == "parse_header"


def test_enclosing_function_is_none_at_file_scope(tmp_path: Path) -> None:
    """T-06-04, second half: line 5 is a `#define`, not a body."""
    index = build(tmp_path, "basic")
    assert index.enclosing_function("basic.c", 5) is None


def test_a_declaration_is_not_a_definition(tmp_path: Path) -> None:
    """A header prototype must never stand in for the body a claim needs."""
    index = build(tmp_path, "cross_tu")
    b_func = index.symbols_named("b_func")[0]
    assert b_func.definition is not None
    assert str(b_func.definition.path) == "b.c"
    assert [str(region.path) for region in b_func.declarations] == ["b.h"]
    assert index.enclosing_function("b.h", 1) is None


def test_types_referenced_by_a_function(tmp_path: Path) -> None:
    index = build(tmp_path, "basic")
    parse_header = index.symbols_named("parse_header")[0]
    assert [symbol.name for symbol in index.types_referenced_by(parse_header.usr)] == ["Packet"]


def test_globals_referenced_by_a_function(tmp_path: Path) -> None:
    """The graph part 09 needs to retrieve a global's declaration.

    Kept apart from the type graph: a struct layout and a counter are wanted
    at different points of the expansion order, and a caller asking for one
    must never receive the other.
    """
    index = build(tmp_path, "basic")
    parse_header = index.symbols_named("parse_header")[0]
    total = index.symbols_named("total")[0]

    assert [symbol.name for symbol in index.globals_referenced_by(parse_header.usr)] == [
        "packets_seen"
    ]
    assert index.globals_referenced_by(total.usr) == []
    assert index.types_referenced_by(parse_header.usr) != index.globals_referenced_by(
        parse_header.usr
    )


def test_a_local_variable_is_not_a_global_reference(tmp_path: Path) -> None:
    """`copied` is read all over parse_header and is inside its own region."""
    index = build(tmp_path, "basic")
    parse_header = index.symbols_named("parse_header")[0]
    referenced = {symbol.name for symbol in index.globals_referenced_by(parse_header.usr)}
    assert "copied" not in referenced


def test_the_global_graph_survives_a_snapshot_round_trip(tmp_path: Path) -> None:
    index = build(tmp_path, "basic")
    parse_header = index.symbols_named("parse_header")[0]

    restored = Index.from_snapshot(index.to_snapshot(), repo_root=index.repo_root)

    assert [symbol.name for symbol in restored.globals_referenced_by(parse_header.usr)] == [
        "packets_seen"
    ]


def test_the_index_records_which_units_are_in_it(tmp_path: Path) -> None:
    index = build(tmp_path, "cross_tu")
    assert [str(path) for path in index.indexed_files()] == ["a.c", "b.c", "c.c"]
    assert index.is_indexed("a.c")
    assert not index.is_indexed("nowhere.c")


@pytest.mark.needs_clang
def test_a_system_header_parses_when_a_resource_directory_is_supplied(tmp_path: Path) -> None:
    """The wheel ships no builtin headers; a real toolchain supplies them.

    Needs `clang` on PATH because the resource directory is read from it —
    C Audit never goes looking for one on its own.
    """
    import subprocess

    resource_dir = subprocess.run(
        ["clang", "-print-resource-dir"], capture_output=True, text=True, check=True
    ).stdout.strip()

    root = tmp_path / "syshdr"
    root.mkdir()
    (root / "main.c").write_text(
        "#include <stddef.h>\nsize_t sized(void) { return sizeof(int); }\n", encoding="utf-8"
    )
    database = root / "compile_commands.json"
    database.write_text(
        f'[{{"directory": "{root}", "file": "{root / "main.c"}", '
        f'"arguments": ["clang", "-c", "{root / "main.c"}"]}}]',
        encoding="utf-8",
    )

    config = index_config(resource_dir=resource_dir)
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    index = build_index(plan, config)
    assert index.is_indexed("main.c")
    assert index.symbols_named("sized")

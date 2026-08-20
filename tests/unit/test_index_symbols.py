"""Part 06 symbol unit tests: USR identity and table semantics.

The USR rewriting is the load-bearing piece here. If two unrelated statics
share one USR, they become one symbol, and every call edge, citation, and
finding that touches either inherits the confusion.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from caudit.index.symbols import Symbol, SymbolKind, SymbolTable, normalize_usr
from caudit.model.source import SourceRegion


def region(path: str, start: int, end: int | None = None) -> SourceRegion:
    return SourceRegion(
        path=PurePosixPath(path),
        start_line=start,
        end_line=end or start,
        start_byte=0,
        end_byte=8,
        sha256="d" * 64,
    )


def symbol(
    usr: str,
    name: str = "helper",
    *,
    kind: SymbolKind = SymbolKind.FUNCTION,
    definition: SourceRegion | None = None,
    declarations: tuple[SourceRegion, ...] = (),
) -> Symbol:
    return Symbol(
        usr=usr,
        name=name,
        qualified_name=name,
        kind=kind,
        definition=definition,
        declarations=list(declarations),
    )


@pytest.mark.parametrize(
    ("raw", "path", "expected"),
    [
        # File-local: the basename Clang used becomes the full path.
        ("c:util.c@F@helper", "lib/util.c", "c:lib/util.c@F@helper"),
        ("c:util.c@F@helper", "app/util.c", "c:app/util.c@F@helper"),
        # A macro USR carries a byte offset that moves on any edit above it.
        ("c:a.c@8@macro@BUF_SZ", "src/a.c", "c:src/a.c@macro@BUF_SZ"),
        # Already global: nothing to qualify.
        ("c:@F@public_fn", "src/a.c", "c:@F@public_fn"),
        ("c:@S@Packet@FI@len", "src/a.c", "c:@S@Packet@FI@len"),
        ("c:@F@convert#I#", "src/a.cpp", "c:@F@convert#I#"),
        # Not a Clang USR at all.
        ("", "src/a.c", ""),
        ("weird", "src/a.c", "weird"),
    ],
)
def test_usr_normalization(raw: str, path: str, expected: str) -> None:
    assert normalize_usr(raw, PurePosixPath(path)) == expected


def test_a_non_macro_offset_component_is_left_alone() -> None:
    """Only the macro form is rewritten; anything else keeps Clang's spelling."""
    assert normalize_usr("c:a.c@124@F@helper@x", "src/a.c") == "c:src/a.c@124@F@helper@x"


def test_merging_prefers_a_definition_over_a_declaration() -> None:
    declaration = symbol("c:@F@f", declarations=(region("src/f.h", 3),))
    definition = symbol("c:@F@f", definition=region("src/f.c", 10, 20))

    merged = declaration.merged_with(definition)
    assert merged.definition == region("src/f.c", 10, 20)
    assert merged.declarations == [region("src/f.h", 3)]
    assert merged.is_definition_available
    # And in the other order, because parse order must not decide.
    assert definition.merged_with(declaration) == merged


def test_two_definitions_resolve_by_region_not_by_arrival() -> None:
    """A weak symbol defined twice picks the same one on every run."""
    first = symbol("c:@F@f", definition=region("src/a.c", 10))
    second = symbol("c:@F@f", definition=region("src/b.c", 10))
    assert first.merged_with(second).definition == region("src/a.c", 10)
    assert second.merged_with(first).definition == region("src/a.c", 10)


def test_merging_a_different_usr_is_refused() -> None:
    with pytest.raises(ValueError, match="cannot merge"):
        symbol("c:@F@f").merged_with(symbol("c:@F@g"))


def test_a_symbol_round_trips_through_json() -> None:
    """The derived field appears in the output and is dropped on the way in.

    Without that, the index cache is write-only — entries serialize and never
    load, so nothing is ever reused and no test would notice.
    """
    original = symbol("c:@F@f", definition=region("src/f.c", 1, 4))
    restored = Symbol.model_validate_json(original.model_dump_json())
    assert restored == original
    assert '"is_definition_available":true' in original.model_dump_json()


def test_the_table_indexes_by_name_and_qualified_name() -> None:
    method = Symbol(
        usr="c:@S@Codec@F@decode#I#",
        name="decode",
        qualified_name="Codec::decode",
        kind=SymbolKind.METHOD,
        definition=region("src/codec.cpp", 5, 9),
    )
    table = SymbolTable([method])
    assert table.named("decode") == [method]
    assert table.named("Codec::decode") == [method]
    assert table.named("nothing") == []
    assert "c:@S@Codec@F@decode#I#" in table
    assert list(table) == [method]


def test_the_innermost_definition_wins() -> None:
    outer = symbol("c:@F@outer", name="outer", definition=region("src/a.c", 1, 40))
    inner = symbol("c:@F@inner", name="inner", definition=region("src/a.c", 10, 20))
    table = SymbolTable([outer, inner])
    assert table.enclosing_function("src/a.c", 15) is inner
    assert table.enclosing_function("src/a.c", 35) is outer
    assert table.enclosing_function("src/a.c", 50) is None
    assert table.enclosing_function("src/other.c", 15) is None


def test_only_callables_can_enclose_a_line() -> None:
    record = symbol("c:@S@T", name="T", kind=SymbolKind.TYPE, definition=region("src/a.c", 1, 5))
    assert SymbolTable([record]).enclosing_function("src/a.c", 3) is None


def test_a_declaration_only_symbol_encloses_nothing() -> None:
    prototype = symbol("c:@F@f", declarations=(region("src/f.h", 2),))
    assert SymbolTable([prototype]).enclosing_function("src/f.h", 2) is None
    assert not prototype.is_definition_available
    assert prototype.span() == 0


def test_conversion_to_the_finding_model_symbol() -> None:
    converted = symbol("c:@F@f", name="f", definition=region("src/f.c", 1)).as_model_symbol()
    assert (converted.name, converted.kind, converted.usr) == ("f", "function", "c:@F@f")


def test_in_file_lists_every_symbol_touching_a_path() -> None:
    table = SymbolTable(
        [
            symbol(
                "c:@F@f",
                name="f",
                definition=region("src/f.c", 1),
                declarations=(region("src/f.h", 1),),
            ),
            symbol("c:@F@g", name="g", definition=region("src/g.c", 1)),
        ]
    )
    assert [item.name for item in table.in_file("src/f.h")] == ["f"]
    assert [item.name for item in table.in_file("src/g.c")] == ["g"]

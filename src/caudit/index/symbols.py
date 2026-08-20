"""Symbols, keyed by USR.

The USR is the identity. Names are for humans: two `static` helpers in
different files share a name, an overload set shares a name, and a macro can
share a name with a function. Every lookup, merge, and graph edge in this
package therefore keys on the USR, and names are only ever an index *into*
USRs.

Clang's own USRs need one adjustment before they can serve as identity here.
For a file-local entity Clang spells the file as its **basename** —
``c:util.c@F@helper`` — so ``src/util.c`` and ``tools/util.c`` produce
identical USRs for two unrelated static functions. :func:`normalize_usr`
replaces that basename with the repository-relative path, which is unique by
construction and independent of where the tree is checked out.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from caudit.model.source import SourceRegion
from caudit.model.source import Symbol as ModelSymbol

__all__ = [
    "Symbol",
    "SymbolKind",
    "SymbolTable",
    "normalize_usr",
    "sort_regions",
]

_USR_PREFIX = "c:"


class SymbolKind(StrEnum):
    """What kind of program entity a symbol is."""

    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    TYPE = "type"
    MACRO = "macro"
    FIELD = "field"


#: Kinds that can enclose a line of executable code.
CALLABLE_KINDS: frozenset[SymbolKind] = frozenset({SymbolKind.FUNCTION, SymbolKind.METHOD})


def normalize_usr(usr: str, path: PurePosixPath | str) -> str:
    """Qualify a file-local USR with its repository-relative path.

    Two changes, both aimed at making the USR a stable identity:

    * the basename Clang embeds for file-local entities becomes the full
      repository-relative path, so same-named statics in different directories
      cannot collide;
    * the byte offset Clang embeds in a macro's USR is dropped. It moves
      whenever anything *above* the definition moves, which would give an
      untouched macro a new identity on the next run and defeat both the
      incremental cache and any run-to-run comparison.

    A USR with no file component (``c:@F@public_fn``, and every C++ USR) is
    already globally unique and is returned unchanged.
    """
    if not usr.startswith(_USR_PREFIX):
        return usr
    body = usr[len(_USR_PREFIX) :]
    head, separator, rest = body.partition("@")
    if not separator or not head:
        return usr
    return f"{_USR_PREFIX}{path}@{_strip_macro_offset(rest)}"


def _strip_macro_offset(rest: str) -> str:
    """``8@macro@BUF_SZ`` → ``macro@BUF_SZ``; anything else is untouched."""
    first, separator, tail = rest.partition("@")
    if separator and first.isdigit() and tail.startswith("macro@"):
        return tail
    return rest


def sort_regions(regions: Iterable[SourceRegion]) -> list[SourceRegion]:
    """Deterministic region order: path, then start line, then end line."""
    return sorted(regions, key=lambda r: (str(r.path), r.start_line, r.end_line, r.start_byte))


class Symbol(BaseModel):
    """One named entity, with every place it was seen.

    ``is_definition_available`` is derived rather than stored: a serialized
    index that claimed a definition it does not carry would be a lie the
    evidence gate could not catch.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    usr: str = Field(min_length=1)
    name: str = Field(min_length=1)
    #: ``Base::run`` for a method, the plain name for a C function.
    qualified_name: str = Field(min_length=1)
    kind: SymbolKind
    #: Where the body is, when this run saw it. Every region is hashed.
    definition: SourceRegion | None = None
    #: Declarations without a body, sorted. A header prototype lands here.
    declarations: list[SourceRegion] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _drop_derived(cls, data: Any) -> Any:
        """Let a serialized symbol be read back.

        ``is_definition_available`` is computed, so it appears in the JSON and
        would then be rejected as an extra key on the way back in — which
        silently made the index cache write-only. Dropping it on input keeps
        the field derived *and* the model round-trippable; the value is
        recomputed from ``definition`` either way, so nothing is trusted.
        """
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if key != "is_definition_available"}
        return data

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_definition_available(self) -> bool:
        return self.definition is not None

    @property
    def is_callable(self) -> bool:
        return self.kind in CALLABLE_KINDS

    @property
    def regions(self) -> list[SourceRegion]:
        """Every region this symbol occupies, definition first."""
        return ([self.definition] if self.definition else []) + list(self.declarations)

    def occupies(self, path: PurePosixPath | str, line: int) -> bool:
        """True when ``line`` falls inside one of this symbol's regions."""
        wanted = str(path)
        return any(
            str(region.path) == wanted and region.start_line <= line <= region.end_line
            for region in self.regions
        )

    def span(self) -> int:
        """Lines covered by the definition, or 0 without one. Used to pick the
        innermost of two enclosing symbols."""
        return self.definition.line_count if self.definition else 0

    def as_model_symbol(self) -> ModelSymbol:
        """The part 02 :class:`~caudit.model.source.Symbol` a finding carries."""
        return ModelSymbol(
            name=self.name,
            kind=str(self.kind),
            qualified_name=self.qualified_name,
            usr=self.usr,
        )

    def merged_with(self, other: Symbol) -> Symbol:
        """Combine two sightings of one USR, from two translation units.

        A definition beats no definition; two definitions are resolved by
        region order rather than by which TU happened to be parsed first, so
        the result does not depend on scheduling.
        """
        if other.usr != self.usr:  # pragma: no cover - callers key by USR
            raise ValueError(f"cannot merge {self.usr} with {other.usr}")
        definitions = sort_regions(
            {region for region in (self.definition, other.definition) if region is not None}
        )
        declarations = sort_regions(set(self.declarations) | set(other.declarations))
        definition = definitions[0] if definitions else None
        return self.model_copy(
            update={
                "definition": definition,
                "declarations": [region for region in declarations if region != definition],
            }
        )


class SymbolTable:
    """Every symbol the run saw, merged across translation units."""

    def __init__(self, symbols: Iterable[Symbol] = ()) -> None:
        self._by_usr: dict[str, Symbol] = {}
        self._by_name: dict[str, set[str]] = {}
        for symbol in symbols:
            self.add(symbol)

    def add(self, symbol: Symbol) -> Symbol:
        """Insert or merge. Returns the resulting symbol."""
        existing = self._by_usr.get(symbol.usr)
        merged = symbol if existing is None else existing.merged_with(symbol)
        self._by_usr[symbol.usr] = merged
        self._by_name.setdefault(symbol.name, set()).add(symbol.usr)
        if symbol.qualified_name != symbol.name:
            self._by_name.setdefault(symbol.qualified_name, set()).add(symbol.usr)
        return merged

    def extend(self, symbols: Iterable[Symbol]) -> None:
        for symbol in symbols:
            self.add(symbol)

    def get(self, usr: str) -> Symbol | None:
        return self._by_usr.get(usr)

    def named(self, name: str) -> list[Symbol]:
        """Every symbol with this name or qualified name, sorted by USR.

        A list, not a symbol: ``symbols_named`` returning one entry for an
        overload set is how a resolver ends up verifying the wrong function.
        """
        return [self._by_usr[usr] for usr in sorted(self._by_name.get(name, set()))]

    def enclosing_function(self, path: PurePosixPath | str, line: int) -> Symbol | None:
        """The innermost function or method whose *definition* contains ``line``.

        File scope returns ``None`` — a declaration is not a body, and a
        citation that lands between two functions has no enclosing one.
        """
        wanted = str(path)
        candidates = [
            symbol
            for symbol in self._by_usr.values()
            if symbol.is_callable
            and symbol.definition is not None
            and str(symbol.definition.path) == wanted
            and symbol.definition.start_line <= line <= symbol.definition.end_line
        ]
        if not candidates:
            return None
        # Innermost first (a nested lambda beats its enclosing function), then
        # by USR so two equal spans resolve the same way on every run.
        candidates.sort(key=lambda symbol: (symbol.span(), symbol.usr))
        return candidates[0]

    def in_file(self, path: PurePosixPath | str) -> list[Symbol]:
        wanted = str(path)
        return [
            symbol
            for symbol in self.all()
            if any(str(region.path) == wanted for region in symbol.regions)
        ]

    def all(self) -> list[Symbol]:
        """Every symbol, ordered by USR — the serialization order."""
        return [self._by_usr[usr] for usr in sorted(self._by_usr)]

    def __len__(self) -> int:
        return len(self._by_usr)

    def __iter__(self) -> Iterator[Symbol]:
        return iter(self.all())

    def __contains__(self, usr: object) -> bool:
        return isinstance(usr, str) and usr in self._by_usr

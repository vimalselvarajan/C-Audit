"""Compiler-aware indices over the scanned revision (part 06).

Parses every translation unit the scan plan selected and answers the
structural questions the rest of the pipeline would otherwise have to guess
at: where a symbol is defined, who calls it, what a macro expands to, which
header pulled in which. Retrieval in part 09 and verification in part 11 both
read from here, which is what makes them structural rather than textual.

Two rules run through the whole package:

* every entry carries a hashed :class:`~caudit.model.source.SourceRegion`, so
  an index fact can support the evidence gate rather than merely assert a line
  number;
* unresolved is not absent — an indirect call is an edge with an unknown
  target, never a missing edge.
"""

from __future__ import annotations

from caudit.index.graphs import CallEdge, CallKind, CallQuery, MacroExpansion
from caudit.index.parser import ParseRequest, ParseResult, ParseStatus, parse_request
from caudit.index.resolver import IndexResolver
from caudit.index.store import Index, IndexCache, IndexSnapshot, IndexStats, build_index
from caudit.index.symbols import Symbol, SymbolKind, SymbolTable

__all__ = [
    "CallEdge",
    "CallKind",
    "CallQuery",
    "Index",
    "IndexCache",
    "IndexResolver",
    "IndexSnapshot",
    "IndexStats",
    "MacroExpansion",
    "ParseRequest",
    "ParseResult",
    "ParseStatus",
    "Symbol",
    "SymbolKind",
    "SymbolTable",
    "build_index",
    "parse_request",
]

"""Cursor traversal and index-record construction for one parsed unit."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

from caudit.errors import RegionError
from caudit.evidence.hashing import hash_bytes
from caudit.evidence.store import SourceStore
from caudit.index import limits
from caudit.index.graphs import CallEdge, CallKind, IncludeEdge, MacroExpansion
from caudit.index.parser import (
    ParseDiagnostic,
    ParseRequest,
    ParseResult,
    ParseStatus,
    _cindex,
)
from caudit.index.symbols import Symbol, SymbolKind, normalize_usr
from caudit.model.finding import Limitation
from caudit.model.source import SourceRegion

_ERROR_SEVERITY: Final = 3
_MISSING_INCLUDE_RE: Final = re.compile(r"'([^']+)' file not found")
_BUILTIN_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "float.h",
        "inttypes.h",
        "iso646.h",
        "limits.h",
        "stdalign.h",
        "stdarg.h",
        "stdatomic.h",
        "stdbool.h",
        "stddef.h",
        "stdint.h",
        "stdnoreturn.h",
        "tgmath.h",
        "varargs.h",
    }
)


@dataclass
class _ClassInfo:
    """A record's bases and virtual methods, for resolving virtual dispatch."""

    bases: set[str] = field(default_factory=set)
    #: Method USR suffix (``@F@run#I#``) → full USR.
    methods: dict[str, str] = field(default_factory=dict)


class Collector:
    """Walks one parsed unit and turns cursors into index records."""

    def __init__(self, request: ParseRequest) -> None:
        self.request = request
        self.store = SourceStore(
            request.repo_root, revision="index", max_file_bytes=request.max_file_bytes
        )
        self.cindex = _cindex()
        self.kinds = self.cindex.CursorKind
        # Looked up once per cursor, so they are built once per unit.
        self.symbol_kinds = _symbol_kinds(self.kinds)
        self.asm_kinds = _asm_kinds(self.kinds)
        self.callable_kinds = _callable_kinds(self.kinds)
        self.container_kinds = {
            self.kinds.NAMESPACE,
            self.kinds.CLASS_DECL,
            self.kinds.STRUCT_DECL,
            self.kinds.UNION_DECL,
            self.kinds.ENUM_DECL,
            self.kinds.CLASS_TEMPLATE,
        }
        #: Where a declaration has to sit to count as a symbol of its own.
        self.scope_kinds = self.container_kinds | {self.kinds.TRANSLATION_UNIT}
        self.symbols: dict[str, Symbol] = {}
        self.calls: list[CallEdge] = []
        self.macros: list[MacroExpansion] = []
        self.includes: list[IncludeEdge] = []
        self.limitations: list[Limitation] = []
        self.type_references: set[tuple[str, str]] = set()
        self.global_references: set[tuple[str, str]] = set()
        self.inputs: dict[str, str] = {}
        self.classes: dict[str, _ClassInfo] = {}
        #: ``(path, start offset, end offset)`` of every macro expansion, used
        #: to tell a call written at its site from one a macro produced.
        self.macro_spans: list[tuple[str, int, int]] = []
        #: Virtual call sites, resolved once the class hierarchy is complete.
        self.virtual_sites: list[tuple[CallEdge, str | None]] = []
        self._region_cache: dict[tuple[str, int, int], SourceRegion | None] = {}

    # ------------------------------------------------------------------ entry

    def collect(self, unit: Any) -> ParseResult:
        diagnostics = [self._diagnostic(item) for item in unit.diagnostics]
        self._record_inputs(unit)
        errors = [item for item in diagnostics if item.is_error]
        if errors:
            self.limitations.extend(self._failure_limitations(errors))
            return self._result(ParseStatus.FAILED, diagnostics)

        self._walk(unit.cursor)
        self._resolve_virtual_calls()
        self._classify_macro_calls()
        return self._result(ParseStatus.PARSED, diagnostics)

    def _result(self, status: ParseStatus, diagnostics: list[ParseDiagnostic]) -> ParseResult:
        return ParseResult(
            file=self.request.file,
            status=status,
            symbols=sorted(self.symbols.values(), key=lambda symbol: symbol.usr),
            calls=sorted(
                self.calls,
                key=lambda edge: (
                    edge.caller,
                    edge.callee or "",
                    edge.site.start_line,
                    edge.site.start_byte,
                    str(edge.kind),
                ),
            ),
            macros=sorted(
                set(self.macros),
                key=lambda item: (item.expansion.start_line, item.expansion.start_byte, item.usr),
            ),
            includes=sorted(set(self.includes), key=lambda edge: (edge.line, edge.included)),
            diagnostics=diagnostics,
            limitations=_dedupe(self.limitations),
            type_references=sorted(self.type_references),
            global_references=sorted(self.global_references),
            input_hashes=dict(sorted(self.inputs.items())),
        )

    # ------------------------------------------------------------ diagnostics

    def _diagnostic(self, raw: Any) -> ParseDiagnostic:
        """Relativized where possible: a diagnostic quoting an absolute build
        path would put the machine that ran the scan into the report."""
        location = raw.location
        file = location.file
        name = str(file.name) if file else None
        relative = self._relative(name)
        return ParseDiagnostic(
            severity=int(raw.severity),
            message=str(raw.spelling),
            path=str(relative) if relative is not None else name,
            line=int(location.line),
        )

    def _failure_limitations(self, errors: list[ParseDiagnostic]) -> list[Limitation]:
        """Name the cause precisely: a missing header is not a syntax error."""
        first = errors[0]
        match = _MISSING_INCLUDE_RE.search(first.message)
        if match is None:
            return [limits.parse_failed(self.request.file, first.describe())]
        header = match.group(1)
        builtin = PurePosixPath(header).name in _BUILTIN_HEADERS
        recorded = [limits.missing_header(self.request.file, header, builtin=builtin)]
        if builtin:
            recorded.append(limits.toolchain_headers_unavailable(self.request.file))
        return recorded

    # ----------------------------------------------------------------- inputs

    def _record_inputs(self, unit: Any) -> None:
        """Hash every in-repo file the unit read, for the incremental cache.

        Headers outside the tree are deliberately not hashed: they belong to
        the toolchain, they are recorded in the include graph, and hashing a
        thousand system headers per unit would cost more than re-parsing.
        """
        self._hash_input(self.request.file)
        for entry in unit.get_includes():
            included = self._relative(getattr(entry.include, "name", None))
            source = self._relative(
                getattr(entry.location.file, "name", None) if entry.location.file else None
            )
            raw_name = str(entry.include.name)
            if source is None:
                continue
            site = self._line_region(source, max(1, int(entry.location.line)))
            if site is not None:
                self.includes.append(
                    IncludeEdge(
                        includer=source,
                        included=str(included) if included is not None else raw_name,
                        site=site,
                        in_repo=included is not None,
                    )
                )
            if included is not None:
                self._hash_input(included)

    def _hash_input(self, relative: PurePosixPath) -> None:
        if str(relative) in self.inputs:
            return
        try:
            data = self.store.load(relative).data
        except RegionError:
            return
        self.inputs[str(relative)] = hash_bytes(data)

    # ------------------------------------------------------------------- walk

    def _walk(self, root: Any) -> None:
        """Iterative pre-order walk carrying the enclosing symbol down.

        Iterative rather than recursive: expression nesting in generated C can
        be thousands deep, and a RecursionError here would look like a parse
        failure in a file that parses perfectly well.
        """
        stack: list[tuple[Any, str | None]] = [
            (child, None) for child in reversed(list(root.get_children()))
        ]
        while stack:
            cursor, enclosing = stack.pop()
            relative = self._cursor_path(cursor)
            if relative is None:
                # Outside the tree (a system header) or nowhere (a predefined
                # macro). Its children live in the same file, so skip them too.
                continue
            enclosing = self._visit(cursor, relative, enclosing)
            stack.extend((child, enclosing) for child in reversed(list(cursor.get_children())))

    def _visit(self, cursor: Any, relative: PurePosixPath, enclosing: str | None) -> str | None:
        """Record what this cursor is. Returns the enclosing USR for children."""
        kinds = self.kinds
        kind = cursor.kind

        if kind == kinds.MACRO_DEFINITION:
            self._add_macro_definition(cursor, relative)
            return enclosing
        if kind == kinds.MACRO_INSTANTIATION:
            self._add_macro_expansion(cursor, relative)
            return enclosing
        if kind == kinds.INCLUSION_DIRECTIVE:
            return enclosing
        if kind in self.asm_kinds:
            self._add_inline_assembly(cursor, relative, enclosing)
            return enclosing
        if kind == kinds.CALL_EXPR:
            self._add_call(cursor, relative, enclosing)
            return enclosing
        if kind == kinds.TYPE_REF:
            self._add_type_reference(cursor, enclosing)
            return enclosing
        if kind == kinds.DECL_REF_EXPR:
            self._add_global_reference(cursor, enclosing)
            return enclosing
        if kind == kinds.CXX_BASE_SPECIFIER:
            self._add_base_class(cursor, enclosing)
            return enclosing

        symbol_kind = self.symbol_kinds.get(kind)
        if symbol_kind is None:
            return enclosing
        if symbol_kind is SymbolKind.VARIABLE and not self._at_scope(cursor):
            # A local. Clang keys its USR by byte offset, so an edit anywhere
            # above it would change its identity — and it is already reachable
            # through the region of the function that declares it. Children are
            # still walked: a call inside its initializer is a real edge.
            return enclosing
        symbol = self._add_symbol(cursor, relative, symbol_kind)
        if symbol is None:
            return enclosing
        if symbol_kind in (SymbolKind.FUNCTION, SymbolKind.METHOD):
            self._record_method(cursor, symbol)
        return symbol.usr if symbol.definition is not None else enclosing

    # ---------------------------------------------------------------- symbols

    def _add_symbol(self, cursor: Any, relative: PurePosixPath, kind: SymbolKind) -> Symbol | None:
        usr = self._usr(cursor)
        if usr is None:
            return None
        region = self._region(cursor, relative)
        if region is None:
            return None
        is_definition = bool(cursor.is_definition()) or kind is SymbolKind.MACRO
        symbol = Symbol(
            usr=usr,
            name=str(cursor.spelling) or usr,
            qualified_name=self._qualified_name(cursor),
            kind=kind,
            definition=region if is_definition else None,
            declarations=[] if is_definition else [region],
        )
        existing = self.symbols.get(usr)
        merged = symbol if existing is None else existing.merged_with(symbol)
        self.symbols[usr] = merged
        return merged

    def _at_scope(self, cursor: Any) -> bool:
        """True for a declaration at file, namespace, record, or enum scope."""
        parent = cursor.semantic_parent
        return parent is not None and parent.kind in self.scope_kinds

    def _qualified_name(self, cursor: Any) -> str:
        """``Base::run``, ``ns::Type``, or the plain name in C."""
        parts: list[str] = [str(cursor.spelling)]
        parent = cursor.semantic_parent
        while parent is not None and parent.kind in self.container_kinds:
            spelling = str(parent.spelling)
            if spelling:
                parts.append(spelling)
            parent = parent.semantic_parent
        name = "::".join(reversed(parts))
        return name or str(cursor.spelling) or "<anonymous>"

    def _record_method(self, cursor: Any, symbol: Symbol) -> None:
        """Remember virtual methods per class, keyed by USR suffix."""
        if cursor.kind != self.kinds.CXX_METHOD:
            return
        if not bool(cursor.is_virtual_method()):
            return
        parent = cursor.semantic_parent
        class_usr = self._usr(parent) if parent is not None else None
        if class_usr is None or not symbol.usr.startswith(class_usr):
            return
        info = self.classes.setdefault(class_usr, _ClassInfo())
        info.methods[symbol.usr[len(class_usr) :]] = symbol.usr

    def _add_base_class(self, cursor: Any, enclosing: str | None) -> None:
        parent = cursor.semantic_parent
        derived = self._usr(parent) if parent is not None else enclosing
        referenced = cursor.referenced
        base = self._usr(referenced) if referenced is not None else None
        if derived is None or base is None:
            return
        self.classes.setdefault(derived, _ClassInfo()).bases.add(base)
        self.classes.setdefault(base, _ClassInfo())

    # ------------------------------------------------------------------ calls

    def _add_call(self, cursor: Any, relative: PurePosixPath, enclosing: str | None) -> None:
        if enclosing is None:
            return
        region = self._region(cursor, relative)
        if region is None:
            return
        referenced = cursor.referenced
        spelling = str(cursor.spelling) or None
        callee = self._usr(referenced) if referenced is not None else None
        if callee is None or referenced.kind not in self.callable_kinds:
            edge = CallEdge(
                caller=enclosing,
                callee=None,
                site=region,
                kind=CallKind.FUNCTION_POINTER,
                spelling=spelling,
            )
            self.calls.append(edge)
            self.limitations.append(
                limits.unresolved_indirect_call(
                    relative, region.start_line, self._name_of(enclosing), spelling
                )
            )
            return

        virtual = bool(referenced.kind == self.kinds.CXX_METHOD and referenced.is_virtual_method())
        edge = CallEdge(
            caller=enclosing,
            callee=callee,
            site=region,
            kind=CallKind.VIRTUAL if virtual else CallKind.DIRECT,
            spelling=spelling,
        )
        self.calls.append(edge)
        if virtual:
            self.virtual_sites.append((edge, self._name_of(enclosing)))

    def _resolve_virtual_calls(self) -> None:
        """Add an edge to every override this unit can see, and say so.

        The override set is bounded by what was parsed. That is a real blind
        spot, not a rounding error, so each virtual site carries a limitation
        rather than presenting its edge set as exhaustive.
        """
        for edge, caller_name in self.virtual_sites:
            base_usr = edge.callee
            if base_usr is None:  # pragma: no cover - virtual edges are resolved
                continue
            base_class = self._class_of(base_usr)
            if base_class is None:
                continue
            suffix = base_usr[len(base_class) :]
            overrides = [
                self.classes[derived].methods[suffix]
                for derived in sorted(self._derived_from(base_class))
                if suffix in self.classes[derived].methods
            ]
            for override in overrides:
                self.calls.append(edge.model_copy(update={"callee": override, "inferred": True}))
            self.limitations.append(
                limits.ambiguous_virtual_dispatch(
                    edge.site.path,
                    edge.site.start_line,
                    caller_name,
                    edge.spelling or base_usr,
                    len(overrides),
                )
            )

    def _class_of(self, method_usr: str) -> str | None:
        """The class USR a method USR belongs to, by longest known prefix."""
        candidates = [usr for usr in self.classes if method_usr.startswith(usr)]
        return max(candidates, key=len) if candidates else None

    def _derived_from(self, class_usr: str) -> set[str]:
        """Transitive closure of classes deriving from ``class_usr``."""
        found: set[str] = set()
        frontier = [class_usr]
        while frontier:
            current = frontier.pop()
            for candidate, info in self.classes.items():
                if current in info.bases and candidate not in found:
                    found.add(candidate)
                    frontier.append(candidate)
        return found

    def _classify_macro_calls(self) -> None:
        """Mark resolved calls whose text came from a macro expansion.

        Not applied to unresolved calls: "the target is unknown" is the more
        consequential fact about a call site, and one kind cannot say both.
        """
        if not self.macro_spans:
            return
        classified: list[CallEdge] = []
        for edge in self.calls:
            inside = any(
                path == str(edge.site.path)
                and start <= edge.site.start_byte
                and edge.site.end_byte <= end
                for path, start, end in self.macro_spans
            )
            if inside and edge.kind is CallKind.DIRECT:
                classified.append(edge.model_copy(update={"kind": CallKind.MACRO_EXPANDED}))
            else:
                classified.append(edge)
        self.calls = classified

    # ----------------------------------------------------------------- macros

    def _add_macro_definition(self, cursor: Any, relative: PurePosixPath) -> None:
        self._add_symbol(cursor, relative, SymbolKind.MACRO)

    def _add_macro_expansion(self, cursor: Any, relative: PurePosixPath) -> None:
        expansion = self._region(cursor, relative)
        if expansion is None:
            return
        extent = cursor.extent
        self.macro_spans.append((str(relative), int(extent.start.offset), int(extent.end.offset)))
        referenced = cursor.referenced
        definition_path = self._cursor_path(referenced) if referenced is not None else None
        name = str(cursor.spelling)
        if referenced is None or definition_path is None:
            self.limitations.append(limits.macro_expansion_unavailable(relative, name))
            return
        definition = self._region(referenced, definition_path)
        usr = self._usr(referenced)
        if definition is None or usr is None:  # pragma: no cover - guarded above
            self.limitations.append(limits.macro_expansion_unavailable(relative, name))
            return
        self.macros.append(
            MacroExpansion(name=name, usr=usr, definition=definition, expansion=expansion)
        )

    # ------------------------------------------------------------------ other

    def _add_inline_assembly(
        self, cursor: Any, relative: PurePosixPath, enclosing: str | None
    ) -> None:
        line = int(cursor.extent.start.line)
        self.limitations.append(limits.inline_assembly(relative, line, self._name_of(enclosing)))

    def _add_type_reference(self, cursor: Any, enclosing: str | None) -> None:
        if enclosing is None:
            return
        referenced = cursor.referenced
        if referenced is None:
            return
        type_usr = self._usr(referenced)
        if type_usr is not None and type_usr != enclosing:
            self.type_references.add((enclosing, type_usr))

    def _add_global_reference(self, cursor: Any, enclosing: str | None) -> None:
        """Record a read or write of a file-scope variable.

        Only ``VAR_DECL`` at namespace, record, or file scope counts. A
        ``DECL_REF_EXPR`` also names the callee of every call — the call graph
        already carries those — and every local, which is inside the enclosing
        function's own region and would be retrieved twice.

        The declaration a function touches is genuinely decisive: a global
        whose initializer sets the bound a loop trusts is the difference
        between a bug and a non-bug, and nothing in the function body says so.
        """
        if enclosing is None:
            return
        referenced = cursor.referenced
        if referenced is None or referenced.kind != self.kinds.VAR_DECL:
            return
        if not self._at_scope(referenced):
            return
        variable_usr = self._usr(referenced)
        if variable_usr is not None and variable_usr != enclosing:
            self.global_references.add((enclosing, variable_usr))

    # ---------------------------------------------------------------- helpers

    def _name_of(self, usr: str | None) -> str | None:
        if usr is None:
            return None
        symbol = self.symbols.get(usr)
        return symbol.name if symbol else None

    def _usr(self, cursor: Any) -> str | None:
        raw = str(cursor.get_usr()) if cursor is not None else ""
        if not raw:
            return None
        relative = self._cursor_path(cursor)
        return normalize_usr(raw, relative) if relative is not None else raw

    def _cursor_path(self, cursor: Any) -> PurePosixPath | None:
        if cursor is None:
            return None
        location = cursor.location
        file = location.file if location is not None else None
        return self._relative(str(file.name)) if file is not None else None

    def _relative(self, name: str | None) -> PurePosixPath | None:
        """Repository-relative path for a file Clang named, or ``None``.

        Clang reports a path the way it appeared on the command line, so a
        compilation database with relative arguments — what ``make``-based and
        Bear-generated databases produce — yields relative names here. Those
        are relative to the unit's build directory, which is what
        ``-working-directory`` told Clang, and emphatically not to wherever
        caudit happens to have been started from.

        Resolving them against the process CWD silently emptied the whole
        index: every cursor landed outside ``repo_root``, ``_walk`` skipped it
        and its children, and the parse still reported success. The result was
        an index with the file listed in ``indexed_files`` and no symbols,
        calls, or types in it — so retrieval found no containing function,
        every candidate reached the model with only its own line, and the
        model correctly declined to confirm anything. On the mini suite that
        alone took macro-F2 from 0.6667 to 0.1667.
        """
        if not name:
            return None
        try:
            candidate = Path(name)
            if not candidate.is_absolute():
                candidate = self.request.directory / candidate
            resolved = candidate.resolve()
        except OSError:  # pragma: no cover - defensive
            return None
        try:
            return PurePosixPath(resolved.relative_to(self.request.repo_root).as_posix())
        except ValueError:
            return None

    def _region(self, cursor: Any, relative: PurePosixPath) -> SourceRegion | None:
        """A hashed, whole-line region for a cursor's extent.

        Whole lines rather than exact columns, so an index region and a part 03
        evidence region for the same lines hash identically — a citation
        resolved against one cannot disagree with the other.
        """
        extent = cursor.extent
        start = max(1, int(extent.start.line))
        return self._line_region(relative, start, max(start, int(extent.end.line)))

    def _line_region(
        self, relative: PurePosixPath, start: int, end: int | None = None
    ) -> SourceRegion | None:
        """Hash a line span, memoized. ``None`` when the file cannot be read."""
        key = (str(relative), start, end or start)
        if key in self._region_cache:
            return self._region_cache[key]
        try:
            region = self.store.make_region(relative, key[1], key[2])
        except (RegionError, ValueError):
            region = None
        self._region_cache[key] = region
        return region


def _dedupe(limitations: Sequence[Limitation]) -> list[Limitation]:
    seen: list[Limitation] = []
    for limitation in limitations:
        if limitation not in seen:
            seen.append(limitation)
    return seen


def _callable_kinds(kinds: Any) -> set[Any]:
    """Cursor kinds a resolved call can point at."""
    return {
        kinds.FUNCTION_DECL,
        kinds.CXX_METHOD,
        kinds.CONSTRUCTOR,
        kinds.DESTRUCTOR,
        kinds.CONVERSION_FUNCTION,
        kinds.FUNCTION_TEMPLATE,
    }


def _symbol_kinds(kinds: Any) -> dict[Any, SymbolKind]:
    """Cursor kind → symbol kind. Built once per unit: the enum is libclang's."""
    return {
        kinds.FUNCTION_DECL: SymbolKind.FUNCTION,
        kinds.FUNCTION_TEMPLATE: SymbolKind.FUNCTION,
        kinds.CXX_METHOD: SymbolKind.METHOD,
        kinds.CONSTRUCTOR: SymbolKind.METHOD,
        kinds.DESTRUCTOR: SymbolKind.METHOD,
        kinds.CONVERSION_FUNCTION: SymbolKind.METHOD,
        kinds.VAR_DECL: SymbolKind.VARIABLE,
        kinds.ENUM_CONSTANT_DECL: SymbolKind.VARIABLE,
        kinds.STRUCT_DECL: SymbolKind.TYPE,
        kinds.UNION_DECL: SymbolKind.TYPE,
        kinds.CLASS_DECL: SymbolKind.TYPE,
        kinds.CLASS_TEMPLATE: SymbolKind.TYPE,
        kinds.ENUM_DECL: SymbolKind.TYPE,
        kinds.TYPEDEF_DECL: SymbolKind.TYPE,
        kinds.TYPE_ALIAS_DECL: SymbolKind.TYPE,
        kinds.FIELD_DECL: SymbolKind.FIELD,
        kinds.MACRO_DEFINITION: SymbolKind.MACRO,
    }


def _asm_kinds(kinds: Any) -> set[Any]:
    """Inline assembly cursor kinds this libclang exposes."""
    found = {getattr(kinds, name, None) for name in ("ASM_STMT", "MS_ASM_STMT", "GCC_ASM_STMT")}
    return {kind for kind in found if kind is not None}

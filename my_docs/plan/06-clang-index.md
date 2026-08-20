# Part 06 — Clang index

## Goal

Parse every selected translation unit with Clang and build the deterministic indices the rest of the system reasons over: symbols, references, call edges, includes, types, and macros — each anchored to a hashed source region. This is the "compiler-aware selection" step the spec places first in its technical sequence, and it is what makes retrieval structural rather than a text search.

It also upgrades the citation resolver from textual matching (part 03) to index-backed symbol and call-edge resolution, which is what part 11 needs to verify an LLM's claims.

## Depends on / Unlocks

- **Depends on:** 05.
- **Unlocks:** 07, 09, 11.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/index/parser.py` | libclang TU parsing, argument adaptation, diagnostics capture |
| `src/caudit/index/symbols.py` | Symbol table keyed by USR; definitions and declarations |
| `src/caudit/index/graphs.py` | Call graph, include graph, type and macro tables |
| `src/caudit/index/store.py` | On-disk index, content-hash keyed, incremental |
| `src/caudit/index/resolver.py` | `CitationResolver` v2 — symbol and call-edge resolution |
| `src/caudit/index/limits.py` | Detection and recording of analysis blind spots |
| `tests/integration/test_index_*.py`, `tests/fixtures/cpp/` | This part's tests |

## Interfaces

```python
class Symbol(BaseModel):
    usr: str                     # Clang USR — stable across runs
    name: str
    qualified_name: str
    kind: SymbolKind             # function | method | variable | type | macro | field
    definition: SourceRegion | None
    declarations: list[SourceRegion]
    is_definition_available: bool

class CallEdge(BaseModel):
    caller: str                  # USR
    callee: str | None           # None for unresolved indirect calls
    site: SourceRegion
    kind: CallKind               # direct | virtual | function_pointer | macro_expanded

class Index:
    def symbol(self, usr: str) -> Symbol | None: ...
    def symbols_named(self, name: str) -> list[Symbol]: ...
    def enclosing_function(self, path: PurePosixPath, line: int) -> Symbol | None: ...
    def callers_of(self, usr: str, depth: int = 1) -> list[CallEdge]: ...
    def callees_of(self, usr: str, depth: int = 1) -> list[CallEdge]: ...
    def types_referenced_by(self, usr: str) -> list[Symbol]: ...
    def macros_expanded_in(self, region: SourceRegion) -> list[MacroExpansion]: ...
    def includes(self, path: PurePosixPath) -> list[PurePosixPath]: ...
    def limitations(self) -> list[Limitation]: ...

def build_index(plan: ScanPlan, config: Config) -> Index:
    """Parses each TU. Parse failures are recorded, never swallowed."""
```

## Parsing rules

- Arguments come from the `ScanPlan` verbatim, minus compilation-only flags, plus `-fsyntax-only`. Nothing is added that the build did not specify.
- Parsing uses detailed preprocessing records so macro definitions and expansions are available — without them, a macro that hides a bounds check is invisible, which the spec calls out as exactly the kind of evidence that must not be lost.
- Parse diagnostics at error severity are recorded per TU. A TU that fails to parse is excluded from the index **and** produces a `Limitation` naming the file and the first error.
- Indexing is parallel across TUs with a per-TU timeout; a timeout is a `Limitation`, not a silent skip.
- The index is keyed by content hash of (TU file + arguments + all included file hashes), so an unchanged TU is not re-parsed on the next run.

## Blind spots are data

The spec twice insists that unavailable information be reported rather than assumed away. Each of these produces a typed `Limitation` attached to the affected region:

| Blind spot | Recorded as |
| --- | --- |
| Indirect call through a function pointer | `CallEdge(callee=None, kind=function_pointer)` + `Limitation` |
| Virtual dispatch with multiple overrides | Edges to all known overrides + `Limitation` noting the set may be incomplete |
| Inline assembly in a scanned function | `Limitation` on the enclosing symbol |
| Missing generated header | TU excluded + `Limitation` naming the header |
| Macro-generated code | Expansion recorded with both the expansion site and the definition site |

## Invariants

- **Every index entry carries a hashed `SourceRegion`.** An index that says "function `foo` is at line 40" without a hash cannot support the evidence gate.
- **Unresolved is not the same as absent.** Code paths must distinguish "no call edge exists" from "the call edge could not be resolved". Collapsing them lets a report imply a function is never called when in truth the caller was invisible.
- **The index is reproducible.** Same sources plus same arguments yields the same USRs, the same regions, and the same serialized index bytes.
- **USRs are the identity.** Names are for humans; deduplication, resolution, and graph edges key on USR, so overloads and static functions in different TUs never collide.

## Acceptance criteria

- **AC-06-1** For a fixture TU, the symbol table contains every function, global, type, and macro with correct kinds and definition regions.
- **AC-06-2** `enclosing_function` returns the correct symbol for lines inside a function, and `None` for lines at file scope.
- **AC-06-3** Call edges are found across translation units, including a caller in `a.c` invoking a definition in `b.c`.
- **AC-06-4** An indirect call yields an edge with `callee=None` and a recorded `Limitation`; it is never reported as "no callers".
- **AC-06-5** A macro used at a candidate site is retrievable with both its expansion site and its definition site.
- **AC-06-6** A TU that fails to parse is excluded, recorded with the first error, and does not abort the run.
- **AC-06-7** A per-TU timeout produces a `Limitation` naming the file.
- **AC-06-8** Two index builds over unchanged sources produce byte-identical serialized indices; an unchanged TU is not re-parsed on the second run.
- **AC-06-9** Resolver v2 resolves a citation naming a real symbol at a real location as `OK`, and returns `SYMBOL_NOT_FOUND` when the symbol exists elsewhere but not at the cited region.
- **AC-06-10** Resolver v2 returns `SYMBOL_NOT_FOUND` for a call edge asserted between two functions with no such edge in the index.
- **AC-06-11** Every `Limitation` produced by this part names a file and, where applicable, a symbol.
- **AC-06-12** A translation unit indexes identically whether its compilation database names the source absolutely or relatively. Clang reports paths as they appeared on its command line, and a relative one is relative to the unit's build directory — never to the directory C Audit was started from.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-06-01 | integration | `fixtures/cpp/basic/` — 3 functions, 1 struct, 2 macros | Symbol table matches the expected set with correct kinds | AC-06-1 |
| T-06-02 | integration | Overloaded C++ functions | Distinct USRs; `symbols_named` returns both | AC-06-1 |
| T-06-03 | integration | `static` functions with the same name in two TUs | Distinct USRs, no collision | AC-06-1 |
| T-06-04 | integration | Function spanning lines 10–30 | `enclosing_function` correct at 10, 20, 30; `None` at line 5 | AC-06-2 |
| T-06-05 | integration | `a.c` calls `b_func` defined in `b.c` | Edge present with `kind=direct` | AC-06-3 |
| T-06-06 | integration | Call through a function pointer table | Edge with `callee=None`, `kind=function_pointer`, `Limitation` present | AC-06-4 |
| T-06-07 | integration | Virtual method with two overrides | Edges to both; `Limitation` notes possible incompleteness | AC-06-4 |
| T-06-08 | integration | `#define CHECK_LEN(n) if ((n) < BUF_SZ)` used at a candidate site | Expansion and definition regions both retrievable | AC-06-5 |
| T-06-09 | integration | Function containing inline `asm` | `Limitation` on that symbol | AC-06-11 |
| T-06-10 | integration | TU including a header that does not exist | TU excluded, `Limitation` names the header, run continues | AC-06-6 |
| T-06-11 | integration | TU with a syntax error | Excluded with the first error message recorded | AC-06-6 |
| T-06-12 | integration | TU with an artificially low timeout | `Limitation` recorded; other TUs still indexed | AC-06-7 |
| T-06-13 | integration | Same tree indexed twice | Serialized index byte-identical; parse counter zero on second run | AC-06-8 |
| T-06-14 | integration | Tree where one file changed | Only the affected TUs re-parsed | AC-06-8 |
| T-06-15 | integration | Citation to `parse_header` at its real definition | Resolver v2 returns `OK` | AC-06-9 |
| T-06-16 | adversarial | Citation naming `parse_header` at a region containing only a comment mentioning it | `SYMBOL_NOT_FOUND` (v1 would have returned `OK`) | AC-06-9 |
| T-06-17 | adversarial | Asserted call edge `main → never_called_fn` | `SYMBOL_NOT_FOUND` with detail naming the missing edge | AC-06-10 |
| T-06-18 | adversarial | Citation to a plausible-looking symbol that does not exist at all | `SYMBOL_NOT_FOUND`, no exception | AC-06-9 |
| T-06-19 | unit | Index with unresolved indirect calls | `callers_of` result is distinguishable from "no callers"; API forces the caller to handle it | AC-06-4 |
| T-06-20 | perf | 200-TU fixture (`slow`) | Parallel index completes within the recorded budget; memory ceiling respected | — |
| T-06-24 | unit | One unit, two databases naming it absolutely and relatively (`needs_clang`) | Both index to the same symbols; `enclosing_function` resolves from the relative one. An empty result is the silent-empty-index failure | AC-06-12 |

## Out of scope and risks

- No bug detection here — the index is neutral infrastructure.
- Cross-language and non-Clang-parseable sources are excluded upstream in part 05.
- **Risk:** libclang exposes less than LibTooling; some type or template detail may be unavailable. Mitigation: the interface above is what later parts consume, so a future LibTooling-backed implementation can replace `Index` without touching parts 07–11. If a needed fact turns out to be unavailable, it becomes a `Limitation` rather than an approximation.
- **Risk:** index size on large repositories. Mitigation: content-hash keying with incremental rebuilds; regions are stored, source text is not duplicated.

### Deviations taken while implementing this part

Recorded here so the interface above is read as intent rather than as literal signatures.

- `callers_of` and `callees_of` return a `CallQuery`, not `list[CallEdge]`. A list makes `if not index.callers_of(usr):` read as "nothing calls it" while unresolved indirect sites sit in the same answer, which is the exact collapse the invariants forbid. `CallQuery` carries `edges`, `unresolved`, and `is_complete`, and defines neither `__len__` nor `__bool__`, so the collapse cannot be written by accident.
- The parallel runner lives in a seventh module, `index/workers.py`. Neither a thread pool nor `ProcessPoolExecutor` can enforce a per-TU timeout — a libclang parse is a C call that cannot be interrupted, and 3.12 has no supported way to kill a pool worker — so the pool owns its processes and replaces one that overruns.
- The `libclang` wheel ships no Clang resource directory, so a TU including `<stddef.h>` does not parse. Discovering one would be inferring an include path, so it is a configuration key (`index.resource_dir`), unset by default, and the parse failure names the fix.
- Index regions are whole-line spans, hashed exactly as part 03 hashes them, so an index fact and an evidence region covering the same lines cannot disagree on their hash.

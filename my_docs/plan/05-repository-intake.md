# Part 05 — Repository intake

## Goal

Turn "a directory the user pointed at" into a validated, revision-pinned scan plan. This part implements the spec's most opinionated MVP decision: **a valid `compile_commands.json` is required, and if it is absent or materially incomplete the tool stops with setup instructions rather than guessing flags.**

Getting this wrong produces silent nonsense downstream — an index built from wrong include paths finds wrong symbols, and every finding above it inherits the error.

## Depends on / Unlocks

- **Depends on:** 01.
- **Unlocks:** 06, 07, 08.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/intake/compdb.py` | Compilation database loading, normalization, flag extraction |
| `src/caudit/intake/filters.py` | Third-party, generated, size, and target filters |
| `src/caudit/intake/revision.py` | Repository root and revision resolution |
| `src/caudit/intake/coverage.py` | Coverage accounting and the completeness decision |
| `src/caudit/intake/plan.py` | `ScanPlan` — the validated output of this part |
| `tests/unit/test_intake_*.py`, `tests/fixtures/compdb/` | This part's tests |

## Interfaces

```python
class TranslationUnit(BaseModel):
    file: PurePosixPath          # repository-relative
    directory: Path              # absolute working directory for the command
    arguments: list[str]         # normalized argv, response files expanded
    output: str | None
    language: Literal["c", "c++"]
    std: str | None              # e.g. "c11", "c++17"

class ExclusionReason(StrEnum):
    THIRD_PARTY = "third_party"
    GENERATED = "generated"
    TOO_LARGE = "too_large"
    NOT_SELECTED = "not_selected"     # --target narrowing
    MISSING_SOURCE = "missing_source"
    UNSUPPORTED_LANGUAGE = "unsupported_language"

class Coverage(BaseModel):
    tus_in_database: int
    tus_selected: int
    tus_excluded: Mapping[ExclusionReason, int]
    source_files_in_tree: int
    source_files_covered: int
    coverage_ratio: float

class ScanPlan(BaseModel):
    repo_root: Path
    revision: str                # git sha, or "unknown"
    dirty: bool
    compile_commands_path: Path
    units: list[TranslationUnit]
    excluded: list[tuple[PurePosixPath, ExclusionReason]]
    coverage: Coverage
    limitations: list[Limitation]

def load_scan_plan(root: Path, compdb: Path, config: Config) -> ScanPlan:
    """Raises IntakeError (exit ENVIRONMENT) when the database is absent or
    materially incomplete. Never infers flags."""
```

## Compilation database handling

The [Clang JSON compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html) format has more variation than it first appears, and each variation is a real fixture:

- Both the `command` string form and the `arguments` array form. The string form is split with shell rules, not `str.split()`.
- `directory` is the working directory; relative `file` entries resolve against it, and the result is then made repository-relative.
- Response files (`@flags.rsp`) are expanded, recursively, with a depth cap.
- Duplicate entries for the same file (multi-config builds) are deduplicated deterministically: last entry wins, and the collision is recorded.
- Compilation-only flags are stripped for parsing (`-c`, `-o <path>`, `-M*` dependency generation) and `-fsyntax-only` is added by part 06.
- Language and standard are derived from the flags (`-x`, `-std=`), falling back to the file extension, and recorded — the spec scopes the MVP to C11+ and C++17+.
- Header files usually have no entry of their own; they are reached through the TUs that include them (part 06), not invented here.

## "Materially incomplete"

The spec requires stopping when the database is materially incomplete, so the phrase needs a number rather than a judgement call:

- **Hard stop (exit `ENVIRONMENT`)** when: the file is missing, unparseable, empty, contains zero entries matching the scan roots, or an explicitly requested `--target` has no entry.
- **Hard stop** when `coverage_ratio` — source files under the scan roots that appear in some TU, over source files present — falls below a configurable floor (default 0.60), unless `--allow-partial-coverage` is passed.
- **Proceed with a recorded `Limitation`** when coverage is above the floor but below 1.0, or when individual TUs reference files missing from disk.

Every stop prints: what was expected, what was found, and the `cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` recipe (or the Bear/`compiledb` equivalent for non-CMake builds).

## Invariants

- **No inferred flags.** There is no code path that fabricates an include path, a macro definition, or a language standard. `compile_flags.txt` and best-effort mode are explicitly deferred; the spec says a later best-effort mode must mark its findings lower confidence, which cannot be honoured until part 02's confidence machinery is exercised end to end.
- **Third-party and generated code are excluded by default.** Defaults cover `third_party/`, `3rdparty/`, `vendor/`, `external/`, `build/`, `node_modules/`, and generated markers (`*.pb.cc`, `*.pb.h`, `moc_*`, `*_generated.*`, files whose first 5 lines contain a generated-file banner). Opt-in via explicit config, never by accident.
- **Coverage is reported, not smoothed.** The numbers in `Coverage` flow into the report (part 08) verbatim so a reader can see what was not looked at.
- **The revision is pinned once**, at the start, and a dirty working tree is recorded as such. A non-git directory yields `revision="unknown"` plus a `Limitation` — it does not abort, but it does mean the report cannot claim reproducibility.

## Acceptance criteria

- **AC-05-1** Both `command` and `arguments` forms produce identical `TranslationUnit` objects for the same logical entry.
- **AC-05-2** Relative `file` paths resolve against `directory` and are stored repository-relative.
- **AC-05-3** Response files are expanded; a self-referential response file fails cleanly at the depth cap.
- **AC-05-4** A missing, empty, or unparseable database exits `ENVIRONMENT` with the setup recipe in the message.
- **AC-05-5** Coverage below the floor exits `ENVIRONMENT` naming the ratio and the floor; `--allow-partial-coverage` converts it to a recorded `Limitation`.
- **AC-05-6** A `--target` with no matching entry exits `ENVIRONMENT`; a `--target` that matches narrows the plan and records the rest as `NOT_SELECTED`.
- **AC-05-7** Default exclusions remove vendored and generated files, and each exclusion is attributed to a reason.
- **AC-05-8** Duplicate entries for one file are resolved deterministically and the collision is recorded.
- **AC-05-9** Language and standard are derived correctly from `-x`, `-std=`, and extension fallback; an unsupported standard is excluded with `UNSUPPORTED_LANGUAGE`.
- **AC-05-10** A dirty working tree sets `dirty=True`; a non-git directory sets `revision="unknown"` with a `Limitation`.
- **AC-05-11** `ScanPlan` is fully serializable and identical across two runs on unchanged inputs.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-05-01 | unit | Same entry as `command` string and `arguments` array | Resulting `TranslationUnit`s are equal | AC-05-1 |
| T-05-02 | unit | `command` with quoted paths and escaped spaces | Shell-aware split preserves the argument | AC-05-1 |
| T-05-03 | unit | `directory: /abs/build`, `file: ../src/a.c` | Stored as `src/a.c` | AC-05-2 |
| T-05-04 | unit | Entry using `@flags.rsp` containing `-I` paths | Flags expanded inline | AC-05-3 |
| T-05-05 | unit | Response file including itself | Fails at depth cap with a clear error, no infinite loop | AC-05-3 |
| T-05-06 | unit | No `compile_commands.json` | Exit 3; message contains the `cmake … -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` recipe | AC-05-4 |
| T-05-07 | unit | Truncated JSON; `[]`; JSON object instead of array | Exit 3 for each, message distinguishes the three causes | AC-05-4 |
| T-05-08 | unit | 10 source files, 3 covered (ratio 0.30) | Exit 3 naming 0.30 and the 0.60 floor | AC-05-5 |
| T-05-09 | unit | Same, with `--allow-partial-coverage` | Proceeds; `Limitation` recorded with the ratio | AC-05-5 |
| T-05-10 | unit | Ratio exactly at the floor | Proceeds (boundary documented) | AC-05-5 |
| T-05-11 | unit | `--target src/missing.c` | Exit 3, message lists the nearest available targets | AC-05-6 |
| T-05-12 | unit | `--target src/a.c` in a 5-entry database | 1 selected, 4 excluded as `NOT_SELECTED` | AC-05-6 |
| T-05-13 | unit | Tree with `third_party/`, `moc_x.cpp`, `x.pb.cc`, generated banner file | All excluded with the right reason | AC-05-7 |
| T-05-14 | unit | Vendored path plus explicit opt-in config | Included, and the opt-in is recorded in the plan | AC-05-7 |
| T-05-15 | unit | Two entries for `src/a.c` (debug and release) | One unit; collision recorded; result stable across shuffles | AC-05-8 |
| T-05-16 | unit | Entries with `-std=c++17`, `-std=c99`, `-x c++`, bare `.cc` | Standard and language correct; `c99` excluded as unsupported | AC-05-9 |
| T-05-17 | unit | Entry whose `file` is missing on disk | Excluded as `MISSING_SOURCE`, `Limitation` recorded, run continues | AC-05-5 |
| T-05-18 | unit | Git fixture with an uncommitted change | `dirty=True`, revision is the HEAD sha | AC-05-10 |
| T-05-19 | unit | Plain directory, no `.git` | `revision="unknown"` plus `Limitation`; no crash | AC-05-10 |
| T-05-20 | unit | Same inputs, two loads | `ScanPlan` JSON identical, unit order stable | AC-05-11 |
| T-05-21 | integration | Real CMake fixture project (`needs_clang`) | Generated database loads; all TUs selected; coverage 1.0 | AC-05-1, AC-05-2 |

## Out of scope and risks

- Parsing the TUs (part 06) and running analyzers over them (part 07).
- Best-effort mode from `compile_flags.txt` — deferred post-MVP; when it lands, its findings must be labeled lower confidence.
- **Risk:** the 0.60 coverage floor is a guess. Mitigation: it is configurable, printed in every stop message, and revisited against real repositories in part 13.
- **Risk:** generated-code detection by banner text is heuristic and can exclude hand-written files. Mitigation: every exclusion is listed in the report with its reason, so a surprising exclusion is visible rather than silent.

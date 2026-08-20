# Mini benchmark suite

Six hand-written cases, one per in-scope weakness family, committed to the
repository so that CI never downloads CASTLE or Juliet and the default test
suite runs offline on a machine with no LLVM installed.

| Case | Family | Truth CWE | Analyzer blind spot |
| --- | --- | --- | --- |
| `oob-write-stack-copy` | out_of_bounds | CWE-787 | no |
| `uaf-double-free` | memory_lifetime | CWE-416 | no |
| `null-deref-unchecked-alloc` | null_uninitialized | CWE-476 | **yes** |
| `integer-truncation-alloc` | integer | CWE-197 | **yes** |
| `resource-leak-error-path` | resource_leak | CWE-772 | no |
| `format-string-user-input` | injection | CWE-134 | no |

## Why two cases are expected to fail

The suite was written by the same project it measures, so it can encode the
tool's blind spots without anyone noticing. Two cases are missed by the
deterministic analyzers, and a run in which *every* case passes is evidence
that something is wrong with the harness rather than that the tool is perfect.

**Which two changed on 2026-08-15**, when the suite was first scored against a
real toolchain instead of authored expectations. The flags had been predictions,
and two of them were wrong:

* `resource-leak-error-path` was predicted to be missed and is **detected**.
  `alpha.unix.Stream` reports CWE-775 at the truth line, which the matching
  policy accepts as equivalent to CWE-772. The prediction assumed the alpha
  checkers were off; the curated profile enables them.
* `null-deref-unchecked-alloc` was predicted to be detected and is **missed**.
  clang 18.1.3 reports nothing for a `calloc` result written through with no
  null check, on the curated profile or on a bare `clang --analyze`: the
  analyzer does not split the state on allocation failure unless something
  else in the function constrains the pointer.

So the reason the two failures are cross-TU no longer holds for both. One is
cross-TU (`integer-truncation-alloc`); the other is a path-sensitivity limit
in a single function. Both are recorded in the case's `note`.

## Files in a case

| File | Purpose |
| --- | --- |
| `case.json` | Ground truth: path, line, CWE, family, variant |
| `src/*.c`, `src/*.h` | The case itself |
| `compile_commands.template.json` | Compilation database with a `${CASE_ROOT}` placeholder, materialised at run time by `MiniSuite.materialize_compile_commands` |
| `baseline-candidates.json` | Recorded analyzer output, replayed by `RecordedCandidateSource` |

## About `baseline-candidates.json`

These recordings are **captures from a real toolchain** as of 2026-08-15:
clang and clang-tidy 18.1.3, recorded by `make record-baseline`. Each file
carries `"source": "captured"` and the analyzers' true versions. They exist so
the pipeline can be exercised end to end offline, which is what CI does.

They were authored expectations until then, and the difference was not
cosmetic — three of the six disagreed with what clang actually emits, in both
directions. Two blind-spot flags were wrong as a result. Do not reintroduce a
hand-written recording; regenerate with:

```bash
make record-baseline
```

which requires a real `clang` and `clang-tidy` and replays nothing.

**The recorder runs the same pass `caudit scan` runs** — `generate_candidates`
under the curated profile — so `caudit eval --recorded` and
`caudit eval --use-clang` score the same tool and produce identical metrics.
That equality is asserted by test. It did not hold before 2026-08-15: the
recorder used part 04's `ClangBaselineSource`, whose ad-hoc check list enables
no compiler diagnostics and no alpha checkers, so the published baseline
scored a ruleset this project does not ship.

Regions are never taken on trust from a recording: `RecordedCandidateSource`
rebuilds every `SourceRegion` from the fixture files on disk, so all hashes
are computed from real bytes.

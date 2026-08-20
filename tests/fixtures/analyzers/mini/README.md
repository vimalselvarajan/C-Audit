# Recorded analyzer output for the mini suite

Native-format analyzer output for `benchmarks/mini/`, committed so part 07's
integration tests exercise the real SARIF, YAML, and diagnostic parsers on a
machine with no LLVM installed.

**These are authored expectations, not captures.** The machine this project was
written on has no Clang, so each file states what the profile's checks are
expected to report — the same expectation already committed as
`benchmarks/mini/<case>/baseline-candidates.json` for part 04, re-expressed in
the format the tool actually emits. `tool_version` is `unrecorded` rather than
an invented number. T-07-21 runs the real toolchain over the same suite under
the `needs_clang` marker and is what confirms them.

Two cases have no recording, deliberately:

| Case | Why |
| --- | --- |
| `integer-truncation-alloc` | The truncation is an explicit cast and the loop bound comes from another translation unit. No checker in the profile relates the two widths. |
| `resource-leak-error-path` | The leaking branch is guarded by a predicate defined in another translation unit. |

Both are flagged `analyzer_blind_spot` in `case.json`, and part 07's tests
assert the *absence* of a candidate for them. A suite where every case is found
would be evidence that the fixtures were written to match the tool rather than
the other way round — the analyzer-bias risk the plan names for this part. If a
real capture ever produces a diagnostic for one of them, drop the flag and add
the recording rather than leaving a stale claim in place.

## Offset placeholders

`clang-tidy --export-fixes` addresses source by byte offset, which no human can
write by hand and which moves whenever a line above it changes. Recordings for
that format are templates using `${OFFSET:<repo-relative path>:<line>}`, which
the test helper resolves against the real fixture source — the same reason
`compile_commands.template.json` carries `${CASE_ROOT}`.

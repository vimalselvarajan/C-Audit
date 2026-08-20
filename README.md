# C Audit

Compiler-aware, evidence-gated auditing for C and C++.

> **Use AI to connect and explain evidence, not to invent it.**

Deterministic static analysis generates candidates, a model adjudicates and
explains them under a strict schema, and deterministic verification rejects
anything whose cited evidence does not resolve against the scanned revision.

- Documentation: [my_docs/README.md](my_docs/README.md)
- Design: [my_docs/specification/core_idea.md](my_docs/specification/core_idea.md)
- Plan: [my_docs/plan/00-overview.md](my_docs/plan/00-overview.md) — 13 parts, four milestones
- Setup: [my_docs/guides/setup.md](my_docs/guides/setup.md)

## Status

**Milestones 0 and 1 complete** (parts 01–08), M2's three parts (09–11) built
with them, and part 12 assembled on top. The measurement machinery exists
before the thing being measured, which is the point of the ordering: the data
contracts, the citation resolver, and the fabrication gate were all built and
tested before anything could produce a claim — so by the time a model appears
in part 10, the machinery that rejects its output already exists.

| Milestone | Parts | State |
| --- | --- | --- |
| M0 Evaluation harness | 01, 02, 03, 04 | **done** |
| M1 Deterministic scanner | 05, 06, 07, 08 | **done** |
| M2 Gemini adjudication | 09, 10, 11 | **measured, and it clears its gate on CASTLE** |
| M3 Repository-scale validation | 12, 13 | parts built; pairs and maintainability still need data |

### Measured results

Every figure comes from running the analyzers this project ships — curated
profile v1 under clang 18.1.3 — not from replaying a fixture. Full detail,
including what was withdrawn and why, is in
[my_docs/project/evaluation-results.md](my_docs/project/evaluation-results.md).

| Corpus | Cases | analyzers only | + Gemini | Δ | Gates |
| --- | --- | --- | --- | --- | --- |
| CASTLE (third-party) | 110 of 250 | 0.2290 | **0.2903** | **+0.0613** | **4 of 4** |
| `benchmarks/mini` (ours) | 6 | 0.6667 | 0.5000 | −0.1667 | 3 of 4 |

On CASTLE, adding the model **raised macro-F2 by 27% relative and more than
halved the false-positive rate** — FP/KLOC 13.665 → 5.797, false positives
33 → 14, true positives 23 → 28. Every hard gate passes, `baseline_floor`
included. 254 provider calls, 352k tokens, 82 minutes.

Every run resolves **100% of its citations** — 792/792 and 593/593 — with zero
fabricated files, symbols, or analyzer names. For a tool whose premise is that
a model may connect evidence but never invent it, that is the number to read
first.

The synthetic and the real figure are reported side by side and never averaged.
Six cases this project wrote are a precondition for credibility, not evidence
of it. The mini suite has zero false positives at baseline and its two misses
generate no candidates, so it has nothing for a model to win and its score can
only fall — which is what the −0.1667 is, and it is one case where Gemini
answered CWE-120 for an unbounded `strcpy`, a mapping outside our allowlist
rather than a wrong one.

**What bounds the result is the candidate set.** The analyzers decide what is
visible; a defect that produces no candidate is never put to the model. Within
that set adjudication moves both ways — on CASTLE it rejected noise in 18 cases
and *rescued* 7 findings the deterministic tier could not classify — but it
cannot see what was never flagged. Recall remains the binding constraint, and
raising it needs a candidate generator, not a better prompt.

M3 remains open for want of data, not code. Repository pairs need pinned SHAs
and per-project build toolchains; the maintainability set needs at least two
independent human labellers per case.

**C Audit is already useful with no AI in it.** `caudit scan` validates the
build description, parses every selected translation unit with Clang, runs the
curated analyzer profile, gates every finding on whether its cited evidence
resolves against the scanned revision, and writes `report.md`,
`results.sarif` (SARIF 2.1.0) and `run-manifest.json`. Two runs of one
revision produce byte-identical Markdown and SARIF; every clock reading and
absolute path lives in the manifest alone.

Exit codes say what happened: `1` when something was confirmed, `0` when the
analyzers ran and found nothing, `3` when they could not run at all — because
`0` must never mean "we did not look".

Indexing needs no system LLVM: it runs on the `libclang` wheel, which bundles
its own shared library. Candidate generation needs `clang` and `clang-tidy` on
`PATH`; without them the scan still writes all three artifacts, and the report
opens by saying nothing was examined.

**Nothing is sent anywhere without consent.** `caudit scan` now runs the whole
pipeline — intake, index, candidates, expansion, adjudication, the gate,
ranking, rendering — and the model half of it only exists on the consented
branch. Without `--consent-cloud` or a recorded consent, no provider is
constructed, no socket can be opened, and the report is byte-for-byte the
Milestone 1 baseline. `--dry-run-prompts` still assembles every request body
into `<out>/prompts` and transmits none of them, so what would be sent can be
read first.

**Findings are ranked, and the ranking explains itself.** Severity comes from
the CWE family table rather than from anything a model wrote, confidence is the
gate's, and each finding renders a one-line "why this rank" built from the same
five inputs the sort key uses — so the order is auditable rather than
mysterious. Review-required items are ranked in their own section and cannot
appear in the confirmed list at any rank.

## Quick start

```bash
make bootstrap
```

```bash
.venv/bin/caudit doctor
```

```bash

### Audit a repository inside C Audit

Keep repositories being audited in `audit-targets/`, not beside the C Audit
checkout. Cloning stays an ordinary Git operation:

```bash
mkdir -p /home/vimdim/personal/c_audit/audit-targets

git clone \
  https://github.com/vimalselvarajan/Combat-Chess.git \
  /home/vimdim/personal/c_audit/audit-targets/Combat-Chess

cmake \
  -S /home/vimdim/personal/c_audit/audit-targets/Combat-Chess \
  -B /home/vimdim/personal/c_audit/audit-targets/Combat-Chess/build \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Run C Audit from its own checkout and give both the input and output as
absolute paths:

```bash
cd /home/vimdim/personal/c_audit

.venv/bin/caudit \
  --set index.resource_dir="$(clang -print-resource-dir)" \
  scan /home/vimdim/personal/c_audit/audit-targets/Combat-Chess \
  --compile-commands /home/vimdim/personal/c_audit/audit-targets/Combat-Chess/build/compile_commands.json \
  --out /home/vimdim/personal/c_audit/caudit-report/combat-chess/scan
```

`audit-targets/` is ignored, guard-protected, excluded from mutating
pre-commit hooks, and preserved by `make clean`. Reports are disposable:
`make clean` may remove everything under `caudit-report/`. Use sibling output
directories such as `dryrun/` and `adjudicated/` so each run keeps its own
`report.md`, `results.sarif`, and `run-manifest.json`.
.venv/bin/caudit eval --suite mini --baseline --out caudit-eval
```

The mini suite runs offline, with no LLVM installed and no network access.

Intake works offline too, against any project with a compilation database:

```bash
.venv/bin/caudit scan . --compile-commands build/compile_commands.json --out caudit-report
```

That writes `caudit-report/report.md`, `caudit-report/results.sarif`, and
`caudit-report/run-manifest.json`.

The retrieval ablation runs offline too, and answers the question this project
has the most to lose from — whether compiler-aware retrieval beats reading a
window of lines around the diagnostic:

```bash
.venv/bin/caudit ablate --suite mini --out caudit-ablation
```

On the mini suite the flat-window control retrieves the same share of the
decisive code and spends 3.4x the tokens. Read the caveats in
[my_docs/project/evaluation-results.md](my_docs/project/evaluation-results.md) before quoting that:
the cases are shorter than the window, and whether structural retrieval helps
a model *find* more is a separate question that needs an API key.

For the paths that do need one, copy the template, fill it in, and load it:

```bash
cp .env.example .env && source tools/load-env.sh
```

`caudit` does not read `.env` — the shell exports it and `caudit` reads the
environment, as it always has. `.env` is gitignored and refused by `make guard`,
and a key alone still sends nothing without `--consent-cloud`. See
[my_docs/guides/setup.md](my_docs/guides/setup.md) section 5.

## What exists

| Area | Module | Part |
| --- | --- | --- |
| CLI, exit codes, layered config, toolchain probe, secret-safe logging | `cli/`, `config/`, `logging.py` | 01 |
| Candidate, Evidence, Finding, RunManifest, CWE rules, stable ids, exported JSON Schema | `model/`, `schemas/` | 02 |
| Source store, region hashing, citation resolver, evidence bundle | `evidence/` | 03 |
| Benchmark adapters, matching policy, metrics, hard gates, traces | `eval/`, `benchmarks/mini/` | 04 |
| Compilation database, filters, revision pinning, coverage accounting | `intake/` | 05 |
| libclang parsing, symbols, call/include/macro/type graphs, incremental index, citation resolver v2 | `index/` | 06 |
| Clang diagnostics, Static Analyzer, curated `clang-tidy` profile, normalization, provenance-preserving dedup | `analyzers/` | 07 |
| Evidence gate, Markdown, SARIF 2.1.0, `run-manifest.json`, byte-reproducible output | `report/` | 08 |
| Dependency closure, caller/callee and cleanup-path expansion, token budget, reversible handles | `retrieval/` | 09 |
| Consent gate, redaction, versioned prompts, tier routing, structured output, response cache, token/cost accounting | `llm/` | 10 |
| Citation and call-edge resolution, quotation checking, CWE preconditions, claim downgrades, confirmed vs needs-review routing | `verify/` | 11 |
| Ranking and its explanation, pipeline assembly, per-claim AI provenance, stage timings, `caudit compare` | `report/ranking.py`, `report/assembly.py`, `cli/scan.py`, `cli/compare.py`, `eval/compare.py` | 12 |
| Vulnerable/fixed pair harness, labelled maintainability set, ablation grid with its control, confidence calibration | `eval/pairs.py`, `eval/maintainability.py`, `eval/ablation.py`, `eval/calibration.py` | 13 |
| Retrieval variants, checkout-and-build for a pair, calibration from ground truth, and the commands that run them | `retrieval/policy.py`, `eval/ablation_runner.py`, `eval/pairs_runner.py`, `cli/ablate_cmd.py`, `cli/pairs_cmd.py`, `cli/calibrate_cmd.py` | 13 |

## Invariants this codebase enforces

- A finding is reported only if every cited file, line, symbol, and call edge
  resolves. Everything else goes to **Needs review**.
- Confirmed findings and review-required candidates are never merged into one
  count — there is no field or method anywhere that returns the sum.
- Impact, reachability, and exploitability are three separate fields, and no
  code path infers one from another.
- Hashes are over exact bytes: no whitespace, line-ending, or encoding
  normalisation.
- A model may cite only an evidence id it was issued. An invented id fails
  before any file is opened.
- A cited symbol has to be *at* the cited region according to the index, not
  merely mentioned in it — a comment naming a function is not evidence about
  that function.
- An indirect call is an edge with an unknown target, never a missing edge.
  "Nothing calls this" is not expressible from a caller set that had unresolved
  sites in it.
- `GEMINI_API_KEY` never reaches a log record at any level, and is not a
  configuration field, so it cannot be dumped.
- No include path, macro definition, or language standard is ever inferred. A
  missing or materially incomplete `compile_commands.json` stops the run with
  setup instructions.
- Coverage is reported, not smoothed: the plan and the report carry what was
  never looked at, and why — including when coverage is complete, so a reader
  never has to infer whether something was skipped.
- `report.md` and `results.sarif` contain no timestamp, no duration and no
  absolute path, so they diff cleanly across runs and machines. Everything
  machine-specific is in `run-manifest.json`.
- A run whose analyzer version, policy version, or revision is unknown fails
  rather than writing a manifest with a null in it. Reproducibility is the
  point of the file.
- A review-required item exports as SARIF `kind="review"` at `level="none"`,
  so a code-scanning system cannot count it as a vulnerability.
- Retrieved code is never truncated, summarised, or paraphrased. A unit is
  included whole or dropped whole, the drop becomes a `Limitation`, and only
  duplicate analyzer messages may be compressed — a rule the type system
  holds, not a convention.
- When the code needed to judge a candidate does not fit the token budget,
  nothing is sent and the candidate becomes `review_required` /
  `context_budget_exceeded`. A half-function produces a confident answer to a
  question nobody asked.
- Everything retrieved keeps a handle to its exact original bytes, including
  what was dropped, so any part of a context can be expanded back to source.
- No bytes reach a hosted model without an explicit consent signal. The only
  component that can open a socket takes the consent decision as a constructor
  argument, so "was consent checked?" is answered by the type.
- The only route from a response to a claim is schema validation. A confident
  paragraph, a truncated object, and JSON with an extra key all end the same
  way: retried, then routed to review. There is no lenient parser to fall back
  on, so there is nothing to weaken later.
- A model may cite only an evidence id this candidate's context issued. An
  invented one is rejected without a retry, and an id borrowed from a different
  candidate is rejected too, even though it resolves.
- Triage decides which tier answers, never what is reported. A candidate the
  cheap tier dismisses stays in the report on the analyzer's word. Nor does the
  tier that *did* read the code get to delete one: a model's rejection becomes a
  review item carrying its argument, for a human to confirm.
- The gate that decides whether a proposal becomes a finding is deterministic
  and model-free. Its signature has no provider, no consent decision and no
  `Config` in it, so "can this be configured off?" is answered by the type.
- Every applicable reason is reported, not the first. A review item saying only
  "hash mismatch" when the CWE was also wrong costs the reviewer the second
  discovery, and the gate already knows.
- A claim is only ever lowered, never raised. `reachability="demonstrated"`
  without control-flow evidence is capped at `argued` and the finding survives
  — the hard gate is on fabricated evidence, not on cautious findings — and the
  weakening reaches the page as a limitation rather than being applied silently.
- A quotation is compared byte for byte against the bytes the model was shown,
  whitespace included. It is the one claim *about* source that a machine can
  settle exactly, which is why quoting is a field rather than something read
  back out of a rationale.
- "The index records no call from `a` to `b`" is never rendered as "no such call
  exists", and a name the index has never heard of is reported as a fabricated
  symbol rather than as a missing edge.
- `confidence` is computed from whether the citations resolved. How sure a model
  says it is, is advisory and is not copied anywhere.
- Excluded files are filtered out before a prompt is assembled and asserted
  against afterwards. The second check raises rather than trimming: a check
  that silently repairs a leak removes the only signal that one happened.
- Credential-shaped strings are scrubbed before assembly and the count is
  recorded. A redaction inside a primary unit becomes a `Limitation`, because
  the model then read text that differs from the code.
- Prompts and responses are not persisted. The response cache stores a prompt
  fingerprint and the parsed result; retaining the raw exchange is an explicit
  setting that the manifest records.
- Nothing a model wrote can move a finding up the report. Severity comes from
  the committed CWE family table capped by the impact kind — a value from a
  fixed enum, applied as a ceiling that can only lower — and `impact.severity`
  is never read by the ranking at all.
- Every candidate reaches the report exactly once. A context that would not
  fit, a provider that went away, a budget that bound, a proposal the gate
  refused: each is a finding carrying a reason, never a candidate that
  disappeared because a later stage failed.
- A stage that fails degrades the run rather than ending it. The report, the
  SARIF invocation and the manifest all say the run was partial, and a partial
  run can never exit `0`.
- A translation unit that will not parse is *not* a partial report. It is
  counted in coverage, named in a limitation, and printed in the coverage
  section — a marker that fired on every repository with an unparseable header
  would stop being read.
- Two runs with a warm cache produce byte-identical Markdown and SARIF, model
  included. Call counts and token totals appear only in the manifest, because
  a warm run makes zero calls where the cold run that filled the cache made
  several.
- `caudit compare` refuses two runs scored under different matching or profile
  versions, or over different cases. What it cannot check — an unrecorded
  version, an unrecorded case list — becomes a stated caveat rather than a
  silent assumption.
- The prompt version is compared only when *both* runs had a model in them. An
  analyzer-only baseline never assembled a prompt, and requiring one to match
  would refuse exactly the comparison Milestone 2 is defined by.
- A repository pair that will not build is excluded **with a reason**, and
  counted in neither the numerator nor the denominator. Quietly dropping the
  projects that stop building is how a benchmark reports a rising score for a
  falling tool.
- A maintainability label needs at least two *distinct* human labellers, and is
  refused if its recorded source names an analyzer this project runs. Labels
  adjudicated from the tool's own checks score the tool against itself.
- Every ablation grid contains the flat-window control, added whether or not it
  was asked for. Without it the suite measures how well structural retrieval is
  tuned rather than whether it is worth having — and "we did not run the
  control" is reported as `None`, never as a win.
- Confidence labels are checked against ground truth: if `high` findings are
  true less often than `medium` ones, the labels are decoration and the overall
  score is refused rather than printed.
- No result is ever pooled across policy versions. Pair outcomes, calibration
  curves and comparisons all raise, with both configurations named.

## Development

```bash
make check
```

ruff, mypy `--strict`, JSON Schema drift check, and pytest with an 85%
coverage floor. CI invokes the same target.

`needs_clang`, `needs_network`, and `slow` are deselected by default.
`needs_libclang` is not: indexing runs on the wheel, so those tests are part of
the default suite and skip only if the wheel cannot be loaded.

Adjudication is tested from committed cassettes in `tests/cassettes/`, so the
default suite opens no socket and needs no API key. A cassette records the
prompt version it was captured against and refuses a request assembled from a
different one, so bumping the prompt version without re-recording fails loudly
instead of testing instructions that no longer exist.

## Layout

```
src/caudit/       the package (see the table above)
schemas/          exported JSON Schema + the vendored official SARIF 2.1.0 schema
benchmarks/mini/  six committed cases, one per weakness family
tests/            unit, contract, adversarial, golden, e2e, integration, fixtures
my_docs/          documentation index, specification, plan, guides, and project records
inspiration_repos/  read-only upstream clones; not part of C Audit
```

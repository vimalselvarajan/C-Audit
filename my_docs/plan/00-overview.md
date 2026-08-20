# C Audit Implementation Plan — Overview

> Derived from [core_idea.md](../specification/core_idea.md). Plan last revised: 2026-08-15,
> across three passes that day. AC-06-12 and T-06-24: a compilation database
> with relative arguments used to produce a silently empty index. AC-04-12 to
> AC-04-16 and T-04-21 to T-04-29: the candidate source is selectable from the
> command line and now runs the shipped analyzer pass, a suite the recorded
> source cannot replay is refused rather than scored as zero, and the CASTLE
> adapter was rewritten around the format CASTLE actually ships. AC-01-10 and
> T-01-17: the shell-loaded `.env` and the guard that refuses to commit or
> delete it. Previously 2026-08-14 — part 13 runners and commands, and the
> retrieval ablation's first measured row.

This folder turns the product spec into work packages. Each numbered part is one sitting of engineering work: a goal, the parts it depends on, concrete deliverables, typed interfaces, invariants it must not break, acceptance criteria, and a table of test cases.

**Read the spec first.** These documents deliberately do not restate the product thesis, the finding contract, or the evaluation methodology. They reference sections of [core_idea.md](../specification/core_idea.md) and describe how to build them.

## How to use this plan

1. Pick the lowest-numbered part whose dependencies are all done.
2. Read its Invariants section before writing code — those are the constraints that make the tool worth building.
3. Implement until every acceptance criterion holds and every test in its table passes.
4. Parts 04, 08, 11, and 13 end with a milestone exit checklist. Do not start the next milestone's parts until the checklist passes.

The ordering is not arbitrary: the data contracts (02), the citation resolver (03), and the metrics that detect fabrication (04) are all built **before** anything can produce a claim. By the time an LLM is introduced in part 10, the machinery that can reject its output already exists and is tested.

## Locked decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Language | Python 3.12 | Matches the Gemini SDK, the reference repos, and the fastest path to Milestone 1 |
| Indexing | `libclang` via the PyPI `libclang` wheel | Wheel bundles the shared library, so no system LLVM install is needed just to index |
| Analyzers | `clang-tidy` and Clang Static Analyzer as subprocesses | Stable CLI contracts and SARIF/YAML output; avoids linking against LLVM |
| First target | Local developer CLI (`caudit scan`) | Spec open question #1. CI wrapper and diff-vs-baseline mode are post-MVP |
| Cloud posture | Gemini with explicit consent, exclusion globs, secret redaction, no retention | Spec open question #2. A local-model backend is an interface in part 10, not an implementation |
| Scan selection | Every TU in the compilation database that survives filters; `--target` narrows | Spec open question #3. Working default — revisit if repository-scale runs prove too slow |

The last three restate open questions the spec leaves unresolved. They are working defaults chosen so the plan is executable, not final product decisions; `core_idea.md` remains the place where they are formally open.

## Environment baseline

Verified on the development machine, 2026-08-11:

| Tool | Status |
| --- | --- |
| Python | 3.12.3, system pip is PEP 668 externally-managed → a virtualenv is mandatory |
| cmake | 3.28.3 |
| git | 2.43.0 |
| clang, clang++, clang-tidy, clang-format, scan-build | **not installed** |
| system libclang | **not present** |
| ninja | not installed |

Part 01 owns bootstrapping and pinning the LLVM toolchain. Parts 01–06 are written so they can be built and tested with no Clang present at all — part 06 indexes through the `libclang` wheel, which bundles its own shared library — and parts 07 and later require the real tools, because they invoke `clang-tidy` and `scan-build` as subprocesses.

One consequence, discovered while building part 06 and recorded here because it shapes the first run on any real repository: the wheel ships no Clang resource directory, so a translation unit including `<stddef.h>` does not parse until `index.resource_dir` is pointed at one. C Audit does not search for it — that would be guessing an include path — and instead names the fix in the limitation. See [setup.md](../guides/setup.md#clangs-builtin-headers).

A second consequence, from part 08: because parts 07 and later cannot run here, the `needs_clang` tests that confirm the committed analyzer recordings against real tools — T-07-21 and T-08-17 — have never been executed on this machine. Everything below them runs offline against those recordings. Treat the recordings as authored expectations until a machine with LLVM has run those two tests.

Part 09 is unaffected by that gap: retrieval is a set of questions to the part 06 index, which is built through the wheel, so every one of its tests runs in the default suite. Building it did require extending part 06 — the index now carries a global-reference graph, because the declarations AC-09-2 asks for were not recoverable from the type graph and matching identifiers textually is what part 06's resolver exists to reject. `INDEX_FORMAT_VERSION` moved to `2` as a result, which invalidates on-disk parse caches written by an earlier revision.

Part 10 adds a third kind of external dependency, and it is handled the same way. Every part 10 test replays a committed cassette from `tests/cassettes/`, so the default suite still opens no socket and needs no API key; T-10-21 is the single `needs_network` test that holds those recordings to the real API, and it has never run here. A cassette records the prompt version it was captured against and refuses to answer a request assembled from a different one, so a prompt bump without a re-record fails loudly rather than testing instructions that no longer exist.

Part 11 adds no external dependency at all — the gate is deterministic, model-free, and reads nothing but the index, the store, and the bundle. It did extend part 10, though, and the extension is worth knowing about before reading either part: `Adjudication` now carries `quoted_evidence` and `asserted_call_edges`, because AC-11-5 and AC-11-6 check claims a model previously had no channel to make. `policy_versions.prompt` moved to `2` with new templates that invite both, and every committed cassette was re-recorded against it.

Part 13 is where the environment baseline stops being a footnote and becomes the result. Its four modules — the pair harness, the maintainability scorer, the ablation grid, the calibration curve — are built and tested, and each now has a runner and a command behind it (`caudit ablate`, `caudit pairs`, `caudit calibrate`). **One of its numbers has been measured**: the retrieval half of the ablation, which needs no model, and which found that the flat-window control retrieves the same share of the decisive code as structural retrieval on the mini suite while spending 3.4x the tokens — a result whose main caveat is that the mini cases are shorter than the window. Everything else still waits on data this machine does not have: pinned CVE pairs with working build recipes, at least two independent human labellers per maintainability case, an API key for every ablation that varies a model tier, and a corpus large enough for a confidence bin to be judged. [evaluation-results.md](../project/evaluation-results.md) records that state explicitly rather than leaving the tables blank. The M3 checklist is open on four of six items, partly measured on one, and says which dependency each is waiting on.

That revision also closed a gap the plan had not noticed: `ExpansionPolicy.from_config` read nothing but the policy version, so `caller_depth` and `retrieval_variant` — two of the four factors `AblationConfig` names — could not reach a run. The grid would have built configurations that differed on paper and produced identical runs, then reported "no effect" for a knob that never moved. The depth knobs are configuration now, and `flat_window` is a real variant of `expand` rather than an enum value with no implementation. `structural_plus_semantic` is refused by name, because part 09 puts semantic retrieval out of scope and serving structural results under that label would be worse than not offering it.

Part 12 assembles all of it into one command, and inherits every gap above rather than adding one. Its end-to-end tests drive the model stage from a `ScriptedProvider` rather than a cassette: a cassette pins one recording to one candidate's evidence ids, and a whole-repository scan gives every candidate its own. That double exercises the plumbing — expansion, the retry loop, validation, the gate, ranking, rendering — and deliberately not answer *quality*. The measurement that needs a real model is `caudit eval --no-baseline`, which is implemented, tested offline, and **has never been run against the API here**. So M2's last two checklist items stay open at the end of part 12 as well, for a narrower reason than before: the path exists and the run needs a key. `SCHEMA_VERSION` moved to `1.7.0` for the manifest's `stages`, `total_cost_usd` and `partial`.

## Parts

| # | Part | Goal | Gate |
| --- | --- | --- | --- |
| 01 | [Engineering baseline](01-engineering-baseline.md) | Package layout, CLI skeleton, `caudit doctor`, lint/type/test gates, toolchain pinning | |
| 02 | [Domain schemas](02-domain-schemas.md) | Candidate, Evidence, Finding, RunManifest; stable IDs; CWE mapping rules | |
| 03 | [Evidence and citations](03-evidence-and-citations.md) | Source store, region hashing, citation resolver v1 | |
| 04 | [Evaluation harness](04-evaluation-harness.md) | Benchmark adapters, baseline runner, metrics, hard gates | **M0** |
| 05 | [Repository intake](05-repository-intake.md) | Compilation database load and validation, filters, coverage accounting | |
| 06 | [Clang index](06-clang-index.md) | Symbol/reference/call/include/macro indices, citation resolver v2 | |
| 07 | [Candidate generation](07-candidate-generation.md) | CSA, clang-tidy, diagnostics; normalization and provenance-preserving dedup | |
| 08 | [Deterministic reporting](08-deterministic-reporting.md) | SARIF 2.1.0, Markdown, `run-manifest.json`, byte-reproducible output | **M1** |
| 09 | [Evidence expansion](09-evidence-expansion.md) | Budgeted structural retrieval with reversible handles | |
| 10 | [LLM adjudication](10-llm-adjudication.md) | Provider tiers, structured output, consent and redaction, caching | |
| 11 | [Verification gate](11-verification-gate.md) | Citation resolution, CWE checks, confirmed vs needs-review routing | **M2** |
| 12 | [Ranking and end-to-end](12-ranking-and-e2e.md) | Ranking, report assembly, full CLI run, baseline comparison | |
| 13 | [Repository-scale validation](13-repo-scale-validation.md) | CVE pairs, maintainability set, ablations, calibration | **M3** |

### Dependency graph

```
01 ──┬─> 02 ──┬─> 03 ──┬─> 04            [M0]
     │        │        │
     │        └────────┼─> 07
     │                 │
     └─> 05 ─> 06 ─────┼─> 07 ─> 08      [M1]
                │      │
                └─> 09 ─> 10 ─> 11       [M2]
                       ↑         │
                 03,06 ┘         v
                          08 ──> 12 ─> 13 [M3]
```

Text form — `01 → 02`; `02 → 03, 04, 07, 08`; `03 → 04, 11`; `01 → 05`; `05 → 06`; `06 → 07, 09, 11`; `07 → 08`; `09 → 10`; `10 → 11`; `08, 11 → 12`; `04, 12 → 13`.

### Milestone mapping

| Milestone in the spec | Parts | Exit condition |
| --- | --- | --- |
| M0 Evaluation harness | 01, 02, 03, 04 | Baselines measured on the mini suite with no AI involved; fabrication gate demonstrably trips |
| M1 Deterministic scanner | 05, 06, 07, 08 | `caudit scan` emits reproducible Markdown + SARIF + manifest from analyzers alone |
| M2 Gemini adjudication | 09, 10, 11 | Confirmed / rejected / review-required states, all citations verified, measured against M1 |
| M3 Repository-scale validation | 12, 13 | Real vulnerable/fixed pairs, labeled maintainability set, ablations, calibrated confidence |

Phase 2 (remediation agent) is out of scope for this plan; a deferred appendix in part 13 records the entry conditions.

## Target repository layout

Parts reference these paths so module ownership is unambiguous:

```
pyproject.toml
src/caudit/
  cli/            01, 12   command entry points, exit codes
                  13       ablate, pairs, calibrate
  config/         01       layered configuration, policy versions
  model/          02       schemas, IDs, CWE rules
  evidence/       03       source store, regions, hashing, resolver
  intake/         05       compilation database, filters, revision
  index/          06       libclang indices and graphs
  analyzers/      07       CSA, clang-tidy, diagnostics, normalize, dedup
  retrieval/      09       expansion policy, variants, budgets, handles
  llm/            10       provider tiers, prompts, cache, redaction
  verify/         11       evidence gate
  report/         08, 12   SARIF, Markdown, manifest, ranking, pipeline assembly
  eval/           04, 13   benchmark adapters, metrics, comparison, pairs,
                           maintainability, ablations, calibration, and the
                           runners that apply them to a real suite
benchmarks/pairs/          pinned CVE-linked revision pairs (empty; see its README)
benchmarks/maintainability/  labelled hazard set (empty; needs human labellers)
my_docs/project/evaluation-results.md   recorded results, per policy version
schemas/                   exported JSON Schema + vendored SARIF 2.1.0 schema
benchmarks/mini/           committed fixture suite, one case per weakness family
tests/
  unit/ integration/ adversarial/ golden/ e2e/ fixtures/ cassettes/
```

## Conventions

### Part document template

Eight sections, in this order: Goal · Depends on / Unlocks · Deliverables · Interfaces · Invariants · Acceptance criteria · Test cases · Out of scope and risks.

### Identifiers

- Acceptance criteria: `AC-<part>-<n>`, e.g. `AC-03-2`.
- Test cases: `T-<part>-<nn>`, e.g. `T-03-07`. Unique across the whole plan.
- Every acceptance criterion is covered by at least one test row; every test row names the criteria it covers.

### Test types

| Type | Meaning | Runs by default |
| --- | --- | --- |
| `unit` | Pure logic, no toolchain, no network | yes |
| `contract` | Validates against a committed JSON Schema (own schemas, or SARIF 2.1.0) | yes |
| `golden` | Compares output against a committed snapshot | yes |
| `adversarial` | Attempts to smuggle an unverifiable claim past a gate; asserts it is caught | yes |
| `integration` | Needs a toolchain. `needs_clang` (a real `clang`/`clang-tidy` on PATH) is deselected by default; `needs_libclang` (the wheel, a hard dependency that bundles its own shared library) is **selected** — indexing needs no system LLVM, so part 06's tests run in the default suite | `needs_clang` no, `needs_libclang` yes |
| `e2e` | Full CLI run on a fixture repository, LLM served from cassettes | yes |
| `perf` | Token budget, latency, or throughput bound | no (`slow`) |

`needs_clang`, `needs_network`, and `slow` are deselected by default. The default suite is offline, deterministic, and runnable on a machine with no LLVM installed — which includes the current development machine.

### Fixtures

- `benchmarks/mini/` is a hand-written suite committed to the repo: one small C or C++ case per weakness family in the spec's in-scope list, each with ground-truth CWE and line. CI depends on it so that no test run requires downloading CASTLE or Juliet.
- CASTLE, the Juliet subset, and CVE pairs are fetched by script into a cache directory, pinned by revision, and exercised only under the `slow` marker.
- LLM responses are recorded once and committed as cassettes. No test in the default suite opens a socket.

### Definition of done for a part

1. Every acceptance criterion holds.
2. Every test in the table exists and passes (or is explicitly deselected by marker, with the marker named).
3. `ruff`, `mypy --strict`, and the coverage floor pass.
4. Anything the part could not resolve is recorded as a `Limitation` in the data model, not left implicit.

## Traceability

Every requirement in the spec maps to at least one part.

| Spec requirement | Part(s) |
| --- | --- |
| Finding contract — Identity, Classification | 02, 11 |
| Finding contract — Location, Evidence | 02, 03, 09 |
| Finding contract — Preconditions, Impact, Remediation | 02, 10, 11 |
| Finding contract — Provenance | 07, 10, 11 |
| Finding contract — Confidence | 02, 11 |
| Finding contract — Maintainability impact | 07, 10, 13 |
| Finding contract — Limitations | 05, 06, 07, 09, 10, 11 |
| Evidence gate, clauses 1–4 | 03, 11 |
| Hard gate — ≥95% citations resolve | 04, 11 |
| Hard gate — zero fabricated files/functions/analyzers/snippets | 03, 04, 11 |
| Hard gate — confirmed and review-required never merged | 08, 11 |
| Hard gate — baseline floors before an overall score | 04, 12 |
| Ranking, and the explanation of it | 12 |
| MVP inputs — compilation database, toolchain, API key | 01, 05, 10 |
| Stop on missing/incomplete database, never guess flags | 05 |
| Coverage counts and excluded targets in the report | 05, 08 |
| Third-party and generated code excluded by default | 05 |
| In-scope weakness families | 04, 07 |
| Outputs — `report.md`, `results.sarif`, `run-manifest.json` | 08, 12 |
| Model capability tiers, configurable and recorded | 10 |
| Structured output constrained by JSON Schema | 02, 10 |
| Security score — macro-F2, precision, FP/KLOC, evidence validity | 04 |
| Maintainability score — labeled set, macro-F1, ranking quality | 13 |
| Architecture stages 1–7 | 05, 06, 07, 09, 10, 11, 08/12 |
| Technique sequence — compiler-aware selection, directed retrieval, dependency expansion | 06, 07, 09 |
| Technique sequence — budgeted assembly, compress only secondary material, reversible retrieval | 09 |
| Technique sequence — structured adjudication, deterministic verification, evaluation | 10, 11, 04/13 |
| Risk — hallucinated evidence | 03, 10, 11 |
| Risk — incorrect build context | 05 |
| Risk — static-analyzer bias | 07, 04 |
| Risk — context truncation | 09 |
| Risk — benchmark overfitting | 13 |
| Risk — data leakage to a hosted model | 10 |
| Risk — uncontrolled API cost | 10 |
| Risk — misleading severity | 02, 12 |

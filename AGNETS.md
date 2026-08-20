# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state: parts 01–13 implemented (M1 complete; M2 and M3 built end to end, neither measured)

Sources of truth, in this order:

- [my_docs/specification/core_idea.md](my_docs/specification/core_idea.md) — the complete design spec for C Audit. It is the source of truth for scope, schemas, gates, and evaluation. Read it before writing any implementation code.
- [agents_docs/](agents_docs/README.md) — implementation-focused orientation for AI agents: architecture, code ownership, domain invariants, operations, pipeline behavior, tests, evaluation, and task playbooks. Use it to locate code and safe workflows; [my_docs/](my_docs/README.md) remains authoritative for product and design decisions.
- [my_docs/plan/](my_docs/plan/00-overview.md) — the spec sequenced into 13 executable work packages, each with interfaces, acceptance criteria, and a numbered test table. Start at [00-overview.md](my_docs/plan/00-overview.md); it carries the dependency graph, the test conventions, and a matrix tracing every spec requirement to a part.
- `inspiration_repos/` — four upstream projects cloned purely as inspiration. **Read-only: never edit, reformat, refactor, or commit inside them.** None of this code is part of C Audit.
- `audit-targets/` — independent, user-controlled repositories being scanned. Keep them untracked and do not modify them unless the task explicitly targets that checkout.

Built so far: **M0 (parts 01–04), M1 (parts 05–08), and parts 09–12.** `src/caudit/` holds the CLI, layered config, domain schemas, evidence store and citation resolver, the evaluation harness, repository intake, the Clang index, candidate generation, deterministic reporting, budgeted evidence expansion, LLM adjudication, the verification gate, ranking, and the assembled pipeline. `caudit scan` now runs the whole thing: intake → index → candidates → expansion → adjudication (if consented) → gate → ranking → `report.md`, `results.sarif`, `run-manifest.json`. Without consent it stops after candidates and writes the **byte-identical part 08 baseline** — that identity is asserted by test, because the M2 comparison measures against it. `make check` is the single quality gate — ruff, `mypy --strict`, a JSON Schema drift check, and pytest with an 85% coverage floor — and CI invokes the same target. `make eval` scores the committed mini suite offline from committed recordings; `make eval-real` runs the real analyzers, and any number meant to be published comes from the latter.

M2's measurement path **has now been run against the real API** (2026-08-15). `caudit eval --no-baseline` scores a suite with the model in the loop through the same pipeline `caudit scan` uses, and `caudit compare` differences it against the baseline. A key lives in `.env` and is loaded with `source tools/load-env.sh`.

The mini-suite comparison is **0.6667 → 0.5000**, and `baseline_floor` fails, so `caudit compare` refuses to call it a result. Read that narrowly before concluding anything about the model. **Adjudication cannot raise recall** — the analyzers generate candidates, the model only rules on them, and a model verdict never removes a candidate — so precision is the only direction available, and the mini suite has *zero* false positives at baseline. Its score can only fall. The −0.1667 is one case where Gemini answered CWE-120 for an unbounded `strcpy`, which is the canonical mapping and simply outside our 37-entry allowlist; the gate correctly routed it to `out_of_scope_family`. Whether CWE-120 belongs in `ALLOWLIST` is an open decision, deliberately not patched in mid-measurement.

Getting there required fixing four things that had made every prior number meaningless; see the "measured results" section below.

Part 13 is built, and **one of its numbers now exists**. `eval/pairs.py`, `eval/maintainability.py`, `eval/ablation.py` and `eval/calibration.py` hold the rules; `eval/ablation_runner.py`, `eval/pairs_runner.py` and `cli/calibrate_cmd.py` apply them, behind `caudit ablate`, `caudit pairs` and `caudit calibrate`. Until 2026-08-14 those four modules were imported by nothing but their own tests, so running any of them meant writing Python.

The measured row is the **retrieval half of the ablation**, which needs no model: on the mini suite the `flat_window` control retrieves the same 4-of-6 share of the decisive lines as structural retrieval and spends **3.4x the tokens** doing it. Read it narrowly — the mini cases are shorter than the ±40-line window, so the control reads whole files and the tie is an artefact of the corpus. Whether structural retrieval helps a model *find* more is the detection half, still unrun, still needing a key; `caudit ablate` reports it as `not measured` and `structural_retrieval_earns_itself()` returns `None` for a retrieval-only grid rather than comparing rows that all carry the analyzer-only score.

Still blocked on data: `benchmarks/pairs/manifest.yaml` is committed **empty** because pinning a pair means cloning it and confirming its build recipe works, and a manifest of unverified SHAs would look like evidence. `benchmarks/maintainability/` has the format, the rules, the loader and now the predictor, but **no labels** — that half needs people and cannot be generated. `caudit calibrate` runs on the mini suite and reports that no confidence bin reaches the five-finding floor — the honest answer on six cases. [my_docs/project/evaluation-results.md](my_docs/project/evaluation-results.md) records all of this case by case; do not let an empty table there be read as a run that produced nothing.

The finding→category predictor was built on 2026-08-14, and how it is built is the point. `predict_category` reads the weakness family first (`memory_lifetime` → `ownership_ambiguity`, because the defect *is* an ownership question) and falls back to `effort_of`'s verified evidence span (two files → `coupling`, two regions in one file → `complexity`). Everything else returns `None`. There is no catch-all category, because a predictor with one labels every finding confidently and measures the bucket; `resource_leak` abstains for the same reason, being genuinely ambiguous between ownership and error handling. Both signals are checkable and neither reads `MaintainabilityImpact`'s prose, which is not. **Two** of the five categories — `duplicated_validation` and `error_handling` — have no mapping from anything in the current schema; they are listed in `UNCOVERABLE`, and a label set containing one makes `MaintainabilityScore.macro_f1` **`None` with a stated refusal** rather than a 0.0 averaged in. That is the objection that kept the predictor unbuilt, answered rather than sidestepped: closing it properly needs a model-facing hazard field, a prompt bump, and re-recorded cassettes.

Part 07's analyzers need `clang` and `clang-tidy` on `PATH`, and as of 2026-08-15 **both are installed here** (Ubuntu clang 18.1.3, at `/usr/bin/clang`); `caudit doctor` reports the real versions, and [my_docs/guides/setup.md](my_docs/guides/setup.md) has the install commands for a machine without them. This changed under the test suite rather than in it: seven tests asserted `ExitCode.ENVIRONMENT` because *this machine* had no analyzer, several saying so in a comment, and installing clang-tidy turned all seven red with no production code touched. They now take a `no_analyzers` fixture (`tests/conftest.py`, the counterpart to `stubbed_analyzers`) that hides the binaries from `shutil.which` while leaving `git` findable, so the no-analyzer branch is imposed rather than inherited. Without an analyzer `caudit scan` still writes all three artifacts and **exits 3, not 0** — `0` is reserved for a run that looked and found nothing, and the report opens with a note saying nothing was examined. Indexing does *not* need them — it runs on the `libclang` wheel, which bundles its own shared library — but that wheel ships no resource directory, so a unit including `<stddef.h>` fails to parse until `index.resource_dir` is set. The top level **is** a git repository, with `origin` on GitHub. Generated output — `caudit-report/` (the `caudit scan --out` default), `caudit-eval/`, `__pycache__/`, `.coverage` and the tool caches — is gitignored, as is `inspiration_repos/` and `.env`. `make guard` runs first in `make check` and fails if any of them is tracked; the same paths are refused by three `language: fail` pre-commit hooks. `make clean` deletes the same set **minus the clones**, which are read-only upstream material rather than generated output, minus `.env`, which holds the API key and cannot be regenerated by anything at any price, and minus `.venv/`, which belongs to `bootstrap`. The `GENERATED` list and the `UNTRACKABLE` regex are one decision spelled twice, so T-01-16 asserts every guard category is exercised by a probe the recipe actually deletes — they had already drifted once, leaving `caudit-report/` and `.hypothesis/` surviving a clean indefinitely. The two carve-outs run the other way: `EXEMPT_FROM_CLEAN` names what the recipe must *not* touch, and `.env` is in `PRESERVED_PROBES` so a clean that grew to delete it fails here.

**The generated blobs are still in history.** Untracking them in `bf28823` stopped the bleeding; it removed nothing already committed. 1008 generated paths were added across two commits, and all 216 committed `.pyc` blobs embed the build machine's absolute source path (`/home/<user>/…` — written that way here on purpose, so this paragraph does not put the string back into a blob it is describing the removal of). Removing them is a `git filter-repo --invert-paths` run over the `UNTRACKABLE` regex followed by a force-push, which rewrites every SHA on `main` and drops `64bfa65` entirely — that commit is 146 generated paths and no real ones. The procedure is prepared and verified in a scratch clone; it lands only when someone runs the force-push, and until then this paragraph is the accurate description of the repository.

Part 09's depth knobs **are** configuration now, under a `retrieval` section, and `ExpansionPolicy.from_config` reads every one of them (the version still comes from `policy_versions.retrieval`, so the manifest cannot record a version the run did not use). They were defaults-only until part 13 needed to vary `caller_depth` and `retrieval_variant`, and a factor a run cannot be configured with is a factor nobody can measure: the grid would have built configurations that differed on paper and produced identical runs.

`retrieval.variant` selects between `structural` (the default and the only one a scan should normally use) and `flat_window` (part 13's control: a line window, no index consulted, which may cut a function in half). The control goes through **the same `expand`** rather than a second retrieval path, and every context it produces carries a limitation saying it is a window and a measurement configuration rather than a scanning one. `structural_plus_semantic` is refused at policy construction — part 09 puts semantic retrieval out of scope, and serving structural results under that label is worse than not offering the variant. The variant name is spelled twice, as a `Literal` in `config/loader.py` and an enum in `retrieval/policy.py`, because the dependency only runs one way; T-09-22 asserts they agree.

Part 12's end-to-end tests drive the model stage from a **`ScriptedProvider`, not a cassette** — a cassette pins one recording to one candidate's evidence ids, and a whole-repository scan gives every candidate its own. It is a plumbing double: it exercises expansion, the retry loop, validation, the gate, ranking and rendering, and deliberately says nothing about answer quality. Do not read a passing e2e test as evidence that adjudication works well; read it as evidence that the pipeline runs.

Part 10's default test suite opens **no socket and needs no API key**: every test replays a committed cassette from `tests/cassettes/`. A cassette records the prompt version it was captured against and refuses a request assembled from a different one, so bumping `policy_versions.prompt` without re-recording fails loudly instead of testing instructions that no longer exist. T-10-21 is the one `needs_network` test that holds the recordings to the real API. A key is now present in `.env`, so it is runnable; the full `caudit eval --no-baseline` path has been exercised against the live API repeatedly since 2026-08-15.

`SCHEMA_VERSION` is now `1.7.0`. Part 10 added four `ReviewReason` members and four exported schemas; two of those are *derived* rather than rendered from a model — `adjudication-response` and `triage-response` are the flattened shapes a provider is actually handed, committed so a change to the flattening is a CI failure rather than a runtime surprise. Part 11 added four more `ReviewReason` members (`call_edge_unresolved`, `evidence_does_not_support_cwe`, `model_rejected`, `model_inconclusive`, all blocking), two `LimitationKind` members (`claim_downgraded`, `provenance_unchecked`), and two fields on `Adjudication`. Part 12 added `StageRecord`/`StageStatus` and three `RunManifest` fields: `stages`, `total_cost_usd`, and `partial`.

`partial` is worth knowing about before reading part 12. It is a stored field that is **recomputed from `stages` on every construction**, including when a manifest is read back from disk, so a supplied `partial: true` is overwritten rather than trusted. A pydantic `computed_field` was tried first and rejected: it serializes but is not accepted on input, so an `extra="forbid"` model cannot round-trip its own output — and the manifest is read back by tests and by `caudit compare`.

Those two fields are worth knowing about before reading either part 10 or part 11. A model has **no channel to name a file or a function** — a location is a handle into a bundle, not a string — so AC-11-5 and AC-11-6 had nothing to check until `quoted_evidence` and `asserted_call_edges` existed. Both default to an empty list, unlike `unresolved_assumptions`, and the difference is deliberate: the gate *branches* on an empty assumption list, and it does not branch on an empty quotation list. `policy_versions.prompt` is now `2`, `prompts/v2/` invites both fields, `prompts/v1/` is kept so a pinned run still gets the instructions it names, and every committed cassette was re-recorded against v2.

Part 07's tests run offline against committed analyzer recordings in `tests/fixtures/analyzers/`, and as of 2026-08-15 those are **real captures from clang 18.1.3**, not authored expectations — same for `benchmarks/mini/*/baseline-candidates.json`, regenerated by `make record-baseline`. Do not hand-write one: T-04-24 fails if a recording replays a different ruleset from the real analyzers. T-07-21 asserts only **determinism** (two runs of the real analyzers agree) — it never compared the fixtures against reality, which is how one asserting a `core.NullDereference` clang does not emit survived; that file is deleted and `resource-leak-error-path` gained a real capture. Run these with `pytest -m needs_clang`; they are deselected by default. CASTLE is now cached and T-04-19 runs; `benchmarks/pairs/manifest.yaml` still pins no pairs, and Juliet is still not downloaded.

Part 08's SARIF output is validated against `schemas/sarif-2.1.0.schema.json`, a byte-for-byte copy of the OASIS schema. Do not edit it. `report.md` and `results.sarif` must stay byte-identical across two runs of one revision, which is why **no timestamp, duration, or absolute path may appear in either** — all three live in `run-manifest.json`. Absolute paths are stripped at the rendering boundary (`report/manifest.py::path_redactor`), so an upstream limitation that names the repository root does not have to know about the rule.

**A compilation database with relative `arguments` used to produce a completely empty index**, and the failure had no symptom. Clang reports a path the way it appeared on its command line, so a database naming the source relatively — what `make`-based and Bear-generated databases produce — yields relative names, and those are relative to the unit's build directory because that is what `-working-directory` told Clang. `parser.py::_relative` resolved them against the *process* CWD, every cursor landed outside `repo_root`, and `_walk` skipped it and its children. The parse still reported `parsed=1, failed=0`, the file still appeared in `indexed_files` (that path comes from the request, not a cursor), and there was no exception, parse failure or limitation. What came out held no symbols, calls or types — so retrieval found no containing function, every candidate reached the model carrying only its own line, and the model correctly declined to confirm what it could not see. On the mini suite that alone was macro-F2 0.6667 → **0.1667**. Fixed on 2026-08-15; T-06-24 asserts a unit named relatively and absolutely indexes identically. Nothing caught it because every indexing fixture writes absolute paths and Combat-Chess's CMake database does too.

Part 09 extended part 06: the index now carries a **global-reference graph** (`Index.globals_referenced_by`) alongside the type graph, because AC-09-2 needs the declarations of the globals a function touches and matching identifiers textually is exactly what the part 06 resolver exists to reject. `INDEX_FORMAT_VERSION` is now `2`, which invalidates on-disk parse caches; `graphs.TypeReferences` is now `graphs.ReferenceTable`, since two instances of it are kept and a caller asking for types must never receive a global.

Work the parts in order and do not reorder them for convenience: the part sequence encodes the safety argument. The data contracts, the citation resolver, and the metrics that detect fabricated evidence are all built *before* anything can produce a claim, so by the time an LLM appears in part 10 the machinery that rejects its output already exists and is tested.

Part 10's ordering is its safety argument, the same way part 09's was. Consent is a **constructor argument** on the only component that can open a socket, so "was consent checked?" is answered by the type rather than by an audit of call sites. Exclusion is enforced twice — units are filtered before assembly, and the assembled prose is asserted against the same filter afterwards — and the second check *raises* rather than trimming, because a check that silently repairs a leak removes the only signal that one happened. The only path from a response to an `Adjudication` is `model_validate_json`; there is no lenient parser to fall back on, which is what makes "prose never becomes a finding" a property rather than a hope.

Part 12's ordering carries the same kind of argument, in two places. **Ranking never reads what a model wrote.** Severity comes from the committed CWE family table capped by a committed `ImpactKind → Severity` ceiling — the kind is a fixed enum a model picks from, the severity is free grading, and the ceiling can only lower — so `impact.severity` is not consulted at all. Confidence is the gate's, reachability is the gate's capped value, agreement counts only external analyzers, and effort is measured from the span of the cited evidence. And **the network only exists on the consented branch**: no provider is constructed unless consent was granted, so a run without consent has nothing in the process that could open a socket.

Part 11 is where that argument is cashed. `caudit.verify.verify` is deterministic and model-free — it takes an `Adjudication`, an `EvidenceContext`, an `Index` and a `SourceStore`, and there is nowhere in its signature to pass a provider, a consent decision, or a `Config`, so "can this be configured off?" is answered by the type. Four rules shape it, and none of them may be quietly relaxed: **failures accumulate** (every applicable reason, not the first); **nothing is discarded** (a refused proposal becomes a `ReviewItem` carrying the same candidate, evidence and provenance); **downgrade precedes rejection** (when only the *strength* of a claim outruns its evidence the finding survives at the weaker claim, recorded as both a reason and a `claim_downgraded` limitation); and **confidence is computed here**, from the resolutions, never copied from `confidence_self_report`.

`SCHEMA_VERSION` in `src/caudit/model/finding.py` gates the committed schemas in `schemas/`. Changing an exported model means running `make schemas` and bumping that version in the same change; `make check` fails otherwise. The derived response schemas go through the same check, so changing `llm/schema.py`'s flattening is a schema change too.

## What C Audit is

A compiler-aware C/C++ auditing tool: deterministic static analysis generates candidates, Gemini adjudicates and explains them under a strict schema, and deterministic verification rejects anything whose cited evidence does not resolve. Outputs are `report.md`, `results.sarif` (SARIF 2.1.0), and `run-manifest.json`.

Guiding principle from the spec: **use AI to connect and explain evidence, not to invent it.**

### Design invariants — do not silently relax these

These are decisions already made in the spec. If a task appears to require breaking one, say so rather than working around it.

- **Evidence gate.** A candidate becomes a reported finding only if every cited file, line, symbol, and call edge resolves against the scanned revision and the evidence supports the stated impact. Everything else goes to a separate **Needs review** section. Enforced in `verify/gate.py`, which is deterministic and takes no provider, no consent and no `Config` — the answer to "can this be turned off?" is that there is nowhere to put the switch.
- **A quotation is checked byte for byte.** `quoted_evidence` is the only channel through which a model can make a checkable claim *about* source, and it is compared against the bytes the bundle captured with no normalisation of whitespace or line endings. Prose describing code is not checkable and is never treated as though it were.
- **An unrecorded call edge is not a disproved one.** The index recording no edge between two functions is a different claim from no such call existing, and when unresolved indirect calls are in the graph the rejection says so. A fabricated *name* is `symbol_unresolved`; two real functions with no edge is `call_edge_unresolved`.
- **The gate weakens a claim before it rejects a finding.** The hard gate is on fabricated evidence, not on cautious findings, so an over-claimed `reachability` or `exploitability` is capped at what the citations support and the finding survives at the lower claim. A claim is only ever lowered, never raised.
- **Confirmed findings and review-required candidates are never merged into one count** — not in the report, not in metrics, and not in a delta. `caudit compare` differences the two separately: a change that moved thirty findings from confirmed to needs-review is enormous, and a summed count renders it as zero.
- **The candidate set bounds recall; adjudication moves findings within it, in both directions.** The analyzers decide what is *visible*: a defect that produced no candidate has no prompt assembled for it and the model is never asked, so it cannot be found at any model quality. Measured on CASTLE, that ceiling is real — the `integer` family's CWE-190 half is undetectable because clang 18 ships no static checker for arithmetic overflow, and 6 of 12 vulnerable cases there produce zero candidates. Raising *that* needs a candidate generator proposing suspect sites, which is a design change and not a better prompt. **But recall is not fixed at the deterministic tier's answer**, and an earlier version of this note said it was. Deterministic promotion leaves candidates it cannot classify as `review_required` — an unmapped rule yields no CWE and routes to `out_of_scope_family` — and adjudication can supply the classification and confirm them. On CASTLE it rescued 7 such candidates while rejecting noise in 18 other cases: true positives 23 → 28 and false positives 33 → 14, with the candidate set identical at 157 findings both runs. So adjudication improves precision *and* recall over the deterministic promotion; what it cannot do is see what was never flagged.
- **Ranking reads no value a model wrote.** Severity comes from the CWE family table capped by the impact kind, never from `impact.severity`; confidence and reachability are the gate's; agreement counts external analyzers only; effort is the span of the cited evidence. Each finding renders a "why this rank" line built from those same five inputs, so an ordering the explanation does not account for is not expressible. Review-required items are ranked in their own section and cannot enter the confirmed list at any rank.
- **Every candidate reaches the report exactly once.** A context that would not fit, a provider that went away, a budget that bound, a proposal the gate refused — each becomes a finding carrying a reason. A diagnostic that disappears because a *later* stage failed is the worst outcome available: the report looks clean and the defect is still there.
- **A failed stage degrades the run; it does not end it.** The stage is recorded, contributes a limitation, marks the report partial in the title line, the SARIF invocation and the manifest, and the run continues on what it already had. A **partial run can never exit `0`**, for the same reason a run with no analyzer cannot. Only our own typed errors are caught this way: an unexpected exception is a bug, and swallowing it would turn a crash into a quietly incomplete report.
- **A translation unit that will not parse is not a partial report.** It is counted in coverage, named in a limitation, and printed in the coverage section — three times over. Marking the run partial as well would fire the loudest marker in the output on nearly every real repository, and a warning that is always on is one nobody reads. Partial is for a stage that did not do its job.
- **The candidate visit order is fixed before any budget is spent.** When the run's token ceiling binds, the order decides which candidates a model saw, so it is sorted by path, line and id rather than left to whatever order part 07 emitted.
- **A benchmark never quietly loses its hard cases.** A repository pair whose build recipe fails is excluded *with a reason* and counted in neither the numerator nor the denominator; a pair with only one working side is excluded too, because one side cannot tell a detection from a persistent false positive. A corpus that drops what it cannot build reports a rising score for a falling tool.
- **The maintainability set is labelled by people, not by the tool.** At least two *distinct* labellers per case, a recorded adjudication whenever they disagreed, and a refusal when the label's source names an analyzer this project runs. Deriving labels from `clang-tidy` output scores the tool against itself, which the spec names directly.
- **The category predictor abstains, and a category it cannot reach withholds the average.** `predict_category` returns `None` rather than falling through to a catch-all, because a predictor with a default bucket labels everything confidently and measures the bucket. `UNCOVERABLE` declares the two categories no signal in the schema can produce, and `score_maintainability` returns `macro_f1: None` with a stated reason when the label set contains one — never a 0.0 averaged in. An F1 of zero that the schema made unavoidable is a fact about the bridge, and reporting it as a score would understate the tool for a reason that has nothing to do with the tool. The per-category numbers are still published, because which category was unreachable is the actionable part.
- **The flat-window ablation control is not optional.** Every grid contains it, `AblationSuite` refuses a set without it, and "the control has not run" is reported as `None` rather than as a win. Without it an ablation suite measures how well structural retrieval is tuned, not whether parts 06 and 09 are worth their complexity.
- **Confidence labels are checked against ground truth.** If `high` findings turn out true less often than `medium` ones, the labels are decoration: the run says so and the overall score is refused. Bins below a minimum size are not judged, because a check that fires on noise is one somebody switches off.
- **Nothing is pooled across policy versions.** Pair outcomes, calibration curves and `caudit compare` all raise with both configurations named. A curve mixing two prompt versions is a curve of neither.
- **Comparison is like-for-like or it is refused.** Different matching or profile versions, or different cases, stop `caudit compare` with both values named. The *prompt* version is compared only when both runs adjudicated — an analyzer-only baseline never assembled a prompt, and requiring one to match would refuse exactly the comparison M2 is defined by. What cannot be checked becomes a stated caveat, never a silent assumption.
- **A valid `compile_commands.json` is required.** If it is absent or materially incomplete, stop with actionable setup instructions. Never guess include paths or compiler flags in the MVP.
- **Never lossy-compress decisive code.** Retrieve complete code units (function + relevant types, macros, callers, callees, cleanup paths). Compression applies only to secondary material: duplicate diagnostics, build logs, old turns, unrelated outlines. A dropped cast or operator can reverse a security claim. Enforced in `retrieval/context.py`: a unit's class is derived from its role and validated against it, and only a `SECONDARY` unit may carry a repeat count or prose. When the primary set alone exceeds the budget nothing is emitted and the candidate becomes `review_required` / `context_budget_exceeded` — a half-function is worse than admitting the limit.
- **Structured output only.** Gemini returns typed, JSON-Schema-constrained finding objects with evidence IDs; validate before rendering. Enforced in `llm/provider.py`: the only route from a response to an `Adjudication` is `model_validate_json`, an invalid one is retried with the validation error fed back, and after the last attempt the candidate becomes `review_required` / `schema_invalid_response`. Nothing is salvaged out of text.
- **A model may cite only what it was issued.** An id the bundle never handed out is rejected here without a retry, and again on the authoritative path in `verify/citations.py` — which checks issuance *before* it opens any file, so "this handle names nothing in the closed world you were given" stays distinct from "this region changed".
- **A model's verdict never removes a candidate.** `rejected` becomes `review_required` / `model_rejected` and `review_required` becomes `model_inconclusive`; both keep the analyzer's diagnostic in the report with the model's argument attached, for a human to confirm. This is the same rule as triage in part 10, applied to the tier that actually read the code.
- **Model IDs live in configuration and are recorded per run**, never hard-coded in the architecture. Three capability tiers: triage (cheap classification/dedup), adjudication (repository reasoning), escalation (ambiguous high-impact only). Escalation fires only when the verdict is ambiguous *and* the impact is high — one truth table in `llm/provider.py::route`, used both after triage and after adjudication. Triage never removes a candidate from the report; it only decides which tier answers.
- **The MVP recommends remediations; it does not modify code.** Patch generation is Phase 2.
- **Impact, reachability, and exploitability are separate schema fields.** Do not claim exploitability without evidence of reachability and attacker control.
- **Gemini API key comes from the runtime environment**, never from the repo. A project-local `.env` is a supported developer convenience and not an exception to this: `tools/load-env.sh` is sourced by the *shell*, which exports the values before `caudit` starts. There is no dotenv dependency and no `load_dotenv` call, so the key still reaches the process only through `os.environ`, is still absent from `Config`, and `gemini.py`'s hint — "it is never read from a config file" — is still literally true. `.env` is gitignored, guard-refused and never cleaned; read "never from the repo" as a statement about what the process opens, not as a ban on the file. Source and prompts are not persisted by default: the response cache stores a prompt *fingerprint* and the parsed result, and `llm.retain_raw` is the explicit opt-in that changes that.
- **No bytes leave the process without consent.** `--consent-cloud`, or a `.caudit/cloud-consent.json` record; absent either, `caudit scan` still produces the part 08 baseline report and says in it that no model looked. Excluded files are filtered before prompt assembly and asserted against afterwards; credential-shaped strings are scrubbed and counted.

### The pipeline (assembled in part 12; `caudit.cli.scan.run_scan` runs it)

Repository intake (resolve revision, validate compilation database, apply filters) → deterministic indexing (Clang parse; symbol/reference/include/call/type/macro indices with source-region hashes) → candidate generation (Clang diagnostics, Clang Static Analyzer, curated `clang-tidy` profile, normalized into one candidate schema, deduplicated with provenance preserved) → evidence expansion (containing function outward, within a token budget, keeping handles to originals so compression is reversible) → LLM adjudication (confirmed / rejected / review-required) → deterministic verification (resolve every citation and hash, check schema and CWE mapping) → report generation (rank, render Markdown + SARIF, record coverage gaps).

Every finding carries: identity/fingerprint, CWE, location + source-region hash, evidence steps, preconditions, impact, provenance, confidence, remediation, maintainability impact, and limitations. See the finding contract table in the spec.

### Hard gates on evaluation

Overall score is 50% security / 50% maintainability, but the average is only valid once these pass: ≥95% of cited locations and symbols resolve exactly; zero fabricated files, functions, analyzer names, or snippets; confirmed and review-required counts kept separate; security recall/precision floors established against the non-AI static-analysis baseline first. Security uses macro-averaged F2 (recall weighted over precision), with precision, FP/KLOC, and evidence-validity reported separately.

Part 13 adds a second refusal on top of the gates: `gated_overall_score` will not compute the average while the confidence labels are miscalibrated, and there is no maintainability half to average yet in any case.

### Measured results, and the four bugs that had to be fixed first

Every number in [my_docs/project/evaluation-results.md](my_docs/project/evaluation-results.md) before 2026-08-15 was **withdrawn and re-measured**. They had been replays of authored fixtures scored through a check list this project does not ship. Four distinct defects, each of which alone invalidated the result:

1. **`caudit eval` had no way to run a real analyzer.** The CLI never passed `use_clang`, so `default_source` always returned `RecordedCandidateSource`. `--use-clang/--recorded` now exists; `--recorded` stays the default so CI is offline, and `make eval-real` is the published-number target.
2. **The benchmark scored a different tool than `caudit scan`.** Part 04's `ClangBaselineSource` enabled `bugprone-*`/`cert-*`/`clang-analyzer-*` and no compiler diagnostics; the curated profile enables `-Wformat-security` and the alpha checkers and excludes most of `insecureAPI.*`. Both directions mattered. `caudit eval --use-clang` and `tools/record_baseline.py` now run `generate_candidates` under the curated profile, and **T-04-24 asserts `--recorded` and `--use-clang` produce identical metrics**.
3. **A missing recording scored zero instead of failing.** `--recorded --suite castle` would have reported 250 clean cases with all gates passing. `run_eval` now refuses before scoring.
4. **Any compilation database with relative `arguments` produced a completely empty index** — see the part 06 note below. This is the big one.

**Measured now, all on clang 18.1.3 under curated profile v1:**

| Corpus | Cases | analyzers | adjudicated | gates |
| --- | --- | --- | --- | --- |
| `benchmarks/mini` | 6 | 0.6667 | 0.5000 | 3/4 |
| CASTLE | 110 of 250 | **0.2290** | — | 4/4 |

CASTLE is cloned and scored: 11 of its 25 CWEs are in the allowlist, 66 vulnerable cases and 44 deliberately safe, FP/KLOC 13.665, 792/792 citations resolved, 56 confirmed and 101 review-required. The 14 out-of-scope CWEs are skipped **with a per-CWE count**, so a score over 110 must never be read as one over 250. The mini suite's 0.6667 is numerically unchanged from the withdrawn figure and that is a coincidence: four families detected either way, but not the same four.

Two blind-spot flags in the mini suite were predictions and both were wrong in opposite directions, and one committed fixture (`null-deref-unchecked-alloc/csa.sarif`) asserted a `core.NullDereference` clang does not emit. Corrected; the flags now record measurements.

Everything else in the results doc is recorded as not run, with the dependency it waits on. Treat an empty table as an absent measurement, never as a zero — and treat the ablation row as what it says, a statement about retrieval cost on short files, not a verdict on whether compiler-aware retrieval finds more.

### Unresolved — ask rather than assume

Three product questions are still open in the spec: CLI vs. CI-check as the first target; whether a no-cloud mode is required from the first release; and whether the MVP scans only selected targets or every translation unit in `compile_commands.json`.

## Working with `audit-targets/`

`audit-targets/` is the durable workspace for repositories C Audit scans.
Each child is an independent Git checkout controlled by the user, not C Audit
source and not generated output. The directory is gitignored, refused by
`make guard` and the nested-repository pre-commit hook, excluded from every
mutating pre-commit hook, and pruned from both `make clean` traversals. Do not
edit an audit target unless the user explicitly asks for work inside it.

Clone targets normally and keep build products inside their checkout:

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

Always pass an absolute `--out` under
`/home/vimdim/personal/c_audit/caudit-report/`. For Combat Chess, use
`combat-chess/scan`, `combat-chess/dryrun`, and
`combat-chess/adjudicated` as separate run directories. `caudit-report/` is
disposable generated output and may be removed by `make clean`; the checkout
under `audit-targets/` must survive unchanged.

## Working with `inspiration_repos/`

Each subdirectory is an independent clone with its own `.git` and upstream remote. Treat them as **read-only reference material**: do not edit, reformat, or commit inside them, and do not import their code wholesale. `inspiration_repos/` is excluded from the top-level repo in `.gitignore`, and `make guard` enforces it. That is not a style preference: the four clones were once tracked as mode `160000` gitlinks with no `.gitmodules`, which made `git submodule status` fail outright and gave every fresh clone four empty directories with no recorded URL to populate them from.

| Path | What it is | Relevance |
| --- | --- | --- |
| `benchmarks/RepoAudit` | Multi-agent LLM code auditor (tree-sitter based, compilation-free, multi-language) | Closest prior art. C Audit differs by being C/C++ only, build-aware, and evidence-gated. Its architecture doc is the most useful read: `docs/architecture.md` |
| `benchmarks/NITR` | Repository-level maintainability benchmark (mostly C++, some Python) for AI-generated edits | Phase 2 only |
| `benchmarks/MaintainCoder` | MaintainBench — maintainability of generated code | Phase 2 only |
| `SWE-CI` | CI-loop benchmark for maintaining repos across commit pairs | Phase 2 only |

The spec is explicit that these three benchmarks measure code *generation/editing*, not vulnerability-report quality. Do not cite them as evidence that the report-only MVP detects vulnerabilities. MVP evaluation targets are CASTLE, a Juliet C/C++ 1.3 subset, and a manually adjudicated CVE-linked real-repo set.

### Running the reference repos

RepoAudit (Python 3.13; needs `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`):

```bash
pip install -r requirements.txt && (cd lib && python build.py) && (cd src && sh run_repoaudit.sh /path/to/project NPD)
```

RepoAudit's CI enforces `black --check --diff src` (pinned 24.10.0) and `mypy src`.

NITR — build a single case and run its public evaluator:

```bash
python3 tools/run_case.py 002.refactor-and-reuse --with-evaluator
```

Some NITR starter cases intentionally do not compile before the task is solved. Repo-wide format check is `cmake -S . -B build && ctest --test-dir build -R format`; the pipeline entrypoint is `python3 evaluator/run_evaluation_pipeline.py evaluator/<case>/pipeline.json`.

SWE-CI (Python 3.11, Docker required, driven by `config.toml`):

```bash
PYTHONPATH=src python -m swe_ci.download
```

MaintainCoder (note the singular `requirement.txt`):

```bash
python main.py --method generate_raw_agent --dataset_name humaneval_dyn --evaluate false --model_name gpt-4o-mini
```

## Docs conventions

[my_docs/project/evaluation-results.md](my_docs/project/evaluation-results.md) is the record of measured results, one entry per policy version. Results from different versions are never pooled, so it grows by appending entries rather than by updating a running total. Add to it whenever a corpus is actually run — and say plainly when one was not.

`my_docs/plan/` uses zero-padded ordered filenames (`04-evaluation-harness.md`). Both the spec and the plan overview carry a "last checked"/"last revised" date at the top, and inline links to primary sources (SARIF spec, CWE mapping guidance, Clang compilation-database docs, Gemini docs) for every external claim. Preserve both conventions when editing: update the date when refreshing assumptions, and attach a source link to new external claims.

Within `my_docs/plan/`, each part follows one fixed eight-section template and identifies its acceptance criteria as `AC-<part>-<n>` and its tests as `T-<part>-<nn>`. Every criterion is covered by at least one test row. When adding a part or a criterion, keep those IDs unique across the folder and update the traceability matrix in `00-overview.md`.

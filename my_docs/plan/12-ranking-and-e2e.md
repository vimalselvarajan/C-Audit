# Part 12 — Ranking and end-to-end

## Goal

Turn a verified finding set into the report a developer actually reads: ordered by what deserves attention first, carrying AI provenance for every claim, and produced by a single command that runs the whole pipeline. Also deliver the comparison the spec requires — AI-assisted results against the Milestone 1 analyzer baseline.

This part is where the pieces stop being components and become a tool.

## Depends on / Unlocks

- **Depends on:** 08, 11.
- **Unlocks:** 13.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/report/ranking.py` | Ranking function and its inputs |
| `src/caudit/report/assembly.py` | Full pipeline assembly, AI provenance, manifest completion |
| `src/caudit/cli/scan.py` | `caudit scan` wired end to end |
| `src/caudit/cli/compare.py` | `caudit compare` — baseline versus adjudicated |
| `tests/e2e/test_scan_full.py`, `tests/golden/ranking/` | This part's tests |

## Interfaces

```python
class RankInputs(BaseModel):
    severity: Severity               # from CWE family and impact, deterministic
    confidence: Confidence           # computed by part 11
    reachability: Reachability
    effort: EffortEstimate           # from remediation scope: local | function | cross-module
    provenance_agreement: int        # how many independent analyzers produced it

def rank_key(f: Finding) -> tuple:
    """Total order. Ties break on finding_id so ordering is never arbitrary."""

def assemble(plan: ScanPlan, outcomes: Sequence[GateOutcome],
             manifest: RunManifest) -> ReportSections: ...

class ComparisonReport(BaseModel):
    baseline: Metrics                # analyzers only (M1)
    adjudicated: Metrics             # after LLM + gate (M2)
    delta: MetricsDelta
    cost: CostSummary                # tokens, requests, spend, wall time
    policy_versions: PolicyVersions
```

## Ranking

Ranking is deterministic and explainable — a reader must be able to see why a finding is at the top:

- Primary key: severity, derived from CWE family and the verified impact (not the model's opinion).
- Then confidence, with `review_required` items never interleaved into the confirmed list — they are a separate, separately ranked section.
- Then reachability: demonstrated above argued above unknown.
- Then provenance agreement: independent analyzers agreeing outranks a single check.
- Then effort ascending, so cheap high-value fixes surface above expensive ones of equal weight.
- Ties break on `finding_id`.

Each finding renders a one-line "why this rank" string built from the same inputs, so the ordering is auditable rather than mysterious.

## End-to-end flow

`caudit scan <repo> --compile-commands <db> --out <dir>` runs: intake (05) → index (06) → candidates (07) → expansion (09) → adjudication (10, if consented) → gate (11) → ranking and rendering (08, 12). Without consent it stops after candidates and renders the part 08 baseline report — the same artifacts, with `model_ids: null`.

The manifest is completed here: model ids actually used, prompt and retrieval policy versions, token and cost totals, per-stage timings, and the source-region hash of every cited region.

## Invariants

- **Ranking never promotes an unverified finding.** Review-required items are ranked within their own section and cannot appear in the confirmed list at any rank.
- **AI provenance is per claim.** A finding shows which facts came from an analyzer, which from the index, and which from the model — the spec's provenance field applies to supporting facts individually, not to the finding as a whole.
- **Determinism survives the LLM.** With a fixed cache or cassettes, two runs produce byte-identical `report.md` and `results.sarif`. Nondeterminism, when it occurs, must come from the provider and be visible in the manifest, not from our own ordering.
- **Comparison is like-for-like.** `caudit compare` refuses to compare runs with different matching-policy, prompt, or profile versions, or different scan plans.

## Acceptance criteria

- **AC-12-1** Ranking is a total order; no two findings compare equal unless identical.
- **AC-12-2** Review-required items never appear in the confirmed ranking.
- **AC-12-3** Ranking inputs are all verified values; nothing is taken from the model's self-report.
- **AC-12-4** Each finding renders a "why this rank" explanation consistent with its inputs.
- **AC-12-5** `caudit scan` with consent produces `report.md`, `results.sarif`, and `run-manifest.json` with model ids, token totals, and policy versions populated.
- **AC-12-6** `caudit scan` without consent produces the same three artifacts with `model_ids: null` and no network access.
- **AC-12-7** Two runs with a warm cache produce byte-identical Markdown and SARIF.
- **AC-12-8** Exit codes follow part 01: 0 clean, 1 confirmed findings, 3 environment problems.
- **AC-12-9** `caudit compare` computes per-family and macro deltas plus cost, and refuses mismatched policy versions.
- **AC-12-10** The manifest records per-stage timings and the total spend for the run.
- **AC-12-11** A stage failure (index, analyzer, provider) degrades to a partial report with recorded limitations rather than producing nothing.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-12-01 | unit | 30 findings with overlapping attributes | Sort is total and stable; shuffling input does not change output | AC-12-1 |
| T-12-02 | unit | Two findings identical except `finding_id` | Deterministic tie-break | AC-12-1 |
| T-12-03 | unit | Mixed confirmed and review-required | Confirmed ranking contains no review items | AC-12-2 |
| T-12-04 | unit | Model self-reporting `high` on a downgraded finding | Rank uses the verified confidence | AC-12-3 |
| T-12-05 | unit | High severity, unknown reachability vs medium severity, demonstrated | Order matches the documented key precedence | AC-12-1 |
| T-12-06 | unit | Finding found by two analyzers vs one | Higher provenance agreement ranks first, all else equal | AC-12-1 |
| T-12-07 | golden | Fixed 10-finding fixture | Ranked order matches the committed snapshot | AC-12-1, AC-12-4 |
| T-12-08 | unit | Each ranked finding | Explanation string names severity, confidence, reachability, agreement consistently with the values | AC-12-4 |
| T-12-09 | e2e | Fixture repo, consent on, cassettes (`needs_clang`) | Three artifacts written; manifest has model ids, tokens, policy versions | AC-12-5 |
| T-12-10 | e2e | Same repo, consent off, sockets monkeypatched to raise | Artifacts written; `model_ids` null; zero network attempts | AC-12-6 |
| T-12-11 | e2e | Same run twice with a warm cache | `report.md` and `results.sarif` byte-identical | AC-12-7 |
| T-12-12 | e2e | Repo with no findings; repo with findings; missing compile DB | Exit 0, 1, 3 respectively | AC-12-8 |
| T-12-13 | unit | Baseline and adjudicated metrics for the mini suite | Deltas correct; cost summary present | AC-12-9 |
| T-12-14 | unit | Reports with different prompt-policy versions | `compare` refuses with both versions named | AC-12-9 |
| T-12-15 | unit | Completed run | Manifest has per-stage timings and total spend | AC-12-10 |
| T-12-16 | e2e | Provider unavailable mid-run | Partial report produced; affected candidates in review with `provider_unavailable`; exit non-zero but not a crash | AC-12-11 |
| T-12-17 | e2e | One TU fails to parse | Report produced; coverage reflects the gap; limitation recorded | AC-12-11 |
| T-12-18 | perf | 50-TU fixture repo (`slow`) | Wall time and token spend within the recorded budget | — |

Where the tests live: `tests/unit/test_report_ranking.py` (T-12-01 to T-12-08),
`tests/golden/test_ranking.py` (T-12-07), `tests/unit/test_report_assembly.py`
(the staging and provenance properties the e2e tests rest on),
`tests/e2e/test_scan_full.py` (T-12-09 to T-12-12, T-12-15 to T-12-17),
`tests/unit/test_eval_compare.py` (T-12-13, T-12-14),
`tests/integration/test_eval_adjudicated.py` (the `--no-baseline` path), and
`tests/integration/test_scan_perf.py` (T-12-18, `slow`).

## Implementation notes (added 2026-08-13)

Where the built code departs from the sketch above, and why. Nothing here
relaxes an invariant; each row is a decision the sketch did not settle.

| # | The plan says | What was built | Why |
| --- | --- | --- | --- |
| 1 | `src/caudit/cli/scan.py` holds `caudit scan` | `cli/scan.py` holds the orchestration; part 08's `cli/scan_cmd.py` keeps the printing | Two jobs with different reasons to change. `scan.py` decides what happens when the index fails; `scan_cmd.py` decides how a coverage table reads. |
| 2 | `ComparisonReport` is listed under `cli/compare.py` | The models and the differencing live in `eval/compare.py`; the command in `cli/compare.py` | The repository layout puts metrics in `eval/` and commands in `cli/`. A domain model in the CLI layer would be the only one. |
| 3 | `assemble(plan, outcomes, manifest) -> ReportSections` | `adjudicate_candidates(...) -> PipelineResult`, then part 08's `build_report` | The manifest is an *output* of assembly, not an input to it — it carries the counts assembly produces. Splitting the pipeline from the rendering also let `caudit eval --no-baseline` reuse the pipeline without reusing the renderer. |
| 4 | Ranking key: severity, confidence, reachability, agreement, effort, id | Exactly that, and nothing else | Path and line were considered as a readability tie-break and rejected: the "why this rank" line is built from the key's own inputs, and a term the explanation omits would place findings for a reason no reader could audit. |
| 5 | Severity "from CWE family and the verified impact" | Family table, capped by a committed `ImpactKind → Severity` ceiling; `impact.severity` is never read | The impact kind is a fixed enum a model picks from; the severity is free grading. The ceiling can only lower, matching part 11's "a claim is only ever lowered". |
| 6 | `effort: EffortEstimate` "from remediation scope" | Derived from the span of the cited evidence: one region is `local`, several in one file `function`, several files `cross_module` | Remediation scope is a judgement; the evidence span is a measurement, and every region in it was resolved against the scanned revision. AC-12-3 asks for verified inputs. |
| 7 | `provenance_agreement: int` — "independent analyzers" | Distinct `tool_name` among `ANALYZER_PRODUCERS` only | `index` and `llm` entries are components of this tool. Counting them would let one analyzer plus a model outrank two analyzers. The set moved to `model/evidence.py` so part 11 and part 12 read one definition. |
| 8 | "The manifest is completed here" with per-stage timings | `RunManifest` gained `stages`, `total_cost_usd`, `partial`; `SCHEMA_VERSION` → 1.7.0 | `partial` is recomputed from `stages` on every construction, including when the file is read back, so a stored flag cannot disagree with the records under it. |
| 9 | AC-12-10: per-stage timings | Every stage but `report` | A stage cannot record its own duration in the file it is writing. The manifest carries the stages that decided its *content*; rendering is timed for the caller and left out of the file. |
| 10 | "Any run with a stage failure marks the report as partial" | A stage that *raised*, or whose work is recorded nowhere else. A translation unit that will not parse does **not** | A parse failure is already in `coverage.translation_units_failed`, in a part 06 limitation naming the file, and in the report's coverage section. Firing the loudest marker in the output on every repository with an unparseable header would make it unreadable. |
| 11 | AC-12-6: `model_ids: null` | `models: []` | Part 08's committed mapping table already spells `model_ids` as `models`, and the emptiness is the claim: no tier was consulted. |
| 12 | AC-12-9: refuse mismatched "matching, prompt, or profile versions" | `matching` and `profile` always; `prompt` and `retrieval` only when **both** runs adjudicated | An analyzer-only baseline never assembled a prompt. Requiring one to match would refuse exactly the comparison Milestone 2 is defined by. |
| 13 | — | `ComparisonReport.caveats` | An unrecorded policy version or case list is *unknown*, not *different*. Refusing on it would reject every baseline written before the field existed; stating it is the difference between an unchecked assumption and a hidden one. |
| 14 | AC-12-7: two runs byte-identical | Two runs **both warm**, which is what the criterion says | A cached answer costs nothing, so a warm run never reaches the token ceiling that stopped the cold run which filled the cache. Comparing cold against warm compares a budget-limited run with an unlimited one. T-12-18 primes the cache first for this reason. |
| 15 | T-04-18: two eval runs produce byte-identical metrics | The scores, gates, policies and scope are identical; `cost.wall_seconds` is not | The run report now carries a duration, for the same reason `run-manifest.json` always did. The comparison rule draws the line in the same place. |
| 16 | T-12-09 is marked `needs_clang` | Runs in the default suite with the analyzer subprocess layer stubbed | The same command lines, parsers and normalizer run; only the process launch is stubbed. T-08-17 is where those recordings meet a real toolchain, and no part 12 criterion is about Clang itself. |
| 17 | — | `ScriptedProvider` rather than a cassette for the end-to-end tests | A cassette pins one recording to one candidate's evidence ids. A whole-repository scan gives every candidate its own ids, which a committed recording cannot know. It is a plumbing double and is documented as one: answer *quality* is what `caudit eval --no-baseline` measures. |
| 18 | `caudit eval --no-baseline` "arrives in part 12" | Implemented: `eval/adjudicated.py` runs the real pipeline per case | It refuses without consent rather than falling back to the baseline — a run that finished and wrote a file labelled `adjudicated` containing the baseline's numbers is the one measurement nobody could trust. |
| 19 | — | `default_source` no longer takes `baseline` | Candidate *generation* is identical in both modes; what an adjudicated run adds happens afterwards. Both sides starting from the same candidates is what makes the delta attributable to the model. |

### What part 12 does not deliver

`caudit eval --no-baseline` needs an API key and cloud consent, and neither is
available on the development machine. The machinery is built and tested offline
— the harness runs end to end, both sides are scored by identical code below
the adjudicator, and `caudit compare` differences them — but **the M2 number
itself has not been measured here**. That is the same standing as T-07-21,
T-08-17 and T-10-21: the code is there, the confirmation needs a machine that
has the dependency.

## Milestone 2 exit checklist, revisited

Part 11 left two items open because measuring an adjudicated run against the M1
baseline required the pipeline to be assembled. It is assembled now, and the
items are still not tickable — for a different and narrower reason.

- [x] Symbol-level and dependency retrieval feeding adjudication (part 09).
- [x] Structured Gemini output with tiered models, consent, and caching (part 10).
- [x] Confirmed / rejected / review-required implemented, with every state reachable and tested.
- [x] Every citation in every confirmed finding resolves against the scanned revision.
- [ ] Recall, precision, evidence accuracy, cost, and latency measured against the M1 baseline through part 04, with the comparison recorded. — **the path exists and is tested; the run needs an API key.**
- [ ] Hard gates pass on the evaluation set. — the gates pass on the M1 baseline (macro-F2 0.6667, 12/12 citations, zero fabrications, counts separate). They have not been applied to an adjudicated run for the same reason.

Ticking either on a scripted provider would be recording a measurement of a
test double.

## Out of scope and risks

- CI packaging, PR annotations, and diff-versus-baseline mode remain post-MVP, per the locked decision to ship a local CLI first. Nothing here blocks them: SARIF is already emitted, and `compare` provides the diff primitive.
- **Risk:** partial reports could be mistaken for complete ones. Mitigation: any run with a stage failure marks the report as partial in the title line, in the SARIF invocation, and in the manifest.
- **Risk:** ranking becomes a place to smuggle in unverified model judgement. Mitigation: AC-12-3 plus T-12-04 assert every ranking input is a verified value.

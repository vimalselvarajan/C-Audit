# Part 13 — Repository-scale validation

> **Milestone 3 gate.**

## Goal

Find out whether the tool works on real code. Synthetic suites make the vulnerable function and the build environment far easier to isolate than any real project does — the spec says so plainly — so passing CASTLE and Juliet is a precondition for credibility, not evidence of it.

This part adds real vulnerable/fixed repository pairs, builds the independently labeled maintainability set the spec requires, runs the retrieval ablations, and calibrates confidence so the labels mean what they say.

## Depends on / Unlocks

- **Depends on:** 04, 12.
- **Unlocks:** the Phase 2 entry conditions (appendix below).

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/eval/pairs.py` | Vulnerable/fixed revision pair harness |
| `src/caudit/eval/pairs_runner.py` | Checkout, build and scan for one revision |
| `src/caudit/eval/ablation_runner.py` | Scoring one ablation configuration against a suite |
| `src/caudit/cli/ablate_cmd.py`, `pairs_cmd.py`, `calibrate_cmd.py` | `caudit ablate`, `caudit pairs`, `caudit calibrate` |
| `src/caudit/eval/maintainability.py` | Labeled-set loader, agreement statistics, scoring |
| `src/caudit/eval/ablation.py` | Ablation runner over policy configurations |
| `src/caudit/eval/calibration.py` | Confidence and severity calibration |
| `benchmarks/pairs/manifest.yaml` | Pinned CVE-linked repository pairs with build recipes |
| `benchmarks/maintainability/` | Labeled C/C++ set, versioned, with per-labeler records |
| `my_docs/project/evaluation-results.md` | Recorded results per policy version |
| `tests/unit/test_eval_pairs_*.py`, `tests/unit/test_calibration_*.py` | This part's tests |

## Interfaces

```python
class RepoPair(BaseModel):
    pair_id: str
    repo_url: str
    vulnerable_rev: str
    fixed_rev: str
    cve: str | None
    cwe: CweId
    build_recipe: BuildRecipe        # how to produce compile_commands.json
    affected_paths: list[PurePosixPath]

class PairOutcome(BaseModel):
    detected_in_vulnerable: bool
    detected_in_fixed: bool          # a detection here is a false positive
    citation_valid: bool
    tokens: int
    wall_time_s: float

class MaintainabilityLabel(BaseModel):
    case_id: str
    category: MaintainabilityCategory   # complexity | duplicated_validation |
                                        # ownership_ambiguity | coupling | error_handling
    labelers: list[str]                 # ≥2, independent
    agreed: bool
    adjudicator_note: str | None

class AblationConfig(BaseModel):
    name: str
    token_budget: int
    caller_depth: int
    expansion_policy_version: str
    tiers: ModelTierConfig
    retrieval_variant: Literal["structural", "structural_plus_semantic", "flat_window"]
```

## Repository pairs

The strongest available signal, because it needs no hand-labeling: run the same scan at the vulnerable revision and at the fixed revision. A detection at the vulnerable revision that disappears at the fixed one is real; a detection that persists is a false positive with a known answer.

- Pairs are drawn from CVE-linked vulnerable/fixed revisions (e.g. [CVEfixes](https://github.com/secureIT-project/CVEfixes)), pinned by SHA, with a build recipe that produces a working compilation database. A pair whose build cannot be reproduced is excluded and recorded — never silently dropped.
- Development and held-out pairs are separate from the first commit, and the held-out set is run only when a policy version is finalized.
- Every pair run records tokens, wall time, and citation validity, so cost and correctness are tracked on the same axis.

## Maintainability set

The spec defines maintainability for the report-only MVP as identifying and explaining security-relevant maintenance hazards, across five categories. Two labeling rules matter more than the scoring:

1. **At least two independent labelers per case**, with agreement reported. A single-labeler set measures one person's taste.
2. **Labels are adjudicated independently of `clang-tidy` output.** Deriving labels from the tool's own checks scores the tool against itself; the spec names this trap directly.

Scoring: category-level macro-F1, ranking quality for top findings (nDCG@10), and a rubric for whether a recommendation is factually accurate and actionable. All three are reported — no single number.

## Ablations

Each ablation changes one variable and re-runs the development set, recording detection quality, evidence validity, tokens, and latency:

- Token budget: several levels, to find where recall degrades.
- Caller/callee depth.
- Retrieval variant: structural (default) versus structural plus semantic versus a flat context window of comparable size — the flat window is the control that tests whether compiler-aware retrieval earns its complexity.
- Model tiers: triage-only, adjudication-only, with and without escalation.

## Calibration

- Confidence labels are checked against ground truth: of findings marked `high`, what fraction are true? A reliability curve is recorded, and if `high` is not meaningfully better than `medium`, the labels are wrong and get recomputed.
- Severity is compared against adjudicated severity on the pair set.
- Calibration results are recorded per policy version; a policy change invalidates prior calibration.

## Invariants

- **Held-out data is used once per finalized policy version**, and the result is recorded whatever it says.
- **Every pair, label, and ablation result names its policy version.** Results across versions are not pooled.
- **Excluded pairs are recorded with a reason.** Silently dropping a repository that fails to build is how a benchmark becomes flattering.
- **Synthetic and real results are always reported side by side**, never one in place of the other.

## Acceptance criteria

- **AC-13-1** The pair harness builds both revisions, produces a compilation database for each, and records a `PairOutcome`.
- **AC-13-2** A detection at the fixed revision is counted as a false positive, not ignored.
- **AC-13-3** A pair that fails to build is excluded with a recorded reason and excluded from metrics.
- **AC-13-4** Development and held-out pair sets are disjoint, enforced by a test over the manifest.
- **AC-13-5** The maintainability loader rejects any case with fewer than two independent labelers.
- **AC-13-6** Inter-labeler agreement is computed and reported with the scores.
- **AC-13-7** Macro-F1, nDCG@10, and the recommendation rubric are all reported; no single aggregate replaces them.
- **AC-13-8** The ablation runner varies one factor at a time and produces comparable, reproducible results.
- **AC-13-9** The flat-window control is run, so the value of structural retrieval is measured rather than assumed.
- **AC-13-10** The calibration curve is computed from ground truth, and a miscalibrated `high` label fails a check.
- **AC-13-11** Every recorded result names its policy versions; pooling across versions raises.
- **AC-13-12** The overall score (0.5 security + 0.5 maintainability) is computed only after every hard gate passes, and refuses to report otherwise.
- **AC-13-13** The finding→category predictor abstains rather than guessing: a finding with no signal returns `None`, never a fallback category, and no weakness in the CWE allowlist reaches a category `UNCOVERABLE` declares out of range.
- **AC-13-14** A labelled category the predictor cannot reach withholds the macro-average and records why, instead of averaging in an F1 of 0.0 the schema made unavoidable. The per-category figures are still published.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-13-01 | unit | Synthetic pair: vulnerable and fixed revisions of one fixture file | Detected in vulnerable, absent in fixed → outcome recorded correctly | AC-13-1 |
| T-13-02 | unit | Pair where the finding persists after the fix | Counted as a false positive; surfaced in metrics | AC-13-2 |
| T-13-03 | unit | Pair whose build recipe fails | Excluded with reason; not counted as a miss | AC-13-3 |
| T-13-04 | unit | Pair manifest with an id in both sets | Disjointness test fails with the id named | AC-13-4 |
| T-13-05 | unit | Maintainability case with one labeler | Loader rejects it | AC-13-5 |
| T-13-06 | unit | 20 cases, known disagreement pattern | Agreement statistic matches the hand-computed value | AC-13-6 |
| T-13-07 | unit | Scored maintainability run | All three metrics present; no combined single score in the output type | AC-13-7 |
| T-13-08 | unit | Ranked findings with known relevance | nDCG@10 matches the hand-computed value | AC-13-7 |
| T-13-09 | unit | Ablation grid varying budget only | Only the budget differs between configs; other fields identical | AC-13-8 |
| T-13-10 | unit | Same ablation config run twice with a warm cache | Identical results | AC-13-8 |
| T-13-11 | unit | Ablation set | The `flat_window` control is present and executed | AC-13-9 |
| T-13-12 | unit | Findings with known truth and confidence labels | Reliability curve matches hand computation | AC-13-10 |
| T-13-13 | unit | Set where `high` findings are true less often than `medium` | Calibration check fails loudly | AC-13-10 |
| T-13-14 | unit | Results with two different prompt-policy versions | Pooling raises with both versions named | AC-13-11 |
| T-13-15 | unit | Metrics failing the ≥95% citation gate | Overall score is refused, gate failure reported instead | AC-13-12 |
| T-13-16 | unit | Metrics passing all gates | Overall score computed as 0.5/0.5 | AC-13-12 |
| T-13-17 | integration | Two real pinned pairs (`slow`, `needs_clang`) | Both build, scan, and produce outcomes end to end | AC-13-1 |
| T-13-18 | unit | Held-out set accessed twice for one policy version | Second access warns and is recorded | AC-13-4 |
| T-13-19 | unit | Mini suite scored under the baseline and under the control | Both rows carry an evidence-coverage figure and differ in token cost — the two configurations reach `expand` | AC-13-8, AC-13-9 |
| T-13-20 | unit | Suite with no compilation database available | Every case excluded with a reason; coverage is `None`, never `0.0` | AC-13-3 |
| T-13-21 | unit | Grid scored with no provider | `structural_retrieval_earns_itself()` is `None`, not `False`; the coverage question is answered | AC-13-9 |
| T-13-22 | unit | `caudit ablate --suite mini` with no consent | Grid runs offline, control present in the written record | AC-13-8 |
| T-13-23 | unit | Pair scanner with an injected command runner | Detection restricted to confirmed findings in `affected_paths`; a failed checkout or an absent database excludes the pair with the revision named | AC-13-1, AC-13-2, AC-13-3 |
| T-13-24 | unit | Findings labelled from suite ground truth; an inverted `high`/`medium` set | Truth comes from the corpus, not the finding; the miscalibrated set fails; small bins reported and not judged | AC-13-10 |
| T-13-25 | unit | A `CWE-416` finding, cited locally and across two files | Both predict `ownership_ambiguity`: the weakness family is consulted before the evidence span, so an ownership defect is not relabelled by where it happens to be cited | AC-13-13 |
| T-13-26 | unit | A `CWE-787` finding cited in two files, and one cited twice in one file | `coupling` and `complexity` respectively, from `effort_of`'s verified span | AC-13-13 |
| T-13-27 | unit | A single-region `CWE-787` finding; a `CWE-772` resource leak | Both abstain — `None`, not a fallback category. A leak is genuinely ambiguous between ownership and error handling, so the table declines to choose | AC-13-13 |
| T-13-28 | unit | Every CWE in the allowlist, at each of the three evidence spans | No prediction ever lands in `UNCOVERABLE`; `UNCOVERABLE` is derived from the two tables, so widening one without narrowing it fails | AC-13-13 |
| T-13-29 | unit | A label set containing an `error_handling` case | `macro_f1 is None` with a refusal naming the category — **not** `0.0`; per-category F1 still reported; `assert_covers` raises; a score cannot carry a number and a refusal, or neither | AC-13-14 |
| T-13-30 | unit | A label set using only reachable categories; a case with two findings | A float macro-F1 matching `macro_f1()` directly; the top-ranked finding speaks for its case, and a case whose leader abstains abstains rather than consulting the runner-up | AC-13-14 |

## Implementation notes (added 2026-08-14)

Where the built code departs from the sketch above, and why.

| # | The plan says | What was built | Why |
| --- | --- | --- | --- |
| 1 | `run_pair` builds both revisions | The scan is an injected `ScanRevision` callable; `run_pairs` owns only the accounting | Cloning and building need a network and a toolchain. Separating them means the rules that matter — what counts as a detection, what is excluded — are tested offline, and T-13-17 supplies the real half. |
| 2 | `PairOutcome.detected_in_fixed` | Plus `true_positive`, `false_positive` and `missed` as properties | "Detected in the fixed revision" is a fact; "false positive" is the judgement about it. Naming the judgement stops each caller re-deriving it, differently. |
| 3 | — | A pair whose *fixed* side fails is excluded too, not scored on the vulnerable side alone | One side cannot distinguish a detection from a persistent false positive. Scoring it either way would be inventing the answer. |
| 4 | Held-out data "is used once per finalized policy version" | `HeldOutLedger` records and **warns**; it does not refuse | A refusal blocks a legitimate re-run after a crash, and the workaround is to delete the ledger — which destroys the record the rule depends on. The count is published instead, and `caveat()` renders it. |
| 5 | `PairScore` unspecified | Three numbers: detection rate, persistence rate, exclusions. No F-score | A pair set answers two different questions, and a harmonic mean of them hides which one moved. |
| 6 | `MaintainabilityLabel.labelers: list[str]` — "≥2, independent" | Enforced as ≥2 **distinct** entries | One person listed twice is one person, and `min_length` alone would not catch it. |
| 7 | "Labels are adjudicated independently of `clang-tidy` output" | A `source` field, refused when it names an analyzer this project runs | The one place that rule can be made checkable instead of merely intended. |
| 8 | — | `agreed=false` requires an `adjudicator_note` | A label with an unrecorded third opinion in it cannot be audited later. |
| 9 | "Inter-labeler agreement is computed" | Raw agreement **and** Cohen's kappa, both published, kappa `None` for a single category | Raw agreement flatters an unevenly distributed set; kappa is hard to read alone. Neither substitutes for the other, and chance agreement is undefined rather than perfect when only one category is in play. |
| 10 | "a rubric for whether a recommendation is factually accurate and actionable" | Two independent booleans per verdict | They fail independently: correct advice can be impossible to act on, and an actionable suggestion can be wrong about the code. Which one failed is the part worth knowing. |
| 11 | `AblationConfig.retrieval_variant: Literal[...]` | A `RetrievalVariant` `StrEnum`; the `Literal` alias is kept for callers written against the sketch | The value is compared, switched on, and rendered; an enum makes a typo a failure rather than a silently distinct configuration. |
| 12 | "Each ablation changes one variable" | `vary` refuses an unknown field **and** a value the baseline already has | A grid point identical to its baseline reports "no effect" for a factor that was never varied — convincingly, and wrongly. |
| 13 | AC-13-9: the flat-window control is run | `ablation_grid` adds it whether or not it was asked for, and `AblationSuite` refuses a set without one | Leaving it out is the easiest way to produce a flattering table, so it is not a caller's decision. |
| 14 | — | `structural_retrieval_earns_itself()` returns `None` when the control has not run | "Not measured" is a different answer from "no", and it must never render as "yes". |
| 15 | AC-13-12: the overall score is computed only after every gate passes | `gated_overall_score` routes through part 04's `overall_score` and adds a calibration refusal | One place holds the gate rule. A score built on labels that do not mean what they say is a number nobody should quote, so miscalibration refuses too. |
| 16 | AC-13-10: "a miscalibrated `high` label fails a check" | Only bins with at least `minimum_per_bin` (default 5) entries are judged | Two `high` findings, one wrong, is noise. A check that fires on noise is a check somebody switches off. |
| 17 | `benchmarks/pairs/manifest.yaml` — "pinned CVE-linked pairs" | Committed **empty**, with the procedure in a README | Pinning a pair means cloning it, checking out both revisions, and confirming the recipe builds. None of that is possible here, and a manifest of unverified SHAs would look like evidence. |
| 18 | `benchmarks/maintainability/` — "labeled C/C++ set" | The format, the rules and the loader; **no labels** | The set needs at least two independent human labellers per case. Generating it would defeat its purpose twice over, so it is documented and left empty. |
| 19 | — | The finding→category predictor **abstains**: two small tables, `None` for anything else, and no catch-all bucket | A predictor with a fallback reports a confident label for every finding and measures the bucket. The tables read the weakness family and `effort_of`'s verified evidence span — a fact about the defect and a measurement of the citations — never the prose in `MaintainabilityImpact`, which is not checkable. `RESOURCE_LEAK` is absent on purpose: it is genuinely ambiguous between `ownership_ambiguity` and `error_handling`, and choosing would be the blind mapping this design exists to avoid. |
| 20 | `score_maintainability` returns a macro-F1 | `macro_f1` is `float \| None`, withheld with a stated `refusal` when a labelled category is `UNCOVERABLE` | This is the objection that kept the predictor unbuilt, answered rather than ignored. Two categories have no signal in the current schema, so their F1 would be 0.0 by construction and would understate the tool for a reason that is an artefact of the bridge. Withholding the average says so; averaging it in does not. Same discipline as decision 14. Closing the gap needs a model-facing hazard field, which means a prompt bump and re-recording every cassette. |
| 19 | — | `tests/conftest.py` now restores `logger.propagate` | `configure_logging` turns propagation off, so any test that called it silenced `caplog` for the rest of the session. T-13-18 was the first assertion to notice; the fixture was the bug. |

## Runners and commands (added 2026-08-14)

The four modules above were, until this revision, imported by nothing but
their own tests. Each was a correct set of rules with no way to apply them:
running an ablation, a pair set, or a calibration meant writing Python. The
gap mattered most for the flat-window control, whose absence was recorded as
"needs an API key" when the truth was that the variant had no implementation
at all.

| Module | Runner | Command |
| --- | --- | --- |
| `eval/ablation.py` | `eval/ablation_runner.py` — `SuiteScorer`, `measure_retrieval` | `caudit ablate` |
| `eval/pairs.py` | `eval/pairs_runner.py` — `RepositoryScanner` | `caudit pairs` |
| `eval/calibration.py` | `cli/calibrate_cmd.py` — `scored_findings` | `caudit calibrate` |
| `eval/maintainability.py` | **none** — see below | — |

Three decisions inside them are load-bearing:

**An ablation has two modes, and a row says which one it is.** `detection`
puts a model in the loop; `retrieval_only` stops after expansion and needs no
key, no consent and no socket. A retrieval-only row carries the analyzer-only
`macro_f2` in *every* configuration, because no model read either context — so
`structural_retrieval_earns_itself()` returns `None` rather than comparing
them. Left comparing, it would have returned `False` every time: a confident
"structural retrieval does not earn itself" from an experiment that could not
have shown otherwise. `structural_retrieval_covers_more()` is the question a
retrieval-only grid can answer, and it reads a coverage column instead.

**A pair is detected only by a confirmed finding in a file the fix touched.**
A scan of a real repository reports findings all over it; crediting any of
them would score the corpus on unrelated true positives and every pair would
look found. A review-required item in the right file is the tool saying it
could not stand the claim up, and counting it would merge the two counts the
spec keeps apart in the one place the merge would be invisible.

**Calibration truth comes from the corpus, never from the run.** Findings are
labelled true or false by part 04's matching policy against the suite's ground
truth — the same rule that decides a true positive in the metrics, so the
curve cannot disagree with the score beside it. The severity it records is the
one the *report* showed (`ranking.severity_of`), not `impact.severity`, which
is the model's own grading and a number no reader ever saw.

### What part 13 does not deliver

The harness is built, tested, and now runnable from the command line. The
bridge that was missing has since been built. What is still missing is data:

| Deliverable | Blocked on |
| --- | --- |
| Repository pairs | Pinned SHAs, network access, per-project build toolchains. `caudit pairs` refuses with the procedure until the manifest has one. |
| Maintainability score | At least two independent human labellers per case. The predictor exists now and reaches three of the five categories; the other two withhold the macro-average rather than depressing it. See below. |
| Ablations, detection mode | An API key — every tier ablation needs a model |
| Ablations, retrieval mode | **Nothing. It has been run**; see [evaluation-results.md](../project/evaluation-results.md). |
| Calibration | A corpus big enough to judge. The mini suite's largest bin holds four findings, and bins below `minimum_per_bin` are reported and not judged. |
| Overall score | The maintainability half, which has not been measured at all |

**The maintainability predictor abstains, and the score refuses.** `Finding`
carries a `MaintainabilityImpact` — five severity-graded prose fields — and
`score_maintainability` wants a `MaintainabilityCategory` per case, one of
five. Three of the categories have a plausible mapping and two
(`duplicated_validation`, `error_handling`) have none, so a mapping written
across all five would score zero on those two by construction and understate
the tool for a reason that is an artefact of the bridge rather than of the
tool. That was the reason the predictor stayed unbuilt until 2026-08-14; it is
now the reason it is built the way it is.

`predict_category` reads two signals and declines everything else. The weakness
family goes first, because it says what the defect *is*: `memory_lifetime` is
an ownership question. `effort_of`'s evidence span is the fallback, because it
says how far the defect reaches: citations in two files are `coupling`, two
regions in one file are `complexity`. Both are checkable — the family comes
from the committed CWE allowlist, the span from citations that resolved against
the scanned revision — and neither reads the prose in `MaintainabilityImpact`,
which is not. Anything else returns `None`. There is no catch-all bucket,
because a predictor with one labels every finding confidently and measures the
bucket. `resource_leak` is absent from the family table for the same reason:
it is genuinely ambiguous between `ownership_ambiguity` (nobody owns the close)
and `error_handling` (the close is skipped on the failure path).

`UNCOVERABLE` names the two categories no signal can reach, and
`score_maintainability` withholds the macro-average with a stated reason when
the label set contains one — `float | None`, the same discipline as
`structural_retrieval_earns_itself` returning `None` rather than "no". The
per-category numbers are still published, because *which* category was
unreachable is the part a reader can act on. Closing the gap properly still
means a model-facing field naming the hazard, which still means a prompt
version bump and re-recording every cassette against an API this machine
cannot reach. Until then the score says what it cannot measure instead of
quietly measuring it wrong.

[my_docs/project/evaluation-results.md](../project/evaluation-results.md) records that state
explicitly rather than leaving the tables empty and letting a reader assume the
runs were done. The one number that *has* been measured — the mini suite's
analyzer-only baseline at macro-F2 0.6667 — is there beside them, labelled as
synthetic.

## Milestone 3 exit checklist

Revised 2026-08-14. Two items are now **partly done** — one partly measured,
one with its last piece of code built and only data outstanding. The rest are
open and blocked on data rather than on code.

- [ ] Real vulnerable/fixed repository pairs run end to end, with build failures recorded rather than hidden. — harness and runner built (`eval/pairs.py`, `eval/pairs_runner.py`, `caudit pairs`, T-13-01…04, T-13-23); **no pairs pinned**.
- [~] Maintainability set built, ≥2 independent labelers per case, agreement reported. — loader, scoring and the finding→category predictor built (`eval/maintainability.py`, T-13-05…08, T-13-25…30); the predictor reaches three of the five categories and abstains on the rest. **No labels**, and they cannot be generated: this half needs people.
- [~] Context-budget and retrieval ablations run, including the flat-window control. — grid, runner and command built (`eval/ablation.py`, `eval/ablation_runner.py`, `caudit ablate`, T-13-09…11, T-13-19…22). **The retrieval half has run**: the control retrieves the same share of the decisive code as structural retrieval on the mini suite and spends 3.4x the tokens doing it. The detection half **needs an API key**.
- [ ] Confidence labels calibrated; severity ranking checked against adjudicated severity. — curve, checks and bridge built (`eval/calibration.py`, `caudit calibrate`, T-13-12…13, T-13-24); runs on the mini suite and reports that **no bin is large enough to judge**, which is the honest answer on six cases.
- [ ] Hard gates pass on the held-out set; synthetic and real results reported together. — the gates pass on the mini suite; the held-out set does not exist.
- [x] `my_docs/project/evaluation-results.md` records results per policy version. — written, and it records the absences above rather than leaving them blank.

The milestone is still not close to passing, and the checklist says so. What
part 13 delivered is the machinery that will make the answers trustworthy when
the data arrives: a corpus that cannot silently drop its hard cases, a label
set that cannot be adjudicated from the tool's own output, an ablation grid
that cannot omit its control, a score that refuses to exist while a gate is
failing, a predictor that abstains rather than filling a bucket — and, as of
this revision, a way to run all four without writing Python.

## Appendix — Phase 2 entry conditions (deferred)

The spec keeps an optional remediation agent for Phase 2: propose patches in an isolated worktree, build and test each one, re-run the audit, and measure regressions. Only then do [MaintainCoder/MaintainBench](https://github.com/IAAR-Shanghai/MaintainCoder), [SWE-CI](https://github.com/SKYLENAGE-AI/SWE-CI), and [NITR](https://github.com/ucr-riple/NITR) become relevant benchmarks — they measure code editing, not vulnerability reporting, and must not be cited as evidence that the report-only MVP detects anything.

Entry conditions: Milestone 3 passed on held-out data; calibrated confidence; a stable finding schema; and an isolation mechanism that cannot touch the user's working tree. The clones under `inspiration_repos/` are read-only reference material and stay that way.

## Out of scope and risks

- No patch generation, no code modification — that is Phase 2 by definition.
- **Risk:** benchmark overfitting through repeated held-out use. Mitigation: held-out access is recorded and warned on (T-13-18), and policy versions are pinned to results.
- **Risk:** the maintainability set is small and reflects its labelers. Mitigation: agreement is published with the scores, categories come from the spec rather than from what the tool happens to detect, and the set is versioned so growth is visible.
- **Risk:** real-world pairs are expensive to run and will be run rarely. Mitigation: the mini suite and CASTLE stay as fast regression signals; pairs gate releases, not commits.

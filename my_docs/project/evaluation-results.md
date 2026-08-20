# Evaluation results

> Last checked: 2026-08-15.

> **Every number in this document before 2026-08-15 was withdrawn and
> re-measured.** They had been produced by replaying authored fixtures through
> a check list this project does not ship — no compiler diagnostics, no alpha
> checkers, and the whole `clang-analyzer-*` glob including checkers the
> curated profile deliberately excludes. `caudit eval` also had no command-line
> way to invoke a real analyzer. Both are fixed; the entries below are
> measurements of the shipped tool, and they say which toolchain produced them.

Every recorded result names the policy versions that produced it. Results from
different versions are never pooled — `score_pairs`, `pooled` and
`compare_runs` all raise rather than averaging two different tools — so this
document is a series of dated, versioned entries rather than a running total.

**Synthetic and real results are always reported side by side.** A synthetic
suite makes the vulnerable function and the build environment far easier to
isolate than any real project does, so passing one is a precondition for
credibility rather than evidence of it. Where a real-world number is missing,
this document says so instead of letting the synthetic one stand in for it.

## Current state

| Corpus | Status |
| --- | --- |
| `benchmarks/mini` (6 cases, committed) | **measured**, analyzer-only and adjudicated |
| CASTLE (110 in-scope of 250) | **measured**, analyzer-only and adjudicated; all four gates pass |
| Juliet C/C++ 1.3 subset | not fetched; adapter built, run under `slow` |
| Repository pairs | **no pairs pinned yet** — `benchmarks/pairs/manifest.yaml` is empty |
| Maintainability labels | **no labels yet** — needs ≥2 independent human labellers per case. The predictor exists as of 2026-08-14 and reaches three of the five categories |
| Retrieval ablation (mini) | **measured**, no model needed |
| Calibration (mini) | **run**; no bin large enough to judge |

The harness for every row above is built, tested, and runnable from the
command line — `caudit eval`, `caudit ablate`, `caudit calibrate`,
`caudit pairs`. What is missing from the middle rows is data, not code, and no
number in this document is derived from a corpus that does not exist.

### What the candidate set bounds, and what it does not

The analyzers decide what is **visible**. A defect that produced no candidate
has no prompt assembled for it, so the model is never asked and it cannot be
found at any model quality. That ceiling is real and is measured below: the
CWE-190 half of the `integer` family is undetectable because clang ships no
static checker for arithmetic overflow, and 6 of 12 vulnerable cases there
produce zero candidates.

Within the candidate set, adjudication moves findings **both ways**, and an
earlier version of this document was wrong to say otherwise. It rejects
candidates the deterministic promotion confirmed wrongly, which raises
precision. It also *rescues* candidates the deterministic promotion could not
classify — an unmapped analyzer rule yields no CWE and routes to
`out_of_scope_family` as review-required — and confirming those **raises
recall**. On CASTLE it did both: 7 cases gained a confirmed finding and 18 lost
one, for true positives 23 → 28 and false positives 33 → 14, with the candidate
set identical at 157 findings in both runs.

The mini suite cannot show either effect. It has **zero false positives at
baseline**, so there is no precision to win, and its two misses produce no
candidates, so there is no recall to rescue. Its adjudicated score can only
fall. That is a property of six hand-written cases, not a result about the
model — and it is why CASTLE, with 44 deliberately-safe cases and 33 baseline
false positives, is the corpus that can actually answer the question.

## Mini suite — analyzer-only baseline

Measured 2026-08-15 on clang and clang-tidy 18.1.3, curated profile v1.
Policy versions: `matching v1`, `profile v1`, `prompt v2`, `retrieval v1`.
Command: `caudit eval --suite mini --baseline --use-clang`.

| Metric | Value |
| --- | --- |
| macro-F2 (β=2, recall-weighted) | **0.6667** |
| false positives per KLOC | 0.000 |
| citation resolution rate | 1.0000 (36/36) |
| evidence validity rate | 1.0000 |
| confirmed findings | 4 |
| items needing review | 2 |

All four hard gates pass. Four of the six weakness families are detected —
`injection`, `out_of_bounds`, `memory_lifetime`, `resource_leak` — and two are
missed, which is what a macro-F2 of 0.6667 is made of.

**The figure is unchanged from the withdrawn one and that is a coincidence, not
a confirmation.** Four families were detected either way, but not the same
four. The earlier number credited `null-deref-unchecked-alloc`, which clang
18.1.3 does not detect, and missed `resource-leak-error-path`, which it does —
via `alpha.unix.Stream`, a checker the old check list did not enable. The two
`analyzer_blind_spot` flags were predictions and both were wrong, in opposite
directions; they now record a measurement. See
[benchmarks/mini/README.md](../../benchmarks/mini/README.md).

This is the floor an adjudicated run has to beat. It is deliberately not
impressive: it is what the deterministic analyzers do alone, measured before
any model was allowed near the pipeline.

## Mini suite — adjudicated

Measured 2026-08-15. Models `gemini-flash-lite-latest` (triage),
`gemini-flash-latest` (adjudication), `gemini-pro-latest` (escalation).
Command: `caudit eval --suite mini --no-baseline --use-clang --baseline-metrics …`.

| Metric | Baseline | Adjudicated | Δ |
| --- | --- | --- | --- |
| macro-F2 | 0.6667 | **0.5000** | −0.1667 |
| false positives per KLOC | 0.000 | 0.000 | 0 |
| citation resolution rate | 1.0000 | 1.0000 (24/24) | 0 |
| evidence validity rate | 1.0000 | 1.0000 | 0 |
| confirmed findings | 4 | 3 | −1 |
| items needing review | 2 | 3 | +1 |

Cost: 12 provider calls, 15 189 input and 4 527 output tokens, 219 s wall.
Spend is reported as $0.0000 because `llm.pricing.*` is unset, not because the
run was free.

`baseline_floor` **fails**: 0.5000 against a floor of 0.6667. No overall score
is reported while a gate is failing, and `caudit compare` refuses to call the
comparison a result. That refusal is the harness working.

Read the −0.1667 narrowly. It is one case, and the model was not wrong about
it. On `oob-write-stack-copy` — `strcpy` into a fixed buffer — the analyzers
say CWE-787 and Gemini answered **CWE-120**, "Buffer Copy without Checking Size
of Input", which is the canonical mapping for an unbounded string copy and
arguably the more precise of the two. CWE-120 is not in C Audit's 37-entry
allowlist, so the gate routed the finding to review as `out_of_scope_family`
and the true positive was lost. That is a gap in the allowlist, not a model
error, and it is recorded as an open decision rather than quietly patched.

The other two misses are the analyzer blind spots. Neither produced a
candidate, so no prompt was ever assembled for them — the model could not have
helped and was never asked.

## CASTLE — analyzer-only baseline

Measured 2026-08-15 on clang and clang-tidy 18.1.3, curated profile v1.
Corpus pinned at `main`, cloned to the benchmark cache. Policy versions:
`matching v1`, `profile v1`, `prompt v2`, `retrieval v1`.
Command: `caudit eval --suite castle --baseline --use-clang`.

**110 of CASTLE's 250 cases are scored** — the 11 CWEs inside C Audit's
allowlist, 66 vulnerable and 44 deliberately not. The other 14 CWEs (10 cases
each: CWE-22, 89, 253, 327, 362, 522, 617, 628, 674, 770, 798, 822, 835, 843)
are web, crypto, concurrency and authentication weaknesses this project does
not claim to analyse. They are skipped with a per-CWE count, so this is a score
over 110 cases and must not be read as one over 250.

| Metric | Value |
| --- | --- |
| macro-F2 (β=2, recall-weighted) | **0.2290** |
| false positives per KLOC | 13.665 |
| citation resolution rate | 1.0000 (792/792) |
| evidence validity rate | 1.0000 |
| confirmed findings | 56 |
| items needing review | 101 |

| Family | tp | fp | fn | precision | recall | F2 |
| --- | --- | --- | --- | --- | --- | --- |
| `injection` | 5 | 1 | 16 | 0.833 | 0.238 | 0.278 |
| `integer` | 0 | 14 | 12 | 0.000 | 0.000 | 0.000 |
| `memory_lifetime` | 10 | 0 | 15 | 1.000 | 0.400 | 0.455 |
| `null_uninitialized` | 1 | 1 | 8 | 0.500 | 0.111 | 0.132 |
| `out_of_bounds` | 2 | 11 | 13 | 0.154 | 0.133 | 0.137 |
| `resource_leak` | 5 | 6 | 9 | 0.455 | 0.357 | 0.373 |

All four hard gates pass. This is the first number in this document from a
corpus the project did not write, and it is a third of the mini suite's for
exactly that reason — six hand-written cases are not evidence about 110
third-party ones, which is why this document reports them side by side rather
than averaging them.

The corpus produces **33 false positives overall** — the precision headroom the
mini suite does not have, and the only way an adjudicated run can beat a
baseline given that adjudication cannot add recall.

Only *confirmed* findings are matched against ground truth; the 101
review-required items are counted and reported but never scored as detections,
so none of them is in that 33. That is the spec's separation holding under a
real corpus rather than in a unit test.

### What the 33 are made of

Grouped by the rule that fired, across all 110 cases with the count that landed
on one of the 44 deliberately-safe cases:

| Rule | fired | on a safe case |
| --- | --- | --- |
| `unix.Malloc` | 29 | 0 |
| `security.insecureAPI.strcpy` | 15 | **6** |
| `-Wunused-parameter` | 24 | 6 |
| `-Wsign-conversion` | 13 | **7** |
| `-Wsign-compare` | 4 | **4** |
| `-Wunused-command-line-argument` | 13 | 2 |
| `-Wformat-security` | 6 | 1 |

Three observations, and the first is the one to act on.

`security.insecureAPI.strcpy` is **syntactic**: it fires because the code calls
`strcpy`, not because a bound was shown to be missing. Six of its fifteen hits
are on cases written to be safe. Deciding whether a particular `strcpy` is
bounded needs someone to read the surrounding code — which is the exact job
adjudication exists for, and the single clearest place a model can earn its
cost on this corpus.

`unix.Malloc` fires 29 times and **never once on a safe case**. It is the
path-sensitive checker in the set and it is the family with precision 1.000.
Where the analyzer actually reasons about paths, it is right.

`-Wunused-parameter`, `-Wsign-compare` and `-Wunused-command-line-argument` are
not security findings at all — the last is not even about the code, it is about
the compile invocation. They arrive because the profile passes `-Wall -Wextra`,
and they reach the report as review-required with no CWE rather than as
confirmed findings. They still cost attention, and dropping `-Wextra` in favour
of naming the diagnostics the profile actually maps is a cheap, deterministic
precision win that needs no model at all. It is deliberately **not** done yet:
changing the profile changes `profile v1`, and `caudit compare` refuses two
runs scored under different profile versions. It belongs in the next policy
version, not in the middle of a measurement.

### FP/KLOC 13.665 is an upper bound on the error, not a measurement of it

CASTLE is a set of single-CWE micro-benchmarks. Each case is labelled for the
one weakness it was written to exercise, and `"vulnerable": false` means *this
case does not contain the CWE it is about* — it is not a claim that the file is
free of every other defect. **Absence of a label is not evidence of absence.**

That is not hypothetical here. `CASTLE-78-10.c` is labelled safe for CWE-78: it
sanitises the command before use, so the injection really is fixed. It also
contains, at lines 21 and 32–33:

```c
strcpy(__buff, buf);          /* into a caller-supplied pointer of unknown size */
...
strcat(sys, cmd);             /* char sys[BUFSIZ], unbounded concatenation */
strcat(sys, buff);
```

C Audit flags these and is scored wrong for it. They look like genuine CWE-787
or CWE-120 issues that CASTLE simply does not label, because they are not what
that case is testing.

This has three consequences worth stating plainly:

1. **The true false-positive rate is lower than 13.665/KLOC**, by an unknown
   amount. Establishing it would need every case relabelled for every weakness
   it contains, which is a manual effort CASTLE has not done and neither have we.
2. **`out_of_bounds` precision of 0.154 is understated.** The
   `security.insecureAPI.strcpy` rule maps to CWE-787, so all 15 of its hits are
   charged to `out_of_bounds` precision — and 13 of them fired in cases about
   entirely different CWEs, where no out-of-bounds ground truth exists to match
   against. Attributing a finding by its own family is right for the question
   "when C Audit says out-of-bounds, is it correct?", but on a single-CWE corpus
   it collides with labels that only cover one family per case.
3. **It sets a trap for the adjudicated comparison.** A model that reads
   `strcat(sys, cmd)` and correctly confirms an unbounded write will be scored
   as *losing* precision. If the adjudicated run shows fewer false positives,
   that is a real gain; if it shows more, this caveat has to be checked before
   the model is blamed.

Recorded before the adjudicated numbers were in, so it cannot be read as an
explanation constructed to fit them.

### Why `integer` scores 0.000, and what it says about the architecture

The worst cell in the table is worth reading closely, because the cause is not
a tuning problem and the conclusion generalises.

The family is 20 CASTLE cases: 10 CWE-190 (integer overflow) and 10 CWE-369
(divide by zero), 12 of them vulnerable. All 12 are missed.

**CWE-190 is undetectable by the deterministic tier.** Clang 18 ships no static
checker for general arithmetic overflow — the only overflow checkers it has are
`alpha.security.ArrayBound*` (buffer bounds) and `alpha.security.MallocOverflow`
(a `malloc` argument), and clang-tidy's nearest check,
`bugprone-integer-division`, is about truncating division rather than overflow.
Detecting it statically needs constant propagation and range arithmetic that no
shipped checker performs; `-fsanitize=signed-integer-overflow` finds it at
*runtime*, which a static audit cannot use. The curated profile's four
`integer` checks are all conversion and truncation warnings mapping to CWE-195,
CWE-196 and CWE-197. Adding a checker would not fix this, because there is no
checker to add.

On `CASTLE-190-1.c` the truth is line 6, `int z = y*y`, where `y` is 77³ and the
product overflows `int`. C Audit reports line 7 instead — a real
`-Wsign-conversion` on the following statement. A different defect at an
adjacent line, correctly scored as one false positive and one miss rather than
as a near-hit.

**CWE-369 is a path-sensitivity limit, not a coverage gap.** `core.DivideZero`
*is* enabled and *is* mapped to CWE-369. It does not fire on cases like
`CASTLE-369-3.c`, where the divisor is the result of 13 500 iterations of
modular arithmetic — the analyzer cannot prove the value reaches zero, which is
the correct behaviour for a checker that must not guess.

Both are precisely the kind of reasoning a model does well: computing that
77³ squared exceeds `INT_MAX` is arithmetic, not path exploration. **For 6 of
the 12 it cannot be asked**, because those cases produce no candidate at all
and no prompt is ever assembled for them.

For the other 6 it was asked, and it helped: the adjudicated run below takes
`integer` from 0 true positives to 1 and from 14 false positives to 8, on
`190-2`, a case where the analyzers produced a candidate the deterministic
promotion could not classify.

That is the ceiling this evaluation establishes, stated precisely: **the
candidate set bounds recall, and the analyzers determine the candidate set.**
A family whose defects produce no candidates cannot be improved by any model.
Raising recall there needs a candidate generator that proposes suspect sites
for a model to rule on — a design change, not a prompt or a model upgrade.

## CASTLE — adjudicated

Measured 2026-08-15. Models `gemini-flash-lite-latest` (triage),
`gemini-flash-latest` (adjudication), `gemini-pro-latest` (escalation). Same
110 cases, same policy versions, same toolchain as the baseline above.
Command: `caudit eval --suite castle --no-baseline --use-clang --baseline-metrics …`.

**All four hard gates pass, `baseline_floor` included.** This is the first
result in this repository where a model-in-the-loop run clears the analyzer
floor it is measured against.

| Metric | Baseline | Adjudicated | Δ |
| --- | --- | --- | --- |
| macro-F2 | 0.2290 | **0.2903** | **+0.0613** |
| false positives per KLOC | 13.665 | **5.797** | **−7.868** |
| citation resolution rate | 1.0000 (792/792) | 1.0000 (593/593) | 0 |
| evidence validity rate | 1.0000 | 1.0000 | 0 |
| confirmed findings | 56 | 42 | −14 |
| items needing review | 101 | 115 | +14 |
| true positives | 23 | **28** | **+5** |
| false positives | 33 | **14** | **−19** |

Cost: 254 provider calls, 268 137 input and 83 872 output tokens, 4 940 s wall.
Spend reads $0.0000 because `llm.pricing.*` is unset, not because it was free.

| Family | Δ precision | Δ recall | Δ F2 | Δ tp | Δ fp |
| --- | --- | --- | --- | --- | --- |
| `out_of_bounds` | **+0.646** | +0.133 | +0.171 | +2 | **−10** |
| `resource_leak` | +0.170 | 0 | +0.017 | 0 | −3 |
| `injection` | +0.167 | +0.048 | +0.056 | +1 | −1 |
| `integer` | +0.111 | +0.083 | +0.088 | +1 | −6 |
| `memory_lifetime` | −0.083 | +0.040 | +0.037 | +1 | +1 |
| `null_uninitialized` | 0 | 0 | 0 | 0 | 0 |

### What the model actually did

**Total findings are 157 in both runs.** Every candidate reached the report
exactly once either way — the invariant holds under a real corpus — so nothing
below comes from the model seeing more.

It moved findings in both directions. **18 cases lost a confirmed finding** and
**7 cases gained one** (`125-5`, `134-5`, `190-2`, `78-1`, `78-4`, `78-9`,
`787-6`). The rescues are candidates the deterministic promotion could not
classify — an unmapped analyzer rule produces no CWE and routes to
`out_of_scope_family` as review-required — which the model classified and
confirmed. That is why true positives rose while the confirmed count fell.

`out_of_bounds` is the clearest case and it went the way the pre-registered
prediction said it would: false positives 11 → 1, precision 0.154 → 0.800. The
noise there was `security.insecureAPI.strcpy`, a syntactic rule that fires
because the code calls `strcpy` rather than because a bound was shown missing.
Deciding whether a given call is bounded requires reading the surrounding code,
and that is what the model did.

`memory_lifetime` is the one regression: precision 1.000 → 0.917, one false
positive introduced, against one true positive gained. `unix.Malloc` is the
path-sensitive checker and was already perfect; there was nothing for the model
to win and one thing to lose.

### The caveat that was recorded in advance

The upper-bound caveat above predicted a trap: a model that correctly confirms
an unlabelled real defect would be scored as *losing* precision. False positives
fell by 19, so the trap did not spring in the direction that would have hidden a
gain. It does mean **+0.0613 is a lower bound on the improvement** — some of the
14 remaining false positives are likely unlabelled true positives of the kind
found in `CASTLE-78-10.c`.

### Reading it honestly

0.2903 is not a good score. It is a **27% relative improvement** on a corpus
this project did not write, with every hard gate passing and every one of 593
citations resolving, and it is the number that matters rather than the mini
suite's 0.6667. Recall is still the binding constraint: 82 of 110 truth entries
are unmatched, most because no candidate was ever generated for them.

## Repository pairs

**Not run.** No pairs are pinned. See
[benchmarks/pairs/README.md](../../benchmarks/pairs/README.md) for the procedure;
the harness records detection at the vulnerable revision, persistence at the
fixed revision as a false positive, and exclusions with reasons.

## Maintainability

**Not scored.** No labels exist. The set requires at least two independent
human labellers per case, adjudicated independently of `clang-tidy` output —
both enforced by the loader rather than by convention. See
[benchmarks/maintainability/README.md](../../benchmarks/maintainability/README.md).

The other half of this row closed on 2026-08-14: the finding→category
predictor is built. It maps a `memory_lifetime` weakness to
`ownership_ambiguity`, and otherwise reads the span of the verified citations —
two files is `coupling`, two regions in one file is `complexity`. It abstains
on everything else, `resource_leak` included.

That covers three of the five categories. `duplicated_validation` and
`error_handling` have no signal in the current schema, and are declared
unreachable rather than left to score 0.0 by accident: a label set containing
one of them makes `macro_f1` **`None` with a stated reason**, not a low number.
So when labels do arrive, a first score will either be a genuine macro-F1 over
the reachable categories or an explicit refusal naming the category that needs
a model-facing hazard field — never a depressed average that reads as the tool
performing badly.

## Ablations — retrieval

**Measured**, 2026-08-14. Policy versions: `matching v1`, `profile v1`,
`prompt v2`, `retrieval v1`. Command: `caudit ablate --suite mini`.

This is the half of the ablation that needs no model: expand every candidate
under each configuration and measure how much of the code that decides each
case ended up on the page, and what it cost.

| Configuration | Evidence coverage | Context tokens |
| --- | --- | --- |
| structural (baseline) | 0.6667 (4/6) | 317 |
| `flat_window` control, ±40 lines | 0.6667 (4/6) | 1076 |
| `token_budget=4000` | 0.6667 | 317 |
| `caller_depth=0` | 0.6667 | 317 |

**Structural retrieval retrieves the same share of the decisive code for 3.4x
fewer tokens.** That is the whole finding, and it is smaller than it looks:

- **The tie is an artefact of the corpus, not a result.** The mini cases are
  single files of a few dozen lines, so a ±40-line window is the whole file.
  A control that reads everything cannot fail to cover the ground truth. This
  comparison only starts discriminating on files long enough for a window to
  miss something, and the mini suite has none.
- **The missing third is the two `analyzer_blind_spot` cases**, which produce
  no candidate, so no context is expanded and their truth lines are covered by
  neither variant. 0.6667 here is the same 4-of-6 the baseline macro-F2 is
  made of, arrived at independently.
- **`token_budget` and `caller_depth` moved nothing**, correctly: the budget
  never binds at 317 tokens, and a corpus of single-function files has no
  callers to expand. Both rows are reported rather than dropped, because a
  factor that did not move is a result about this corpus.

**The detection half has not run.** Whether structural retrieval helps a model
*find* more is a different question from whether it puts more in front of one,
and answering it needs an API key. `caudit ablate` reports that question as
`not measured` rather than inferring it from the coverage column, and
`AblationSuite.structural_retrieval_earns_itself()` returns `None` for a grid
measured this way — comparing rows that all carry the analyzer-only score
would have produced a confident "no" from an experiment that could not have
shown otherwise.

So the honest summary is: on this corpus structural retrieval is **cheaper for
equal coverage**, and whether it is *better* is still open.

## Calibration

**Run, and nothing could be judged**, 2026-08-14. Command:
`caudit calibrate --suite mini`.

| Confidence | True | Of | Judged |
| --- | --- | --- | --- |
| high | 0 | 0 | no — fewer than 5 |
| medium | 4 | 4 | no — fewer than 5 |
| review_required | 0 | 0 | no — fewer than 5 |

The mini suite's four confirmed findings all carry `medium`, and no bin
reaches the five-finding floor below which a bin is reported and not judged. A
reliability curve over four findings would fire on noise, and a check that
fires on noise is one somebody switches off.

This is what the calibration bridge produces on the only corpus that exists
here. It becomes informative on CASTLE, on Juliet, or on a pair set — none of
which have been fetched or pinned.

## Overall score

**Refused.** The spec makes the 50% security / 50% maintainability average
valid only once every hard gate passes *and* both halves have been measured.
The maintainability half has not been measured at all, so there is no average
to report — and `gated_overall_score` will not compute one from a corpus that
is missing. The predictor built on 2026-08-14 moves nothing here: it supplies
the bridge from findings to categories, and the labels it would be scored
against still do not exist.

## Intended for the next policy version

Two changes are identified, evidenced, and **deliberately not made**, because
each bumps a policy version and `caudit compare` refuses two runs scored under
different ones. Making either today would invalidate every number above.
Recorded here so the reason for the delay survives, and so they land together
rather than one at a time — each costing another round of re-measurement.

**Drop `-Wextra` for an explicit diagnostic list.** *(bumps `profile` to v2)*
The profile passes `-Wall -Wextra` and then maps only the security-relevant
diagnostics, so `-Wunused-parameter` (24 hits on CASTLE),
`-Wunused-command-line-argument` (13, and not about the code at all) and
`-Wsign-compare` (4, all on safe cases) arrive with no CWE and land as
review-required. They cost a reader's attention without ever being reportable.
Naming the diagnostics the profile actually maps is a deterministic precision
win that needs no model.

**Admit `CWE-120`.** *(allowlist alone is free; the equivalence bumps
`matching` to v2)* `classify_cwe("CWE-120")` returns `out_of_scope` — not
prohibited, not discouraged, just absent. It is a Base-level entry and the
canonical mapping for an unbounded copy, and on `oob-write-stack-copy` the
model answered it for `strcpy(out->slot, name)` where the analyzers said
CWE-787. The gate refused it as `out_of_scope_family` and a true positive was
lost. Adding it to `ALLOWLIST` under `out_of_bounds` costs nothing; making it
*score* against a CWE-787 truth also needs it in
`DEFAULT_EQUIVALENCE["CWE-787"]`, which is the version bump.

The honest objection to the second is that adding a CWE because a model prefers
it fits the allowlist to the model rather than to the domain. What settles it is
that a reasonable analyst handed an unbounded `strcpy` would accept CWE-120 —
the equivalence map already exists for exactly that kind of pairing, and CWE-121
and CWE-122 are in it on the same grounds. CASTLE contains no CWE-120 cases, so
this changes nothing on the 110-case corpus either way; it affects the mini
suite and real scans.

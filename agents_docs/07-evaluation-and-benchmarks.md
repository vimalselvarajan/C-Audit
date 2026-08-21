# Evaluation and benchmarks

## Measurement principle

Evaluation lives in `src/caudit/eval/` and is intentionally stricter than “count the
findings.” It measures a fixed candidate source against labeled truth with a versioned
matching policy, preserves exclusions, separates confirmed from review-required items,
and refuses invalid comparisons.

Read the canonical [evaluation results](../my_docs/project/evaluation-results.md) and
[project gaps](../my_docs/project/project-gaps.md) before quoting any number. Those
documents distinguish measured facts from unrun work and record caveats by policy
version.

## Suites and candidate sources

`caudit eval` supports `mini`, `castle`, `juliet`, and `pairs` adapters. The default
is `mini`.

- `--recorded` (the default) replays committed analyzer recordings. It is offline and
  intended for CI/reproducible tests, not for publishing a new analyzer result.
- `--use-clang` runs the actual configured analyzer profile. Use it for a genuine
  measurement and require the appropriate toolchain.
- Only the mini suite carries committed recordings. The command refuses an unavailable
  recording rather than producing a misleading all-zero score.
- `--baseline` evaluates analyzer-only promotion. `--no-baseline` enables adjudication
  and requires a real consent/provider path (or an injected cassette in tests).

```bash
make eval       # offline mini analyzer-only replay
make eval-real  # mini suite against real Clang analyzers
```

Candidate generation bounds absolute recall: if the analyzers produce no candidate for
a defect, adjudication never sees it and cannot recover it. Within a fixed candidate
set, adjudication can classify candidates left review-required by deterministic
promotion, improving confirmed-finding recall and precision over that baseline. It must
still never delete a candidate or manufacture a missing one. Interpret model deltas
under both constraints.

## Metrics, matching, and gates

- `eval/matching.py` holds the matching policy. Treat a policy change as an experiment
  change; report the policy version and do not pool results across versions.
- Security scoring reports macro F2 alongside precision/recall, FP/KLOC, per-family
  metrics, and evidence validity. The gate conditions determine whether an overall
  claim is permitted.
- `eval/gates.py` checks fabrication/evidence and baseline requirements. A score is not
  a license to ignore a failed hard gate.
- `caudit compare` reads run reports and refuses comparisons with incompatible cases,
  matching/profile policies, or other incomparable inputs. A prompt version is compared
  only where both runs actually adjudicated.

## Repository pairs and maintainability

`caudit pairs` uses paired vulnerable/fixed revisions. A pair must have a pinned source,
both revisions, and a working build recipe. A build failure is an explicit exclusion,
not a dropped hard case. The committed pairs manifest can intentionally be empty until
such verification has happened; that command should refuse rather than invent data.

The maintainability data format lives under `benchmarks/maintainability/`. Labels must
come from distinct human labelers, disagreements need adjudication, and labels cannot
be sourced from an analyzer C Audit runs. The predictor may abstain; an uncoverable
category withholds macro-F1 rather than pretending that a schema limitation is a model
score.

## Ablation and calibration

`caudit ablate` varies retrieval/budget settings and always includes a `flat_window`
control. Without a model call it is a **retrieval-only** measurement: analyzer F2 cannot
change, so evidence coverage and token cost are the meaningful columns. Do not label a
retrieval-only tie as a detection result.

`caudit calibrate` matches report findings against ground truth and tests whether higher
confidence labels are actually more accurate. Bins below `--minimum-per-bin` are
reported but not judged. A miscalibrated result blocks the derived overall score rather
than being averaged away.

## Adding or changing benchmark data

1. Preserve provenance, source revision, build recipe, and ground-truth rationale.
2. Keep all exclusions with reasons; never silently narrow numerator or denominator.
3. Select candidate source explicitly (`recorded` versus real analyzer).
4. Record every policy version and configuration that can change results.
5. Add deterministic adapter/matching/metric tests before treating outputs as a
   measurement.
6. Append a new canonical results entry for an actual run; do not overwrite an older,
   different-policy record into a running aggregate.

# Part 04 — Evaluation harness and baselines

> **Milestone 0 gate.**

## Goal

Build measurement before building the thing being measured. The spec puts the evaluation harness at Milestone 0 for a reason: without a baseline from the analyzers alone, there is no way to show later that Gemini added value rather than noise, and no way to prove that a report contains no invented evidence.

This part produces numbers for **raw analyzers, no AI**, and implements the hard gates that can fail a run.

## Depends on / Unlocks

- **Depends on:** 02, 03.
- **Unlocks:** 13. Informs 07, 08, 11, 12.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/eval/case.py` | `BenchmarkCase`, `GroundTruth`, suite protocol |
| `src/caudit/eval/adapters/mini.py` | Adapter for the committed `benchmarks/mini/` suite |
| `src/caudit/eval/adapters/castle.py` | CASTLE adapter (fetched, cached, `slow`) |
| `src/caudit/eval/adapters/juliet.py` | Juliet subset adapter (pinned CWE directories) |
| `src/caudit/eval/matching.py` | Versioned detection-matching policy |
| `src/caudit/eval/metrics.py` | Precision, recall, F-beta, macro-F2, FP/KLOC, evidence validity |
| `src/caudit/eval/gates.py` | Hard gates from the spec; a failing gate fails the run |
| `src/caudit/eval/trace.py` | JSONL run traces for later ablations |
| `src/caudit/cli/eval.py` | `caudit eval --suite mini --baseline` |
| `benchmarks/mini/` | Six hand-written cases, one per in-scope weakness family |
| `tests/unit/test_eval_*.py`, `tests/adversarial/test_gates.py` | This part's tests |

## Interfaces

```python
class GroundTruth(BaseModel):
    path: PurePosixPath
    line: int
    cwe: CweId
    family: WeaknessFamily
    variant: Literal["vulnerable", "fixed"]     # Juliet good/bad twins, CVE pairs

class BenchmarkCase(BaseModel):
    case_id: str
    root: Path
    compile_commands: Path | None
    ground_truth: list[GroundTruth]
    lines_of_code: int

class MatchingPolicy(BaseModel):
    version: str                 # recorded in every metrics report
    line_tolerance: int          # default 3
    require_same_file: bool = True
    cwe_equivalence: Mapping[CweId, frozenset[CweId]]   # accepted alternates per truth entry

    def matches(self, truth: GroundTruth, finding: Finding) -> bool: ...

class Metrics(BaseModel):
    per_family: Mapping[WeaknessFamily, FamilyMetrics]   # tp, fp, fn, precision, recall, f2
    macro_f2: float
    fp_per_kloc: float
    evidence_validity_rate: float        # resolved citations / total citations
    citation_resolution_rate: float
    confirmed_count: int
    review_required_count: int           # reported separately, never summed

class GateResult(BaseModel):
    name: str
    passed: bool
    observed: float | int
    threshold: float | int
    detail: str

def evaluate_gates(metrics: Metrics, findings: Sequence[Finding],
                   resolutions: Sequence[Resolution]) -> list[GateResult]: ...
```

## The matching policy is the experiment

An undefined notion of "detected" makes every metric meaningless, and it is the easiest place to accidentally flatter the tool. The policy is therefore explicit, versioned, and recorded alongside results:

- A finding matches a ground-truth entry when the file is the same, the line is within `line_tolerance`, and the CWE is the truth CWE or one of its declared equivalents.
- Each truth entry may be matched **once**; surplus findings on the same defect are false positives, not free credit.
- Findings against `variant="fixed"` sources are false positives — this is what makes Juliet's good/bad twins and CVE pairs informative.
- Changing `line_tolerance` or the equivalence map requires a version bump, and results carrying different policy versions are not comparable. The harness refuses to compare them.

## Baseline runner

The baseline runs Clang diagnostics, the Static Analyzer, and the curated `clang-tidy` profile over each case and maps their output into `Candidate` objects (part 02) with no LLM involvement. Until part 07 exists, this uses a thin direct invocation that part 07 later replaces with the shared normalizer — the interface is the same, so the baseline numbers stay comparable.

Baseline numbers are the floor the spec requires before any overall score is reported.

## Acceptance criteria

- **AC-04-1** Metric functions match hand-computed values on fixtures, including the degenerate cases (no findings, no ground truth, all false positives) with no division-by-zero.
- **AC-04-2** Macro-F2 is averaged across families, unweighted by family size, and β=2 is verifiable from the formula (recall weighted above precision).
- **AC-04-3** The matching policy handles the boundary cases exactly: distance equal to tolerance matches, one beyond does not; a truth entry is consumed by at most one finding.
- **AC-04-4** A finding on a `fixed` variant counts as a false positive.
- **AC-04-5** Comparing two metric reports with different policy versions raises rather than producing a misleading delta.
- **AC-04-6** Injecting a fabricated finding (nonexistent file) into an otherwise clean run causes the zero-fabrication gate to fail and the run to exit non-zero.
- **AC-04-7** The citation-resolution gate fails when fewer than 95% of citations resolve.
- **AC-04-8** `confirmed_count` and `review_required_count` are reported as separate fields; no code path sums them, and a test asserts no aggregate field exists.
- **AC-04-9** The mini suite runs end to end with no network access and no CASTLE/Juliet download.
- **AC-04-10** Every run writes a JSONL trace with case id, candidate counts, timings, tool versions, and the policy version.
- **AC-04-11** Two runs over the same suite produce identical metrics.
- **AC-04-12** The candidate source is selectable from the command line, and which one ran is recorded. `--recorded` replays committed analyzer output and is the default so CI scores offline; `--use-clang` runs the real toolchain and is what any published number comes from.
- **AC-04-13** A suite the recorded source cannot replay is refused before scoring, naming the cases and the flag that fixes it. Scoring it would report zero findings for every case, which is indistinguishable from a corpus that came back clean.
- **AC-04-14** The CASTLE adapter reads the corpus as it actually ships: a flat source directory and one central `CASTLE-C250.json`. Labels, CWE, and decisive lines come from that manifest; source bytes come from the `.c` file on disk.
- **AC-04-15** CASTLE's non-vulnerable cases are kept, with no ground truth, so every finding against one scores as a false positive. Cases whose CWE is outside the allowlist are skipped with a per-CWE count, never dropped silently.
- **AC-04-16** Each CASTLE case is staged into a root of its own, and its compilation database is derived from the corpus's own `compile` line rather than from invented flags.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-04-01 | unit | tp=3, fp=1, fn=2 | precision 0.75, recall 0.6, F2 0.625 (hand-computed) | AC-04-1, AC-04-2 |
| T-04-02 | unit | Zero findings; zero ground truth; all-FP | Defined values, no `ZeroDivisionError`, documented convention for 0/0 | AC-04-1 |
| T-04-03 | unit | Two families with very different case counts | Macro-F2 equals the unweighted mean of family F2 | AC-04-2 |
| T-04-04 | unit | Truth at line 100, findings at 97 and 103 (tolerance 3) | Both match | AC-04-3 |
| T-04-05 | unit | Truth at line 100, finding at 104 | No match; counted as FP | AC-04-3 |
| T-04-06 | unit | Two findings on one truth entry | One TP, one FP | AC-04-3 |
| T-04-07 | unit | Correct line, wrong file | No match | AC-04-3 |
| T-04-08 | unit | Truth CWE-787, finding CWE-121 with declared equivalence | Match; without the equivalence, no match | AC-04-3 |
| T-04-09 | unit | Juliet-style good/bad twin; finding on the good twin | Counted as FP | AC-04-4 |
| T-04-10 | unit | Reports with policy versions `1` and `2` | Comparison raises with both versions named | AC-04-5 |
| T-04-11 | adversarial | Clean run plus one finding citing `src/ghost.c` | Zero-fabrication gate fails; exit code non-zero; gate detail names the file | AC-04-6 |
| T-04-12 | adversarial | Run where 94% of citations resolve | Resolution gate fails at the 95% threshold | AC-04-7 |
| T-04-13 | adversarial | Run at exactly 95% | Gate passes (boundary is inclusive and documented) | AC-04-7 |
| T-04-14 | unit | Metrics object | No attribute sums confirmed and review-required; both present | AC-04-8 |
| T-04-15 | unit | Report rendering of metrics | Counts appear under separate headings | AC-04-8 |
| T-04-16 | e2e | `benchmarks/mini/` (six cases) | `caudit eval --suite mini --baseline` completes offline and emits metrics for six families | AC-04-9 |
| T-04-17 | unit | Completed run | Trace JSONL parses; contains policy version, tool versions, per-case timings | AC-04-10 |
| T-04-18 | unit | Same suite run twice | Metrics byte-identical | AC-04-11 |
| T-04-19 | integration | CASTLE adapter, cached checkout (`slow`, `needs_clang`) | Parses ≥1 case per covered CWE; ground truth non-empty | AC-04-9 |
| T-04-20 | integration | Juliet subset adapter (`slow`) | Good/bad twin pairing detected for the pinned CWE directories | AC-04-4 |
| T-04-21 | unit | Stub suite, one case with a recording and one without | `missing_recordings` names the unrecorded case; `run_eval` raises before creating the output directory, naming both cases and `--use-clang` | AC-04-13 |
| T-04-22 | unit | `caudit eval` invoked with `--use-clang`, `--recorded`, and neither | The flag reaches `run_eval`; the default is `--recorded`; `default_source` returns a different class for each | AC-04-12 |
| T-04-23 | unit | Recorded case whose recording holds zero diagnostics | Scores normally and writes metrics — the guard must not turn a genuinely clean case into an error | AC-04-13 |
| T-04-24 | unit | Mini suite scored `--recorded` and `--use-clang` (`needs_clang`) | Identical macro-F2, FP/KLOC and both counts; a recording that replays a different ruleset fails here | AC-04-12 |
| T-04-25 | integration | CASTLE fixture in the real shape: flat sources plus a central manifest | CWE, decisive line and path read from the manifest; family resolved | AC-04-14 |
| T-04-26 | integration | Manifest record with `vulnerable: false` and empty `lines` | Case loads with no ground truth and keeps its family, so a finding against it is a false positive charged to that family | AC-04-15 |
| T-04-27 | integration | Manifest containing a CWE-89 record | Excluded from `case_ids`, counted in `skipped()`, and `load` raises | AC-04-15 |
| T-04-28 | integration | Every case in a multi-case fixture | Exactly one `.c` file under each `case.root` | AC-04-16 |
| T-04-29 | integration | `materialize_compile_commands` for a CASTLE case | Driver swapped to clang, `-c` present, link target gone, no invented flags | AC-04-16 |

## Milestone 0 exit checklist

Every item passed; the list is ticked as of 2026-08-14. It had been left
unticked long after the work was done, which made M0 read as open in the one
document a reader checks for that.

- [x] `Candidate` and `Finding` schemas exist, are exported, and are version-locked (part 02).
- [x] Exact location and evidence validation implemented and adversarially tested (part 03).
- [x] Mini suite committed; CASTLE and a Juliet subset wrapped behind adapters. *Both refuse to fetch implicitly. CASTLE was cloned and T-04-19 ran for the first time on 2026-08-15 — the adapter had to be rewritten first, because it read a format CASTLE does not have. Juliet is still not downloaded, so T-04-20 has never run.*
- [x] Baseline analyzer metrics recorded for the mini suite, with no LLM in the pipeline — macro-F2 **0.6667**, 12/12 citations resolved, zero fabrications.
- [x] Hard gates implemented, with tests proving each one can fail (T-04-11, T-04-12, T-04-13).
- [x] Matching policy version 1 documented and recorded in the trace.

## Out of scope and risks

- No AI-assisted findings are scored here — that comparison is part 12.
- Maintainability scoring needs an independently labeled set and lands in part 13.
- **Risk:** synthetic suites overstate performance; the spec says so directly. Mitigation: real-repository pairs in part 13, and CASTLE/Juliet results always reported alongside, never instead.
- **Risk:** the mini suite is written by the same person building the detector, so it can encode the tool's blind spots. Mitigation: include at least two cases the baseline analyzers are known to miss, so a suite where everything passes is visibly suspicious.

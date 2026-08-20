# Part 07 — Candidate generation

## Goal

Run the deterministic analyzers and turn their heterogeneous output into one `Candidate` stream: Clang compile diagnostics, the Clang Static Analyzer, and a curated `clang-tidy` profile. Merge duplicates without losing any producer, because provenance is what lets a reader tell "three analyzers agree" from "one noisy check fired".

The spec's position is that analyzers generate candidates, not verdicts. Nothing in this part decides whether something is a real vulnerability.

## Depends on / Unlocks

- **Depends on:** 02, 05, 06.
- **Unlocks:** 08.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/analyzers/runner.py` | Parallel subprocess execution, timeouts, output capture |
| `src/caudit/analyzers/csa.py` | Clang Static Analyzer invocation and SARIF parsing |
| `src/caudit/analyzers/tidy.py` | `clang-tidy` invocation and YAML fixes parsing |
| `src/caudit/analyzers/diagnostics.py` | Compile diagnostics parsing |
| `src/caudit/analyzers/normalize.py` | Analyzer output → `Candidate` |
| `src/caudit/analyzers/dedup.py` | Fingerprint-based merge, provenance union |
| `config/profiles/security.yaml` | The curated check profile, versioned |
| `tests/integration/test_analyzers_*.py`, `tests/unit/test_normalize_*.py` | This part's tests |

## Interfaces

```python
class AnalyzerRun(BaseModel):
    analyzer: Producer
    tool_version: str
    profile_version: str | None
    unit: PurePosixPath
    exit_code: int
    duration_s: float
    raw_output_path: Path        # retained for provenance, not for the prompt

class AnalyzerResult(BaseModel):
    runs: list[AnalyzerRun]
    candidates: list[Candidate]
    limitations: list[Limitation]

class Analyzer(Protocol):
    name: Producer
    def run(self, unit: TranslationUnit, timeout_s: float) -> AnalyzerRun: ...
    def parse(self, run: AnalyzerRun) -> list[Candidate]: ...

def generate_candidates(plan: ScanPlan, index: Index, config: Config) -> AnalyzerResult: ...

def merge_candidates(candidates: Sequence[Candidate]) -> list[Candidate]:
    """Groups by dedup_fingerprint. Provenance is unioned; never truncated."""
```

## The curated profile

The profile is committed configuration with its own version string, recorded in the manifest so a report names the ruleset that produced it:

- **Clang Static Analyzer:** `core.*`, `unix.Malloc`, `alpha.security.ArrayBound*`, `alpha.core.*` selected individually — path-sensitive checks that map onto the in-scope weakness families.
- **clang-tidy:** `bugprone-*`, `cert-*`, `clang-analyzer-*`, plus a narrow `readability-*`/`misc-*` slice chosen for the spec's *security-relevant maintainability* signals (function complexity, duplicated validation, unclear ownership).
- **Compile diagnostics:** `-Wall -Wextra` plus the security-relevant subset (`-Wformat-security`, `-Warray-bounds`, `-Wconversion`, `-Wshadow`) — added as analysis flags, never written back into the build.

Every check in the profile is annotated with the weakness family it feeds, so part 04's per-family metrics can attribute a detection to a rule. A check with no family annotation fails profile validation.

## Normalization

Each analyzer's native output becomes a `Candidate`:

| Analyzer | Source format | Notes |
| --- | --- | --- |
| CSA | SARIF via `clang --analyze -Xclang -analyzer-output=sarif` | `codeFlows` become ordered `control_flow_step` evidence, preserving the path |
| clang-tidy | YAML from `--export-fixes` | Notes attach to the primary diagnostic; suggested fixes are recorded, never applied |
| Diagnostics | `-fdiagnostics-format=json` | Severity mapped; notes attached to their parent |

Normalization always: makes paths repository-relative, converts locations into hashed `SourceRegion`s via part 03, attaches `Provenance` with the tool version and rule id, and maps the rule to a CWE through the profile annotation (unmapped rules keep `suggested_cwe=[]` rather than guessing).

## Invariants

- **Dedup never drops a producer.** Merging two candidates unions their `Provenance` lists. A test asserts the post-merge provenance count equals the pre-merge total.
- **The analyzer's own text is preserved verbatim** alongside the normalized form. Paraphrasing analyzer output at intake would make provenance unverifiable later.
- **Analyzer versions are captured per run**, not per session — a repository can hit different toolchains in exotic setups, and the manifest must reflect what actually ran.
- **A crashed or timed-out analyzer is a recorded `Limitation`,** never an empty result treated as "clean". This is the difference between "we found nothing" and "we did not look".
- **No candidate is discarded for being unmapped.** An unmapped rule produces a candidate with no CWE and is routed to review, per part 02's `out_of_scope_family` reason.

## Acceptance criteria

- **AC-07-1** Each in-scope weakness family has at least one mini-suite fixture that yields ≥1 candidate.
- **AC-07-2** CSA SARIF output is parsed into candidates with ordered control-flow evidence preserved.
- **AC-07-3** clang-tidy YAML output is parsed, including notes attached to their parent diagnostic.
- **AC-07-4** Compile diagnostics are parsed and mapped to severities.
- **AC-07-5** Two analyzers reporting the same defect merge into one candidate carrying two provenance entries.
- **AC-07-6** Provenance count is conserved across a merge of any input set.
- **AC-07-7** An analyzer timeout, crash, or non-zero exit yields a `Limitation` naming analyzer and TU; other TUs continue.
- **AC-07-8** An unknown or newly added rule id does not crash normalization; the candidate is produced with no CWE mapping.
- **AC-07-9** Every candidate's region hash resolves through part 03.
- **AC-07-10** Profile validation rejects a check with no weakness-family annotation.
- **AC-07-11** Candidate order is deterministic across runs and independent of TU completion order.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-07-01 | integration | `benchmarks/mini/oob_write/` | ≥1 candidate; region on the offending line ±tolerance | AC-07-1 |
| T-07-02 | integration | `mini/use_after_free/` | ≥1 candidate with CSA provenance | AC-07-1, AC-07-2 |
| T-07-03 | integration | `mini/null_deref/` | ≥1 candidate | AC-07-1 |
| T-07-04 | integration | `mini/int_overflow/` | ≥1 candidate | AC-07-1 |
| T-07-05 | integration | `mini/resource_leak/` | ≥1 candidate | AC-07-1 |
| T-07-06 | integration | `mini/format_string/` | ≥1 candidate | AC-07-1 |
| T-07-07 | unit | Recorded CSA SARIF with a 4-step `codeFlow` | Four ordered `control_flow_step` evidence items, order preserved | AC-07-2 |
| T-07-08 | unit | Recorded tidy YAML with a diagnostic plus two notes | One candidate; notes attached, not separate candidates | AC-07-3 |
| T-07-09 | unit | Recorded tidy YAML with a suggested fix | Fix recorded in provenance detail; no file modified (asserted) | AC-07-3 |
| T-07-10 | unit | Recorded JSON diagnostics with warning and error | Both parsed with correct severity | AC-07-4 |
| T-07-11 | unit | CSA and tidy candidates for the same defect | One merged candidate, two provenance entries, both rule ids retained | AC-07-5 |
| T-07-12 | unit | Random candidate sets (hypothesis) | Post-merge provenance total equals pre-merge total | AC-07-6 |
| T-07-13 | unit | Candidates differing only by line within tolerance | Merged; canonical region chosen deterministically | AC-07-5 |
| T-07-14 | unit | Candidates in different functions with identical messages | Not merged | AC-07-5 |
| T-07-15 | integration | Analyzer stub that sleeps past the timeout | `Limitation` recorded; remaining TUs complete | AC-07-7 |
| T-07-16 | integration | Analyzer stub exiting 134 with no output | `Limitation` recorded; not treated as a clean TU | AC-07-7 |
| T-07-17 | unit | Output containing rule id `bugprone-future-check-2030` | Candidate produced, `suggested_cwe=[]`, no exception | AC-07-8 |
| T-07-18 | unit | Every candidate from a mini-suite run | All region hashes resolve `OK` through part 03 | AC-07-9 |
| T-07-19 | unit | Profile entry missing its family annotation | Validation error naming the check | AC-07-10 |
| T-07-20 | unit | Same inputs, TU completion order shuffled | Candidate list identical | AC-07-11 |
| T-07-21 | integration | Full mini suite, twice (`needs_clang`) | Identical candidate sets; analyzer versions recorded per run | AC-07-11 |

## Out of scope and risks

- No adjudication, ranking, or reporting — parts 10, 12, 08.
- No fix application, ever, in the MVP. Suggested fixes are recorded as text.
- **Risk:** analyzer-bias — scoring the tool against candidates it generated. Mitigation, per the spec: the mini suite includes cases the analyzers are known to miss, and part 13's maintainability labels are adjudicated independently of `clang-tidy` output.
- **Risk:** `alpha.*` CSA checks are experimental and noisy. Mitigation: they are enabled individually, annotated in the profile, and their contribution to false positives is tracked per rule in part 04's metrics so the profile can be tuned with data.

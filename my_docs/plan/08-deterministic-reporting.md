# Part 08 — Deterministic reporting

> **Milestone 1 gate.**

## Goal

Emit the three artifacts the spec names — `report.md`, `results.sarif`, `run-manifest.json` — from analyzer output alone. When this part is done, C Audit is a useful tool with no AI in it: a build-aware Clang scanner with reproducible, evidence-hashed reports.

Shipping this before the LLM layer is deliberate. It is the baseline every later claim is measured against, and it means a user who declines cloud adjudication still gets something.

## Depends on / Unlocks

- **Depends on:** 02, 05, 07.
- **Unlocks:** 12. Consumed by 04 for baseline scoring.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/report/sarif.py` | SARIF 2.1.0 writer |
| `src/caudit/report/markdown.py` | Human-readable report renderer |
| `src/caudit/report/manifest.py` | `run-manifest.json` assembly |
| `src/caudit/report/sections.py` | Section model: confirmed, needs review, coverage, limitations |
| `schemas/sarif-2.1.0.schema.json` | Vendored official schema, used in tests |
| `tests/contract/test_sarif_*.py`, `tests/golden/report/`, `tests/e2e/test_scan_baseline.py` | This part's tests |

## Interfaces

```python
class ReportSections(BaseModel):
    confirmed: list[Finding]           # at M1: analyzer findings meeting the evidence gate
    needs_review: list[Finding]        # separate list, separate count, always rendered
    coverage: Coverage
    limitations: list[Limitation]
    excluded: list[tuple[PurePosixPath, ExclusionReason]]

class RunManifest(BaseModel):
    schema_version: str
    caudit_version: str
    started_at: datetime               # the only place timestamps live
    repo_root_name: str
    revision: str
    dirty: bool
    config_hash: str
    policy_versions: PolicyVersions    # prompt, retrieval, matching, profile
    analyzer_versions: Mapping[str, str]
    model_ids: Mapping[str, str | None]     # null at M1
    coverage: Coverage
    finding_hashes: Mapping[str, str]       # finding_id → source-region hash digest
    counts: ReportCounts                    # confirmed and needs_review, separate fields

def write_report(sections: ReportSections, manifest: RunManifest, out_dir: Path) -> None: ...
```

## SARIF mapping

Targeting [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), validated in tests against the vendored official schema:

| C Audit concept | SARIF |
| --- | --- |
| Tool and version | `runs[].tool.driver.name` / `.version` |
| Rule (analyzer check or CWE family) | `tool.driver.rules[]` with `id`, `shortDescription`, `help` |
| CWE | `rules[].properties.tags` (`"CWE-787"`) and `relationships` to the CWE taxonomy |
| Finding | `runs[].results[]` |
| Location | `results[].locations[].physicalLocation` with `region` line and byte offsets |
| Evidence path | `results[].codeFlows[].threadFlows[].locations[]`, ordered |
| Dedup fingerprint | `results[].partialFingerprints.caudit/v1` |
| Confidence | `results[].properties.confidence` and `.confidenceReason` |
| Needs review | `results[].kind = "review"` with `level = "none"`; confirmed use `kind = "fail"` |
| Coverage gaps, excluded targets | `runs[].invocations[].toolExecutionNotifications` |
| Analyzer provenance | `results[].provenance` plus `properties.producers` |

Using `kind` to separate review-required results means a consuming code-scanning system does not silently count them as vulnerabilities — the spec's requirement survives the export, not just the Markdown.

## Determinism

Two runs over identical inputs must produce byte-identical `report.md` and `results.sarif`:

- Findings sort by `(severity, cwe, path, start_line, finding_id)` — total order, no ties.
- Timestamps, durations, and absolute paths appear **only** in `run-manifest.json`. The other two artifacts are diffable across runs and machines.
- The repository root is rendered by name, never as an absolute path.
- Mappings serialize with sorted keys; floats use fixed precision.
- Manifest fields that legitimately vary (`started_at`, timings) are excluded from the reproducibility comparison by an explicit allowlist, so "reproducible" is a checked property rather than a claim.

## Invariants

- **Confirmed and needs-review never merge.** Separate sections, separate counts, separate SARIF `kind`. No summary line in any artifact adds them together — asserted by test, not by convention.
- **Every rendered finding cites resolvable evidence.** Rendering runs the citation resolver first; anything unresolved moves to needs-review with its reason. A report cannot contain an unverified confirmed finding by construction.
- **Coverage is always rendered,** including when it is complete. A reader must never have to infer whether something was skipped.
- **The manifest is complete or the run fails.** A missing analyzer version, policy version, or revision is an error, not a null — reproducibility is the point of the file.

## Acceptance criteria

- **AC-08-1** `results.sarif` validates against the vendored SARIF 2.1.0 schema for empty, single-finding, and multi-finding runs.
- **AC-08-2** Confirmed findings serialize with `kind="fail"`; needs-review with `kind="review"`, `level="none"`.
- **AC-08-3** CWE appears both as a tag and as a taxonomy relationship on every rule that has one.
- **AC-08-4** Control-flow evidence renders as an ordered `codeFlow` preserving step order.
- **AC-08-5** `report.md` renders confirmed and needs-review under separate headings with separate counts, and no artifact contains their sum.
- **AC-08-6** Coverage and excluded-target lists appear in both Markdown and SARIF notifications.
- **AC-08-7** Two runs over identical inputs produce byte-identical `report.md` and `results.sarif`.
- **AC-08-8** The manifest contains every required key; a missing analyzer version fails the run.
- **AC-08-9** `finding_hashes` covers every rendered finding and matches the hashes recorded at candidate time.
- **AC-08-10** An empty run renders a valid, non-confusing report ("no findings", coverage still shown).
- **AC-08-11** No absolute filesystem path appears in `report.md` or `results.sarif`.
- **AC-08-12** A finding whose citation fails to resolve is rendered in needs-review with its resolution reason, never in confirmed.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-08-01 | contract | Empty, 1-finding, 12-finding runs | All validate against the SARIF 2.1.0 schema | AC-08-1 |
| T-08-02 | contract | Mixed confirmed and needs-review | `kind` values as specified; counts match the sections | AC-08-2 |
| T-08-03 | contract | Finding with CWE-787 | Tag and taxonomy relationship both present | AC-08-3 |
| T-08-04 | contract | CSA candidate with a 4-step flow | `codeFlow` has 4 locations in order | AC-08-4 |
| T-08-05 | golden | Fixed 6-finding fixture | `report.md` matches the committed snapshot | AC-08-5 |
| T-08-06 | unit | Report with 3 confirmed, 2 needs-review | Both counts present; grep for "5" as a total finds nothing | AC-08-5 |
| T-08-07 | unit | Run with 4 excluded targets and coverage 0.82 | Both appear in Markdown and in SARIF notifications | AC-08-6 |
| T-08-08 | unit | Same inputs, two runs | `report.md` and `results.sarif` byte-identical | AC-08-7 |
| T-08-09 | unit | Same inputs run from two different working directories | Outputs still identical | AC-08-7, AC-08-11 |
| T-08-10 | unit | Findings generated in shuffled order | Sorted output identical | AC-08-7 |
| T-08-11 | unit | Manifest with `analyzer_versions` missing an entry | Run fails with a message naming the missing analyzer | AC-08-8 |
| T-08-12 | unit | Completed run | Every manifest key present and non-null except `model_ids` (null at M1) | AC-08-8 |
| T-08-13 | unit | 6-finding run | `finding_hashes` has 6 entries matching candidate-time hashes | AC-08-9 |
| T-08-14 | unit | Run with zero findings | Report renders, states no findings, still shows coverage | AC-08-10 |
| T-08-15 | unit | Report text and SARIF body | No string matching `^/` or `[A-Za-z]:\\` outside the manifest | AC-08-11 |
| T-08-16 | adversarial | Finding citing a file deleted after analysis | Rendered in needs-review with `HASH_MISMATCH`/`MISSING_FILE`; absent from confirmed | AC-08-12 |
| T-08-17 | e2e | Fixture repo with a real compile DB (`needs_clang`) | `caudit scan` writes all three artifacts; exit code 1 with findings, 0 without | AC-08-1, AC-08-7 |
| T-08-18 | unit | Manifest reproducibility comparison across two runs | Differences confined to the timestamp/timing allowlist | AC-08-7 |

## Milestone 1 exit checklist

Checked 2026-08-12, on a development machine with **no Clang or clang-tidy installed**.

- [x] `compile_commands.json` loaded and validated; incomplete databases stop the run (part 05).
- [x] Symbols and source-region hashes indexed (part 06).
- [x] Curated Clang toolchain runs; candidates normalized and deduplicated with provenance intact (part 07). *Implemented and tested against committed recordings; the `needs_clang` confirmations (T-07-21, T-08-17) have not been executed on this machine.*
- [x] Baseline Markdown, SARIF 2.1.0, and `run-manifest.json` emitted and byte-reproducible. SARIF validates against the vendored official schema for empty, single- and multi-finding runs.
- [x] Baseline metrics recorded on the mini suite through part 04, establishing the floor for M2: macro-F2 **0.6667**, 12/12 citations resolved, zero fabrications, counts kept separate.
- [x] `caudit scan` is usable by someone who never configures a Gemini key — no code path in parts 01–08 reads one.

## Implementation notes (added 2026-08-12)

Where the built code departs from the sketch above, and why.

| Decision | Reason |
| --- | --- |
| `RunManifest` is part 02's model, not a second type. The sketch's names map onto it (`repo_root_name`→`repository_root`, `dirty`→`revision_dirty`, `analyzer_versions`→`tools`, `finding_hashes`→`cited_region_hashes`, `counts`→`coverage.confirmed_count`/`.review_required_count`); the table is in `report/manifest.py`. | One manifest type, one committed schema, one drift check. |
| `config_hash` added to `RunManifest`; `SCHEMA_VERSION` → 1.3.0. | Named in the interface above, and it is what makes "same inputs" checkable without diffing the whole config snapshot. |
| `ReviewReason.EVIDENCE_UNAVAILABLE` added. | Makes the `ResolutionStatus`→`ReviewReason` map total. An excluded or oversized file is not a deleted one, and telling a reader `missing_file` would send them looking for a deletion that never happened. |
| `ReportSections` also carries `unresolved` (finding id → resolver verdict) and `notes` (run-level statements). | `ReviewReason` is deliberately coarser than `ResolutionStatus`; without `unresolved` the precise reason AC-08-12 asks for is lost between the gate and the page. `notes` carries "no analyzer ran", which is not a blind spot in any one place. |
| SARIF rule id is the **analyzer check**, with the CWE as a tag and a taxonomy relationship. | The mapping table permits either. A consumer suppresses, tunes and files bugs against the check; CWE is still fully expressed, and one rule can legitimately carry several. |
| `results[].provenance` is omitted; analyzer provenance goes in `properties.producers`. | Every field the SARIF `resultProvenance` object defines is a timestamp or a conversion source, and a timestamp in `results.sarif` breaks AC-08-7. |
| `originalUriBaseIds["%SRCROOT%"]` is declared with a *description* and no `uri`. | Defining the uri would put the absolute repository path in the artifact, which AC-08-11 forbids. |
| Absolute paths are stripped from both portable artifacts at the rendering boundary (`path_redactor`). | Found by T-08-15: part 05's `revision_unavailable` limitation names the tree absolutely, correctly, for a terminal message. AC-08-11 is a property of the artifact, so it is enforced where the artifact is produced rather than by asking every upstream part to sanitize its strings. |
| `caudit scan` exits **3** when no analyzer ran, even though all three artifacts are written. | `0` is reserved for a run that looked and found nothing. A CI step reads `$?`, not the limitations section. |
| `promote_candidate` moved from `eval/baseline.py` to `report/promote.py`; `eval` re-exports it. | `caudit scan` at M1 and `caudit eval --baseline` must describe the same thing, or the baseline the M2 numbers are compared against is measuring a different tool. The dependency direction (04 consumes 08) is the one the plan already specifies. |
| `write_report` returns a `ReportArtifacts` record rather than `None`. | `caudit scan`'s exit code depends on the confirmed count; returning it means the CLI does not read its own output back to find out what it just wrote. |
| T-08-06's "grep for 5 finds nothing" is implemented as "no total-shaped phrase and no `total` anywhere". | A bare `5` occurs in line numbers and hashes; the assertion has to be about a *sum being stated*, which is what the criterion means. |

## Out of scope and risks

- No ranking beyond the deterministic sort (part 12), no AI provenance fields populated (part 10).
- **Risk:** the SARIF `kind="review"` convention may still be surfaced as a vulnerability by some consumers. Mitigation: `level="none"` as well, an explicit note in the run notifications, and the distinction documented in `report.md` so the human artifact is unambiguous regardless.
- **Risk:** golden Markdown snapshots are brittle and get updated reflexively. Mitigation: the golden fixture is small and its update requires a matching change in the counts assertions of T-08-06, so a blind re-record breaks a second test.

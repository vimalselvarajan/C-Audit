# Part 11 — Verification gate

> **Milestone 2 gate.**

## Goal

Decide, deterministically and without consulting any model, whether an adjudication becomes a confirmed finding. This is the component that makes the product claim true: *use AI to connect and explain evidence, not to invent it.*

The gate implements the spec's four clauses — every citation resolves, the evidence supports the stated weakness, the impact does not exceed what the evidence proves, and unresolved assumptions are stated — and routes everything else to **Needs review** without ever merging the two counts.

## Depends on / Unlocks

- **Depends on:** 03, 06, 10.
- **Unlocks:** 12.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/verify/gate.py` | The gate: adjudication + context → `Finding` or review |
| `src/caudit/verify/citations.py` | Citation extraction and bulk resolution |
| `src/caudit/verify/claims.py` | Impact-versus-evidence rules |
| `src/caudit/verify/cwe_check.py` | CWE allowlist, prohibited mappings, family agreement |
| `src/caudit/verify/reasons.py` | `ReviewReason` enum and formatting |
| `tests/adversarial/test_gate_*.py`, `tests/unit/test_verify_*.py` | This part's tests |

## Interfaces

```python
class GateOutcome(BaseModel):
    accepted: bool
    finding: Finding | None
    review_item: ReviewItem | None       # never None when accepted is False
    reasons: list[ReviewReason]          # all failures, not just the first
    resolutions: list[Resolution]        # full audit trail

class ReviewReason(StrEnum):
    CITATION_UNRESOLVED = "citation_unresolved"
    HASH_MISMATCH = "hash_mismatch"
    SYMBOL_UNRESOLVED = "symbol_unresolved"
    CALL_EDGE_UNRESOLVED = "call_edge_unresolved"
    EVIDENCE_DOES_NOT_SUPPORT_CWE = "evidence_does_not_support_cwe"
    IMPACT_EXCEEDS_EVIDENCE = "impact_exceeds_evidence"
    ASSUMPTIONS_UNSTATED = "assumptions_unstated"
    CWE_NOT_ALLOWED = "cwe_not_allowed"
    OUT_OF_SCOPE_FAMILY = "out_of_scope_family"
    SCHEMA_INVALID_RESPONSE = "schema_invalid_response"
    CONTEXT_BUDGET_EXCEEDED = "context_budget_exceeded"
    PROVIDER_UNAVAILABLE = "provider_unavailable"

def verify(adjudication: Adjudication, context: EvidenceContext,
           index: Index, store: SourceStore) -> GateOutcome: ...
```

## The four checks

**1. Every citation resolves.** Each `cited_evidence_id` must exist in the bundle; each resolved region's hash must still match; each named symbol must exist at its cited location per the index (resolver v2); each asserted call edge must exist in the call graph. Any failure → the corresponding reason.

**2. The evidence supports the stated weakness.** The claimed CWE's family must be consistent with the kinds of evidence present — a use-after-free claim needs an allocation or free site among its evidence, an out-of-bounds write needs the write and something bounding it. These are structural preconditions per family, encoded as data in `cwe_check.py`, not a judgement about whether the bug is real.

**3. The impact does not exceed the evidence.** `reachability="demonstrated"` requires control-flow evidence connecting an entry point to the site. `exploitability` above `unlikely` requires evidence of attacker-influenced input reaching the site. When the claim outruns the evidence the finding is **downgraded** — the weaker claim is kept with a recorded reason, rather than discarding a possibly real bug.

**4. Assumptions are stated.** `unresolved_assumptions` must be present. If the context recorded dropped units (part 09) or the index recorded blind spots touching this code (part 06) and the model asserted no assumptions, that contradiction is itself a reason (`ASSUMPTIONS_UNSTATED`).

## Invariants

- **The gate is deterministic and model-free.** No LLM call happens inside verification. A gate that could ask a model whether its own output was trustworthy would be circular.
- **Failures accumulate.** All applicable reasons are reported, not just the first — a review item saying only "hash mismatch" when the CWE was also wrong wastes the reviewer's time.
- **Nothing is discarded.** A failed adjudication becomes a `ReviewItem` with its reasons and evidence trail. The spec's needs-review section is a queue, not a bin.
- **Confirmed and review-required are separate everywhere.** No aggregate count exists in this part's output types.
- **Downgrade before rejection.** When only the strength of a claim is unsupported, keep the finding and weaken the claim. The spec's hard gate is on fabricated evidence, not on cautious findings.
- **`confidence` is computed here**, from the resolution results, never copied from the model's self-report.

## Acceptance criteria

- **AC-11-1** A fabricated file path in a citation yields `CITATION_UNRESOLVED` and is never confirmed.
- **AC-11-2** A fabricated function name yields `SYMBOL_UNRESOLVED`.
- **AC-11-3** A fabricated line number inside a real file yields `CITATION_UNRESOLVED` or `SYMBOL_UNRESOLVED`, never `OK`.
- **AC-11-4** A fabricated analyzer name in provenance is rejected against the set of analyzers that actually ran.
- **AC-11-5** A quoted snippet that does not match the cited region's bytes yields `HASH_MISMATCH`.
- **AC-11-6** An asserted call edge absent from the index yields `CALL_EDGE_UNRESOLVED`.
- **AC-11-7** A CWE whose family preconditions are unmet yields `EVIDENCE_DOES_NOT_SUPPORT_CWE`.
- **AC-11-8** `reachability="demonstrated"` without control-flow evidence is downgraded with `IMPACT_EXCEEDS_EVIDENCE`; the finding survives at the lower claim.
- **AC-11-9** `exploitability="plausible"` with no attacker-input evidence is downgraded.
- **AC-11-10** Absent or contradicted `unresolved_assumptions` yields `ASSUMPTIONS_UNSTATED`.
- **AC-11-11** A fully valid adjudication is confirmed with `confidence` computed from resolutions, not from the model's self-report.
- **AC-11-12** All applicable reasons are reported for a multi-fault adjudication.
- **AC-11-13** No input can produce a confirmed finding with an unresolved citation — property-tested over generated adjudications.
- **AC-11-14** The gate's output types contain no field summing confirmed and review counts.
- **AC-11-15** Verification is deterministic and performs no network I/O.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-11-01 | adversarial | Citation to `src/ghost.c` | `CITATION_UNRESOLVED`; `accepted=False` | AC-11-1 |
| T-11-02 | adversarial | Citation naming `validate_input()` which does not exist | `SYMBOL_UNRESOLVED` | AC-11-2 |
| T-11-03 | adversarial | Real file, line 9999 | Not accepted; reason recorded | AC-11-3 |
| T-11-04 | adversarial | Real file, real symbol, wrong line (off by 40) | `SYMBOL_UNRESOLVED` | AC-11-3 |
| T-11-05 | adversarial | Provenance claiming `infer` (never ran) | Rejected against the actual analyzer set | AC-11-4 |
| T-11-06 | adversarial | Quoted snippet with an added `!` versus the real region | `HASH_MISMATCH`; detail shows both hashes | AC-11-5 |
| T-11-07 | adversarial | Snippet differing only in whitespace | `HASH_MISMATCH` (exact bytes, by design) | AC-11-5 |
| T-11-08 | adversarial | Claimed edge `parse() → free_buf()` absent from the graph | `CALL_EDGE_UNRESOLVED` | AC-11-6 |
| T-11-09 | adversarial | CWE-416 (UAF) with no free site in evidence | `EVIDENCE_DOES_NOT_SUPPORT_CWE` | AC-11-7 |
| T-11-10 | adversarial | CWE-787 with no write in evidence | `EVIDENCE_DOES_NOT_SUPPORT_CWE` | AC-11-7 |
| T-11-11 | adversarial | `reachability="demonstrated"`, no control-flow evidence | Downgraded to `argued`/`unknown`; finding retained; reason recorded | AC-11-8 |
| T-11-12 | adversarial | `exploitability="demonstrated"` with only a local static buffer | Downgraded; reason recorded | AC-11-9 |
| T-11-13 | unit | Valid adjudication with a genuine control-flow path | `reachability="demonstrated"` preserved | AC-11-8 |
| T-11-14 | adversarial | `unresolved_assumptions: []` while the context dropped 3 units | `ASSUMPTIONS_UNSTATED` | AC-11-10 |
| T-11-15 | adversarial | Empty assumptions while the index recorded an indirect call in the path | `ASSUMPTIONS_UNSTATED` | AC-11-10 |
| T-11-16 | unit | Fully valid adjudication, all citations resolve | Confirmed; `confidence` derived from resolutions | AC-11-11 |
| T-11-17 | unit | Model self-reports `high`, two citations fail | Result is review-required; self-report ignored | AC-11-11 |
| T-11-18 | adversarial | Adjudication with a bad hash, a bad CWE, and no assumptions | All three reasons present | AC-11-12 |
| T-11-19 | unit | Hypothesis: generated adjudications with random citation validity | No confirmed finding ever has an unresolved citation | AC-11-13 |
| T-11-20 | unit | `GateOutcome` and `ReviewItem` types | No field sums the two counts | AC-11-14 |
| T-11-21 | unit | Full gate run with sockets monkeypatched to raise | Completes; zero network attempts; identical results across runs | AC-11-15 |
| T-11-22 | unit | Same adjudication verified 50 times, shuffled evidence order | Identical outcome and reason ordering | AC-11-15 |
| T-11-23 | unit | Out-of-scope CWE family | `OUT_OF_SCOPE_FAMILY`; item retained in review, not dropped | AC-11-14 |

## Milestone 2 exit checklist

- [x] Symbol-level and dependency retrieval feeding adjudication (part 09).
- [x] Structured Gemini output with tiered models, consent, and caching (part 10).
- [x] Confirmed / rejected / review-required implemented, with every state reachable and tested.
- [x] Every citation in every confirmed finding resolves against the scanned revision.
- [ ] Recall, precision, evidence accuracy, cost, and latency measured against the M1 baseline through part 04, with the comparison recorded.
- [ ] Hard gates pass on the evaluation set: ≥95% citation resolution, zero fabrications, counts kept separate.

The last two are **part 12's**, and marking them here would be reporting a
measurement nobody took. Measuring an adjudicated run against the M1 baseline
requires the pipeline to be assembled — retrieval, adjudication and the gate
wired into `caudit scan` and `caudit eval` — which is exactly what part 12
does. The three parts of M2 are built and tested; the milestone's own numbers
are produced one part later.

## Implementation notes (added 2026-08-13)

Part 11 is built. Every acceptance criterion holds and every test in the table
above exists. Where the implementation departs from the sketch, it is recorded
here rather than left for a reader to discover by diffing.

| # | Deviation | Why |
| --- | --- | --- |
| 1 | `ReviewReason` was **not** redeclared here. Part 02's enum gained `call_edge_unresolved`, `evidence_does_not_support_cwe`, `model_rejected` and `model_inconclusive`, all blocking | The enum is on the finding contract and is exported as JSON Schema. A second copy in `verify/reasons.py` would be a second thing to keep in step, and part 08 already branches on the part 02 one. `reasons.py` owns everything *around* the enum instead: the resolver mapping, the wording, the report order. |
| 2 | The plan's `CWE_NOT_ALLOWED` is the existing `CWE_MAPPING_REJECTED`; `OUT_OF_SCOPE_FAMILY` covers the other half | Two names for one condition is how a router develops a bug that only one of its callers has. Part 02 already distinguished *prohibited mapping* from *out of family*, and T-11-23 asks for the second by name. |
| 3 | Two new fields on `Adjudication`: `quoted_evidence` and `asserted_call_edges` | AC-11-5 and AC-11-6 check claims a model had no way to make. A location is a handle into a bundle rather than a string, so without these there is no channel for a fabricated snippet or a fabricated edge to arrive through — and a check with no input is not a check. `SCHEMA_VERSION` moved to `1.6.0`, `policy_versions.prompt` to `2`, and `prompts/v2/` invites both. |
| 4 | Both new fields default to an empty list, where `unresolved_assumptions` is required | The gate *branches* on an empty assumption list — asserting there are none is a claim it can contradict — whereas quoting nothing and omitting the field leave it with identical work. Requiring quotations would also push a model to quote when it has no reason to, and every unnecessary quotation is a new way for a sound finding to fail on a stray space. |
| 5 | A quotation is checked by **containment**, not equality | A region is a whole function and a quotation is usually one line of it. What is not relaxed is the comparison: the quoted bytes must be present exactly, whitespace included (T-11-07). |
| 6 | `REASON_FOR_STATUS` moved from `report/sections.py` to `evidence/resolver.py` | It is a property of `ResolutionStatus`, and parts 08 and 11 both need it. Leaving it in `report` would have meant either a duplicate table or `verify → report → verify`. |
| 7 | `LINE_OUT_OF_RANGE` now maps to `citation_unresolved`, not `hash_mismatch` | A line past the end of a file is not a file that changed. The old mapping sent a reader looking for an edit that never happened. This also satisfies AC-11-3 as written. |
| 8 | `edge_failures` takes the `Index` so it can tell two faults apart: a name the index has never heard of is `symbol_unresolved`, two real functions with no recorded call between them is `call_edge_unresolved` | `IndexResolver` reports both as `SYMBOL_NOT_FOUND`, and only the caller knows which question it asked. This is also what makes T-11-02 reachable at all. |
| 9 | An out-of-bounds precondition requires the access (or, for the write variants, the write) but **not** "something bounding it" | An unbounded write is the *defect*. Requiring a visible bound would reject the clearest true positives in the family. |
| 10 | The precondition check does not run when nothing citable resolved | With no evidence, "the evidence does not support the weakness" is a statement about an argument that does not exist, and it would charge the reviewer twice for one mistake. `citation_unresolved` already says it. |
| 11 | `exploitability` above `unlikely` needs attacker-input evidence; `demonstrated` additionally needs the traced path | Stricter than the plan's sentence rather than looser. Without the refinement `demonstrated` could never be reached through the gate, and a value no input can produce is not a value. |
| 12 | A downgrade is recorded as a `Limitation` (`claim_downgraded`) as well as a `ReviewReason` | The reason lives on the gate's outcome, which part 08 does not render. The limitation is how the weakening reaches the page — "downgraded findings carry their reason into the report" needs a carrier. |
| 13 | `verify()` takes `analyzers` and `model_provenance` beyond the plan's four arguments | AC-11-4 needs the set of tools that actually ran, and nothing in the four objects carries it. Omitting `analyzers` does not skip the check quietly: the finding gains a `provenance_unchecked` limitation, because a check that silently does not run is indistinguishable from one that passed. |
| 14 | A `rejected` verdict yields `model_rejected` and a `review_required` verdict yields `model_inconclusive`, both keeping the candidate | Deleting an analyzer's diagnostic on a model's say-so is the failure this project is built around, and it is the same argument part 10 made for triage. The two are separate reasons because "I disagree" and "I could not tell" are different answers. |
| 15 | The gate reuses `promote_candidate` for the baseline finding it builds on | If the gate's fallback disagreed with part 08 about what a candidate means, the analyzer-only baseline and the adjudicated run would describe different things and the M2 comparison would be measuring the difference between two promoters. |
| 16 | `GateOutcome` gained `details` and `resolution_rate`; `ReviewItem` wraps a `Finding` | `reasons` is what a router branches on and `details` is what lets a human disagree with the gate. `ReviewItem` holds a `Finding` so part 12 can hand it straight to `build_sections`. Neither type has any field or property that sums the two counts, and T-11-20 asserts the absence over both. |
| 17 | Not wired into `caudit scan` | Same standing as parts 09 and 10: a library entry point until part 12 assembles the pipeline. |

## Out of scope and risks

- The gate does not judge whether a bug is *important* — ranking is part 12.
- It cannot detect a finding that is wrong but perfectly cited. That is what the benchmark suites in parts 04 and 13 are for; the two mechanisms cover different failure modes and neither substitutes for the other.
- **Risk:** structural CWE preconditions reject legitimate findings whose evidence is arranged unusually. Mitigation: rejection is never deletion — the item lands in review with the precondition named, and part 13 tracks how often this fires on adjudicated real-world cases.
- **Risk:** downgrade-instead-of-reject could be used to keep weak findings alive. Mitigation: downgraded findings carry their reason into the report, and part 04 counts them separately so the effect on precision is visible.

## Amended by part 12 (2026-08-13)

`verify` is wired into `caudit scan` now. Part 12 supplies the two arguments
part 11 left optional: `analyzers` is the set of tools that actually ran, so
the provenance check in AC-11-4 is live rather than recording a
`provenance_unchecked` limitation, and `model_provenance` records which tier
answered — `tool_name` is the configured model id, `tool_version` is the prompt
policy version, and `rule_id` is the tier.

A refused outcome becomes a review item in the report's **Needs review**
section with the gate's reasons attached, and the finding it carries is ranked
within that section alone. Nothing in part 12 can move it into the confirmed
list: `ReportSections` refuses to hold a review-required finding there, and the
ranking is applied to each list after the split rather than before it.

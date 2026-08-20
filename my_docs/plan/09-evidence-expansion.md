# Part 09 — Evidence expansion

## Goal

Given a candidate location, assemble the code an auditor would actually need to judge it — the whole containing function, the types and macros it depends on, the callers that supply its inputs, the cleanup paths that should have run — inside a token budget, without ever damaging the code that decides the answer.

This is where the spec's guiding principle becomes an algorithm: *select code structurally, but compress prose and noise.* A dropped cast or a truncated bounds check does not degrade the answer gracefully; it inverts it.

## Depends on / Unlocks

- **Depends on:** 06.
- **Unlocks:** 10.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/retrieval/policy.py` | `ExpansionPolicy` — what to pull in, in what order |
| `src/caudit/retrieval/closure.py` | Dependency closure over types, macros, globals |
| `src/caudit/retrieval/paths.py` | Caller/callee expansion, error-handling and cleanup paths |
| `src/caudit/retrieval/budget.py` | Token accounting and unit-level selection |
| `src/caudit/retrieval/context.py` | `EvidenceContext` — the assembled bundle plus handles |
| `tests/unit/test_retrieval_*.py`, `tests/integration/test_expansion_*.py` | This part's tests |

## Interfaces

```python
class UnitClass(StrEnum):
    PRIMARY = "primary"          # never compressed, never truncated
    SUPPORTING = "supporting"    # dropped whole if the budget binds
    SECONDARY = "secondary"      # compressible: duplicate diagnostics, logs, outlines

class ContextUnit(BaseModel):
    evidence_id: str
    unit_class: UnitClass
    region: SourceRegion
    symbol: Symbol | None
    relevance: float
    token_estimate: int

class ExpansionPolicy(BaseModel):
    version: str                 # recorded in the manifest
    caller_depth: int = 2
    callee_depth: int = 1
    include_cleanup_paths: bool = True
    include_global_decls: bool = True
    max_units: int

class EvidenceContext(BaseModel):
    candidate: Candidate
    units: list[ContextUnit]
    dropped: list[DroppedUnit]        # what did not fit, and why
    limitations: list[Limitation]
    total_tokens: int

def expand(candidate: Candidate, index: Index, store: SourceStore,
           policy: ExpansionPolicy, budget: TokenBudget) -> EvidenceContext: ...

def zoom(context: EvidenceContext, evidence_id: str) -> bytes:
    """Exact original bytes for any unit, including dropped ones."""
```

## Expansion order

Ordered so that if the budget binds, what is lost is the least decisive material:

1. **Primary** — the complete function containing the candidate. Whole, never a window.
2. **Primary** — every type, `typedef`, `struct` layout, macro definition, and constant referenced inside that function. This is dependency closure, not a heuristic: omitting the macro that hides a bounds check changes the verdict.
3. **Primary** — for source-to-sink candidates, the complete functions on the reported path.
4. **Supporting** — callers to `caller_depth`, callees to `callee_depth`, complete each.
5. **Supporting** — error-handling and cleanup paths: `goto` cleanup labels, early returns, `free`/`close`/`unlock` sites for the resources involved.
6. **Supporting** — declarations of globals the function touches.
7. **Secondary** — analyzer messages, duplicate diagnostics, file outlines.

Ranking within a class is by dataflow proximity to the candidate value first, call-graph distance second, textual proximity last.

## Budget rules

- The budget is counted with the provider's tokenizer, not a character heuristic, so the number matches what part 10 actually sends.
- **Primary units are never truncated, split, or summarized.** If the primary set alone exceeds the budget, the candidate is not adjudicated: it becomes `review_required` with reason `context_budget_exceeded`. Emitting a half-function to the model is worse than admitting the limit.
- Supporting units are dropped **whole**, lowest relevance first, and each drop is recorded in `dropped` and surfaced as a `Limitation` on the finding.
- Only secondary units may be compressed, and only losslessly with respect to meaning: deduplicating identical analyzer messages, collapsing repeated log lines. No learned or token-level compression touches code.
- Every unit — kept, dropped, or compressed — retains its `evidence_id` and hash, so `zoom` returns the exact original. That is what makes the compression reversible in the sense the spec requires.

## Invariants

- **Dependency closure over primary units is complete or the candidate is flagged.** A partial closure is not silently acceptable.
- **No code is ever paraphrased.** Code enters the context as exact bytes or not at all.
- **What was dropped is visible.** `dropped` is not diagnostic noise; it becomes `Limitations` on any finding derived from this context, which is how a reader learns the model was reasoning with less than the whole picture.
- **Expansion is deterministic.** Same candidate, index, policy, and budget yields the same units in the same order — otherwise part 10's cache and part 12's reproducibility both break.

## Acceptance criteria

- **AC-09-1** The complete containing function is always present, never a line window.
- **AC-09-2** Types, typedefs, macros, and constants referenced by the primary function are all present.
- **AC-09-3** For a fixture where a macro conceals the bounds check, the macro definition is in the context; a control test that omits it demonstrates the verdict would flip.
- **AC-09-4** Callers and callees appear to the configured depth, each as a complete function.
- **AC-09-5** Cleanup paths (`goto` label, early returns, matching `free`/`close`) are included for resource-related candidates.
- **AC-09-6** `total_tokens` never exceeds the budget.
- **AC-09-7** No primary unit is ever truncated, at any budget — property-tested across randomized budgets.
- **AC-09-8** When the primary set alone exceeds the budget, no context is emitted; the candidate is marked `review_required` with reason `context_budget_exceeded`.
- **AC-09-9** Dropped supporting units are recorded and become `Limitations`.
- **AC-09-10** `zoom` returns byte-identical original source for kept, compressed, and dropped units alike.
- **AC-09-11** Compression is applied only to `SECONDARY` units — asserted by class, not by inspection.
- **AC-09-12** Expansion is deterministic across runs and independent of index iteration order.
- **AC-09-13** Every knob that shapes a context — the depths, the unit cap, the closure depth, the retrieval variant — is settable in configuration and reaches `expand`. Added 2026-08-14: part 13's ablation grid can only vary a factor a run can be configured with, and `from_config` read nothing but the version.
- **AC-09-14** The `flat_window` retrieval variant produces a real line window through the same `expand` a scan calls, and the context it produces says it is a window. `structural_plus_semantic` is refused by name rather than silently served by structural retrieval.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-09-01 | integration | Candidate at line 210 of a 180-line function | Context contains the whole function, both boundaries exact | AC-09-1 |
| T-09-02 | integration | Function using `struct hdr`, `typedef u32`, `#define MAX` | All three definitions present | AC-09-2 |
| T-09-03 | integration | `fixtures/cpp/macro_bounds/` — check hidden in `CHECK_LEN` | Macro definition present in the context | AC-09-3 |
| T-09-04 | unit | Same fixture with the macro forcibly excluded | Recorded expectation: remaining evidence no longer proves the check exists (documents why closure is mandatory) | AC-09-3 |
| T-09-05 | integration | Function with 3 callers, 2 callees, depth 2/1 | Expected set present, each complete | AC-09-4 |
| T-09-06 | integration | Leak candidate with `goto cleanup` and two `free` sites | Cleanup label and both `free` sites included | AC-09-5 |
| T-09-07 | integration | Function reading two globals | Global declarations included | AC-09-2 |
| T-09-08 | unit | Budget of 4000 tokens, oversized candidate set | `total_tokens` ≤ 4000 | AC-09-6 |
| T-09-09 | unit | Hypothesis: budgets 500–50000, varied candidates | No primary unit's region is ever a strict subset of its true extent | AC-09-7 |
| T-09-10 | unit | Primary set alone at 120% of budget | No context emitted; `review_required` / `context_budget_exceeded` | AC-09-8 |
| T-09-11 | unit | Budget that fits primaries and half the supporting units | Whole units dropped, none partial; drops recorded lowest-relevance first | AC-09-9 |
| T-09-12 | unit | Context with 3 dropped units | 3 `Limitations` naming what was omitted | AC-09-9 |
| T-09-13 | unit | Kept, compressed, and dropped units | `zoom` byte-identical to source for all three | AC-09-10 |
| T-09-14 | unit | Context containing 5 identical analyzer messages | Deduplicated once, classed `SECONDARY`; code units untouched | AC-09-11 |
| T-09-15 | adversarial | Attempt to compress a `PRIMARY` unit through the API | Rejected — type/assertion prevents it | AC-09-11 |
| T-09-16 | unit | Same inputs, index iteration order shuffled | Identical unit list and order | AC-09-12 |
| T-09-17 | unit | Token estimate vs the provider tokenizer on the same text | Within the documented tolerance; estimate never under-counts | AC-09-6 |
| T-09-18 | integration | Candidate whose path crosses three functions | All three complete functions are `PRIMARY` | AC-09-1 |
| T-09-19 | perf | 500-candidate run (`slow`) | Expansion throughput within budget; index reused, not rebuilt | — |
| T-09-20 | integration | Candidate 80 lines into the 184-line `long_walk`, both variants | Structural returns the function whole; the control returns a window holding neither end of it, retrieves no types/macros/callers/cleanup paths, and says so in a limitation | AC-09-14 |
| T-09-21 | unit | `ExpansionPolicy(variant=structural_plus_semantic)` | Refused by name, through the type, so every route into it is closed | AC-09-14 |
| T-09-22 | unit | Config setting all eight retrieval knobs away from their defaults | Every one reaches the policy; the config `Literal` and the variant enum are asserted to agree | AC-09-13 |

## Out of scope and risks

- No prompt construction or model interaction — part 10.
- No embedding, BM25, or hybrid retrieval. The spec's sequence puts compiler-aware selection first, and for a candidate with a known location the index gives a better answer than similarity search. Semantic retrieval stays available as a later ablation in part 13.
- **Risk:** deep caller expansion explodes on hot utility functions. Mitigation: `max_units` caps breadth, callers are ranked by dataflow proximity, and truncation of the caller set is a recorded `Limitation` rather than a silent cut.
- **Risk:** tokenizer drift when the model changes makes budgets wrong. Mitigation: the tokenizer is obtained from the provider layer, the estimate is asserted never to under-count (T-09-17), and the policy version is recorded per run.

## Implementation notes (added 2026-08-12)

Built as specified. Every acceptance criterion holds and every test in the table exists; `T-09-19` carries the `slow` marker and is deselected by default, as the table's `perf` type prescribes. Deviations from the sketch above, each with its reason:

| # | Sketch | Built | Why |
| --- | --- | --- | --- |
| 1 | `ContextUnit` has `evidence_id`, `unit_class`, `region`, `symbol`, `relevance`, `token_estimate` | Adds `role`, `depth`, `occurrences`, `note` | `unit_class` is derived from `role` and validated against it, so a caller cannot relabel a function as secondary and then compress it. `occurrences`/`note` make compression a representable state that only `SECONDARY` may hold; `depth` is the call-graph distance the ranking needs. |
| 2 | `UnitClass` decides both ordering and dropping | One `relevance` number decides both | Display order and drop order are read from the same key, so they cannot disagree. Role feeds the base relevance, so the plan's seven-step expansion order falls out of the numbers rather than being maintained separately. |
| 3 | "Ranking by dataflow proximity first" | The analyzer's own reported path is the dataflow signal | It is the only dataflow evidence that exists before part 10. A unit containing a `control_flow_step` gets a fixed bonus; call-graph distance is second, location last. Inventing a second proximity measure would be guessing. |
| 4 | `expand(...) -> EvidenceContext` with `review_required` on budget overflow | Returns a context carrying `review_reason=context_budget_exceeded`, `units=[]` | The pipeline still has to report the candidate, so raising would be wrong. `ReviewReason.CONTEXT_BUDGET_EXCEEDED` was added to part 02 and to `BLOCKING_REVIEW_REASONS` (`SCHEMA_VERSION` 1.3.0 → 1.4.0). |
| 5 | `budget: TokenBudget` as a new type | Reuses `config.loader.TokenBudget` | It already exists, is already documented as the thing part 09 spends against, and is already recorded per run. A second type of the same name would be two sources of truth. |
| 6 | Five modules | `UnitFactory` lives in `budget.py` | `closure.py` and `paths.py` both mint units, and a unit's cost *is* token accounting. Putting it in `context.py` would have made `context` import `budget` while `budget` imports `context`. |
| 7 | Macro closure over the containing function | Transitive, and seeded by the type regions too | `BUF_LEN` sizes `struct Frame` and never appears in the function body; a closure that stopped at the function would deliver `CHECK_LEN` without the number it bounds against. Found by T-09-03 while writing it. |
| 8 | Globals come from the index | **Part 06 was extended** with a global-reference graph | The index recorded type references and call edges but not variable references, so AC-09-2 was unsatisfiable without either extending it or matching identifiers textually — which is precisely what the part 06 resolver exists to reject. `INDEX_FORMAT_VERSION` 1 → 2; `graphs.TypeReferences` became `graphs.ReferenceTable` since two instances are now kept. |
| 9 | — | `UnitRole.CANDIDATE_SITE` added | A diagnostic at file scope has no containing function. Retrieving the cited region under the `containing_function` role would be a line window wearing AC-09-1's name; this role says what it is and comes with a `no_evidence_expansion` limitation. |
| 10 | Cleanup paths are retrieved | They are retrieved **and made addressable** | The `goto` block and the `free` sites are usually already inside the primary function. Emitting them as their own units costs a few tokens and buys a citable evidence id per release site, which is what part 11 checks a claim against. Label detection reads the primary's own already-hashed bytes; it locates a line and asserts nothing. |
| 11 | T-09-17 compares against "the provider tokenizer" | Compares against a family of conforming tokenizers | No provider tokenizer exists until part 10. `HeuristicTokenizer` states an assumption — tokens average ≥ 3 characters — and the test holds it to exactly that, on the committed fixtures. The never-under-count half is arithmetic and therefore total; the tolerance half is a stated bound (≤ 2× a 3-char count), not a guess about Gemini. |
| 12 | T-09-04 is a unit test with "the macro forcibly excluded" | Reads the committed fixture's bytes directly | The claim is about what the code says with and without the macro, not about what retrieval does, so routing it through an index would test the wrong thing. |
| 13 | — | `ExpansionPolicy.from_config` | `DEFAULT_POLICY.version` and `config.policy_versions.retrieval` were two independent strings spelling `"1"`, and the manifest records the second. A report naming a retrieval version the run did not use is worse than one naming none. |

Not wired into `caudit scan`: `expand` is a library entry point until part 10 has something to send a context to and part 12 assembles the pipeline. The depth knobs are consequently not on the CLI yet — only `policy_versions.retrieval` is, and it is what the manifest records.

## Amended by part 12 (2026-08-13)

`expand` is wired into `caudit scan` now. It runs once per candidate inside
`caudit.report.assembly.adjudicate_candidates`, charged against a
`RunLedger` that hands out the tail of the run budget in a **fixed candidate
order** — path, then line, then id. That order is part 12's, not part 09's, and
it exists because the ledger decides which candidates a model saw once the
ceiling binds: leaving it to whatever order part 07 emitted would make a
budget-limited run irreproducible for a reason nothing in the report explains.

The depth knobs are still not on the CLI, and `policy_versions.retrieval` is
still the only retrieval setting the manifest records.

## Amended by part 13 (2026-08-14)

The depth knobs **are** configuration now, under a `retrieval` section, and
`ExpansionPolicy.from_config` reads all of them. The reason is part 13's, not
part 09's: `AblationConfig` names `caller_depth` and `retrieval_variant` as
factors to vary, and a factor a run cannot be configured with is a factor
nobody can measure. The grid would have built configurations that differed on
paper and produced byte-identical runs, then reported "no effect" for a knob
that never moved.

The same change added the `flat_window` variant to `expand`. Two things about
it are deliberate and should not be tidied away:

- It goes through **the same `expand`**, selected by a policy field, rather
  than through a second retrieval path. A control implemented separately is a
  control that can quietly stop resembling the thing it is controlling for.
- It is reachable from a scan, via `--set retrieval.variant=flat_window`, and
  every context it produces carries a limitation saying it is a window that
  may cut a function in half and a measurement configuration rather than a
  scanning one. Hiding it from `caudit scan` would have meant the ablation
  measured a code path users cannot run.

`structural_plus_semantic` is refused at policy construction. Part 09 puts
embedding and BM25 retrieval out of scope and no semantic retriever exists, so
the enum names the variant and the type rejects it — a grid can ask for it and
be told, by name, that it does not exist. Accepting it and running structural
retrieval underneath would file structural numbers under a semantic label.

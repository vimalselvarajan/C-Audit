# Pipeline behavior: evidence, LLM, gate, and outputs

## Analyzer-only promotion

`finding_policy.promotion.promote_candidate` is the deterministic baseline mapping.
It supplies a reportable finding from analyzer evidence even when no model is involved.
The no-consent path must remain the same promotion path used for baseline evaluation;
do not create a weaker “fallback” representation that would make baseline and
adjudicated runs incomparable.

Candidate deduplication preserves all analyzer provenance and evidence. Ordered static
analyzer control-flow steps are semantically ordered; never sort or interleave them
while merging candidates.

## Retrieval and budgets

`retrieval.service.expand` creates an `EvidenceContext` for one candidate.

- Normal structural retrieval starts from the whole containing function, then considers
  types, macros, callers, callees, cleanup paths, and analyzer flow evidence according
  to `ExpansionPolicy`.
- The default retrieval variant is `structural`. `flat_window` exists as the ablation
  control and intentionally does not consult the index. `structural_plus_semantic` is
  named but currently refused rather than silently emulated.
- Primary/decisive code must never be lossy-compressed or narrowed to fit a budget.
  If the primary set does not fit, no model call is made and the candidate becomes
  review-required with `context_budget_exceeded`.
- Per-candidate and per-run ceilings are enforced by `TokenBudget` and `RunLedger`.
  Candidate order is deterministic before the ledger spends anything.
- Context units have evidence handles; secondary material may be compacted only under
  the explicit policy. Keep the “capture before selection” ordering intact.

## LLM workflow

The model code is in `llm/`; `llm/service.py::adjudicate` is the pipeline boundary.

1. A consent-aware provider is created only after consent is resolved.
2. Optional triage decides whether a candidate merits the full tier; triage never
   removes it from the report.
3. The adjudication tier receives a versioned, evidence-bounded prompt and must return
   JSON conforming to the exported Pydantic schema.
4. Only ambiguous, high-impact cases may use escalation, and the routing table is
   shared between triage and adjudication.
5. Schema-invalid responses are retried with validation feedback. Prose is never
   salvaged into a finding. Transport retries and schema retries are tracked separately.
6. Reported provider usage, not a local token guess, drives run accounting and optional
   cost ceilings. A content-addressed response cache may replay an unchanged request.

Model IDs and prices are configuration, never hard-coded into workflow decisions.
Prompt policy versions are recorded because a hosted model alias alone is not a
reproducible description of the behavior.

## Gate behavior

`verify.gate.verify` accepts an `Adjudication` only when its evidence and claims pass
local checks. It can produce a confirmed finding, a downgraded confirmed finding, or a
review item. It does not make network calls.

| Situation | Result |
| --- | --- |
| Valid confirmed proposal and no blocking failure | Confirmed finding; gate-derived high confidence unless a claim was downgraded |
| Evidence supports a weaker claim than proposed | Confirmed, weakened claim with medium confidence and visible downgrade reason |
| Invented/unresolved citation, bad quote/edge/symbol/provenance, unsupported CWE, or open assumption | Review-required item with all applicable reasons |
| Model rejects or cannot decide | Review-required item; analyzer candidate remains visible |
| Context/provider/schema/budget problem before a proposal | Analyzer-promoted review item when the reason blocks confirmation |

The gate uses the index-aware resolver. A string match in a comment does not prove a
symbol; two cited functions do not prove a call edge; a re-read file does not prove what
the model saw. Preserve this closed-world behavior in new checks.

## Ranking and report determinism

`finding_policy/ranking.py` computes rank from verified values only:

1. CWE-family severity, capped downward by impact kind;
2. gate confidence;
3. gate reachability;
4. number of independent external analyzer producers;
5. deterministic evidence-span remediation scope.

Model self-confidence and model-written severity do not determine rank. Confirmed and
review-required items are split before ranking and render in separate sections.

`report/service.py` writes UTF-8 with `\n` explicitly. `report.md` and
`results.sarif` omit timestamps, durations, and absolute paths; those facts belong in
`run-manifest.json`. If an artifact becomes nondeterministic, locate and stabilize the
upstream ordering/value rather than normalizing rendered text after the fact.

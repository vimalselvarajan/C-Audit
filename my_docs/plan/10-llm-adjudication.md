# Part 10 — LLM adjudication

## Goal

Ask a model to do the one thing it is better at than the analyzers: connect dispersed evidence into an explanation, decide whether a candidate is real, and say what would fix it. Constrain it so that it can only speak in typed, schema-valid claims that cite evidence it was actually given.

The model is not an oracle here. It produces a proposal; part 11 decides whether it survives.

## Depends on / Unlocks

- **Depends on:** 02, 09.
- **Unlocks:** 11.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/llm/provider.py` | `LLMProvider` protocol, tier routing, retries |
| `src/caudit/llm/gemini.py` | Gemini backend with structured output |
| `src/caudit/llm/prompts/` | Versioned prompt templates per tier |
| `src/caudit/llm/redaction.py` | Secret scrubbing and exclusion enforcement |
| `src/caudit/llm/consent.py` | Consent gate — the only path to the network |
| `src/caudit/llm/cache.py` | Content-hash response cache |
| `src/caudit/llm/accounting.py` | Token and cost accounting, per-finding and per-run caps |
| `tests/cassettes/`, `tests/adversarial/test_privacy.py`, `tests/unit/test_llm_*.py` | This part's tests |

## Interfaces

```python
class Tier(StrEnum):
    TRIAGE = "triage"            # cheap: classify, dedup, plan queries
    ADJUDICATION = "adjudication"
    ESCALATION = "escalation"    # ambiguous, high-impact only

class ModelTierConfig(BaseModel):
    triage: str                  # model id, from config — never hard-coded
    adjudication: str
    escalation: str | None

class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REVIEW_REQUIRED = "review_required"

class Adjudication(BaseModel):
    """The model's proposal. Not a Finding until part 11 accepts it."""
    verdict: Verdict
    cited_evidence_ids: list[str]        # must be IDs from the bundle
    cwe: CweId | None
    cwe_rationale: str
    trigger_conditions: list[str]
    impact: Impact
    reachability: Reachability
    exploitability: Exploitability
    remediation: Remediation
    maintainability_impact: MaintainabilityImpact
    unresolved_assumptions: list[str]    # required; empty list must be deliberate
    confidence_self_report: Confidence

class LLMProvider(Protocol):
    def adjudicate(self, context: EvidenceContext, tier: Tier) -> ProviderResponse: ...
    def token_count(self, text: str) -> int: ...

def route(candidate: Candidate, context: EvidenceContext,
          triage: TriageResult) -> Tier: ...
```

## Consent and privacy

The spec's risk table treats sending source to a hosted model as a first-class hazard, and the MVP posture chosen for this plan is *cloud with explicit consent*. That makes the consent gate a component, not a flag:

- No bytes leave the process without an explicit consent signal (`--consent-cloud`, or a persisted per-repository consent record). Absent consent, `caudit scan` still runs and produces the part 08 baseline report.
- Exclusion globs are enforced **before** prompt assembly, and again as an assertion on the assembled prompt. A file excluded in part 05 can never appear in a request body.
- A redaction pass scrubs credential-shaped strings from the prompt and records how many redactions occurred.
- `--dry-run-prompts` writes every assembled prompt to disk and sends nothing — the way a user audits what would be transmitted before allowing it.
- No prompt or response is persisted by default. The cache stores hashes and parsed results, not raw source; enabling raw retention is explicit and recorded in the manifest.
- The API key is read from the environment only. It never enters config dumps, logs, traces, or the manifest (inherited from part 01).

`LLMProvider` is a protocol precisely so a local backend can be added later without touching parts 09 or 11. The MVP ships the Gemini implementation only.

## Structured output and failure handling

- The response schema is derived from part 02's exported JSON Schema, flattened if the provider rejects constructs it does not support — with the mapping committed and tested.
- A response that is not schema-valid is retried a bounded number of times with the validation error fed back. After the last attempt the candidate becomes `review_required` with reason `schema_invalid_response`. Prose is never parsed into a finding.
- A cited evidence ID not present in the bundle fails immediately here (cheap check) and again in part 11 (authoritative).
- Empty `unresolved_assumptions` is accepted only when the model explicitly asserts there are none; a missing field is a schema violation.

## Cost control

- Responses cache on `sha256(prompt || model_id || policy_version || schema_version)`. A cache hit is free and deterministic, which is also what makes cassette-based testing honest.
- Triage runs first on cheap models to discard obvious non-issues and to plan which candidates deserve full adjudication.
- Escalation fires only when the adjudication verdict is ambiguous **and** the impact is high — a rule with its own truth table and test, not a vibe.
- Per-finding token caps and a per-run cost ceiling; hitting the ceiling stops further calls and records a `Limitation` rather than truncating context to squeeze more in.

## Invariants

- **Model IDs come from configuration and are recorded per run.** No model name is written into the code.
- **The model may only cite what it was given.** Evidence IDs are content-addressed (part 03); an invented one cannot resolve.
- **The model never decides the final state.** Its `verdict` is a proposal; `confidence_self_report` is advisory and is never copied into a `Finding`'s confidence without part 11's verification.
- **No network access in the default test suite.** All tests run from cassettes; live tests are marked `needs_network` and deselected.

## Acceptance criteria

- **AC-10-1** Tier routing follows the configured table; escalation fires only on ambiguous-and-high-impact, verified against a truth table.
- **AC-10-2** Model ids are read from config and recorded in the manifest; no model id appears as a literal in `src/`.
- **AC-10-3** A schema-invalid response is retried the configured number of times, then becomes `review_required` / `schema_invalid_response`.
- **AC-10-4** A prose (non-JSON) response is never converted into a finding.
- **AC-10-5** A response citing an unknown evidence ID is rejected at this layer.
- **AC-10-6** Without consent, zero network calls occur and the baseline report is still produced.
- **AC-10-7** Bytes from an excluded file never appear in an assembled prompt.
- **AC-10-8** Credential-shaped strings are redacted before assembly, and the redaction count is recorded.
- **AC-10-9** The API key appears in no prompt, log, trace, cache entry, or manifest.
- **AC-10-10** `--dry-run-prompts` writes prompts and performs no request.
- **AC-10-11** A repeated identical request is served from cache with no second call.
- **AC-10-12** Exceeding the per-run cost ceiling stops further calls and records a `Limitation`.
- **AC-10-13** Token and cost accounting match the cassette's reported usage.
- **AC-10-14** `unresolved_assumptions` is always present in an accepted response.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-10-01 | unit | Truth table of (ambiguity × impact) | Escalation only in the ambiguous-and-high cell | AC-10-1 |
| T-10-02 | unit | Config naming three tier models | Requests carry the configured ids; manifest records all three | AC-10-2 |
| T-10-03 | unit | Static scan of `src/` | No `gemini-*` string literal outside config defaults and tests | AC-10-2 |
| T-10-04 | unit | Cassette returning malformed JSON twice, then valid | Two retries, then success; call count is 3 | AC-10-3 |
| T-10-05 | unit | Cassette returning malformed JSON every time | `review_required` / `schema_invalid_response`; no partial finding | AC-10-3 |
| T-10-06 | adversarial | Cassette returning a confident prose paragraph | No finding constructed; routed to review | AC-10-4 |
| T-10-07 | adversarial | Cassette citing `ev_deadbeef` (never issued) | Rejected here; reason recorded | AC-10-5 |
| T-10-08 | adversarial | Run without `--consent-cloud`, socket monkeypatched to fail loudly | Zero connections; baseline report still written; exit code sane | AC-10-6 |
| T-10-09 | adversarial | Repo with `secrets/keys.c` excluded, candidate nearby | Assembled prompt contains no byte from that file | AC-10-7 |
| T-10-10 | adversarial | Source containing `AKIA…` and a PEM block | Redacted in the prompt; redaction count recorded | AC-10-8 |
| T-10-11 | adversarial | `GEMINI_API_KEY` set, full run with tracing on | Key value absent from prompts, logs, traces, cache files, manifest | AC-10-9 |
| T-10-12 | unit | `--dry-run-prompts` | Prompt files written; provider call count zero | AC-10-10 |
| T-10-13 | unit | Same candidate adjudicated twice | Second is a cache hit; call count 1; results identical | AC-10-11 |
| T-10-14 | unit | Cache key components varied one at a time | Any change to prompt, model id, policy or schema version misses the cache | AC-10-11 |
| T-10-15 | unit | Cost ceiling set below the run's needs | Calls stop at the ceiling; `Limitation` recorded; no context truncation attempted | AC-10-12 |
| T-10-16 | unit | Cassette with known usage numbers | Accounting matches exactly | AC-10-13 |
| T-10-17 | unit | Response missing `unresolved_assumptions` | Schema violation; not accepted | AC-10-14 |
| T-10-18 | unit | Response with `unresolved_assumptions: []` and an explicit assertion | Accepted | AC-10-14 |
| T-10-19 | unit | Provider raising 429 then succeeding | Backoff honoured; retry recorded in the trace | AC-10-3 |
| T-10-20 | unit | Provider timing out repeatedly | `review_required` / `provider_unavailable`; run completes | AC-10-3 |
| T-10-21 | needs_network | Live Gemini call (deselected by default) | Real response validates against the committed response schema | AC-10-3 |

## Implementation notes (added 2026-08-13)

Part 10 is built. Every acceptance criterion holds and every test in the table
above exists. Where the implementation departs from the sketch, it is recorded
here rather than left for a reader to discover by diffing.

| # | Deviation | Why |
| --- | --- | --- |
| 1 | `Adjudication`, `Verdict`, `Tier`, `TriageResult`, `Usage` and `ProviderResponse` live in a new `llm/adjudication.py`, not in `provider.py` | The plan gives `provider.py` the protocol, routing, and retries — all about *calling*. These types are about *what comes back*, and part 11 imports them without pulling in a retry loop it does not use. |
| 2 | `LLMProvider.adjudicate` takes a `ProviderRequest` holding an already-assembled prompt, not `(context, tier)` | A backend handed an `EvidenceContext` would have to enforce exclusion, scrub secrets, and count the budget itself, and the second backend could forget one. The plan's signature survives as the *package* entry point, `caudit.llm.adjudicate(context, ...)`. |
| 3 | `route()` narrows the escalation cell with three further clauses: escalation disabled, a context holding no code, or no in-scope CWE | Each names a case where the expensive tier cannot change the outcome. A stronger model reading the same nothing returns the same nothing; an out-of-family candidate is review-required whatever comes back. |
| 4 | A triage `dismiss` never removes a candidate. The outcome is `review_required` / `analyzer_only`, and the candidate stays in the report | "Discard obvious non-issues" is implemented as *do not spend the adjudication tier*, not as *delete*. Suppressing a candidate on a cheap model's word, before the evidence gate, is the failure this project is built to avoid. |
| 5 | A fabricated evidence id is rejected without a retry | The plan says it "fails immediately here". Re-asking invites the same claim to be laundered through an id that happens to exist, and the model has already shown it is not working from the bundle. |
| 6 | Four new `ReviewReason` members, `SCHEMA_VERSION` 1.4.0 → 1.5.0 | `schema_invalid_response` and `provider_unavailable` are named by the plan; `citation_unresolved` is what AC-10-5 needs and part 11 also lists; `run_budget_exhausted` is what AC-10-12 leaves a candidate as. All four are in `BLOCKING_REVIEW_REASONS`. |
| 7 | Every field of `Adjudication` is required, and `cwe` is required-and-nullable | "Empty `unresolved_assumptions` must be deliberate" is implemented structurally: the field has no default, so `[]` is a claim the model made and an omission is a schema violation. The same reasoning applied to the rest of the object costs nothing and removes a class of silent defaults. |
| 8 | Six committed schemas, not four: `adjudication`, `triage-result`, and the derived `adjudication-response` / `triage-response` | The flattening *is* the plan's "mapping", and committing the shape a provider is actually handed makes a change to it a CI failure rather than a runtime surprise. `render_derived` in `schema_export.py` renders them through the same drift check. |
| 9 | `GeminiProvider.token_count` is a local estimate; the API's exact count is not called | That number decides whether a request may be *made*. A round trip inside the decision spends a call to ask whether a call is affordable. The estimate over-counts by construction, which is the safe direction, and the ceiling that binds is enforced on reported usage. |
| 10 | Prices are configuration (`llm.pricing.<tier>.*`) and default to zero | A published price belongs to a vendor catalogue; a stale one in the source produces a confident, wrong cost report. A cost ceiling configured against a zero price table records a limitation saying it cannot bind. |
| 11 | Exclusion is enforced separately on quoted code and on generated prose | Found by the second assertion firing during development: the *limitation* explaining a withheld unit named the excluded file. Prose C Audit writes is masked; an `#include "secrets/keys.h"` inside a non-excluded file is that file's own bytes and is not rewritten, because that would be editing code to satisfy a rule about prose. |
| 12 | A redaction inside a `PRIMARY` unit becomes a `Limitation` | The model then reasoned about text that differs from the code, and a claim turning on the replaced span is not supported by what it read. |
| 13 | `llm/cassette.py` ships in `src/`, not under `tests/` | It is the replay path, keyed by prompt version and refusing to answer more requests than it recorded. A test-only copy would let replay and production diverge without anything noticing. |
| 14 | `caudit scan` wires only `--consent-cloud`, `--remember-consent` and `--dry-run-prompts`; `adjudicate()` is a library entry point | An `Adjudication` becomes a `Finding` only through part 11's gate, and part 12 assembles the pipeline. Same posture part 09 took with `expand`. |
| 15 | `--remember-consent` is new | The plan names "a persisted per-repository consent record" as a consent signal but no way to create one. It writes `.caudit/cloud-consent.json`; deleting the file withdraws consent. |
| 16 | `assemble_manifest` gained `models`; `build_report` gained `models` and `extra_limitations` | Part 08 hard-coded `models=[]` "by construction at M1". A stage that ran now passes one record per configured tier, including tiers it never called: `calls=0` says a model was configured and not consulted, where an absent row says nothing. |
| 17 | `RunAccount` and part 09's `RunLedger` both spend against `token_budget.per_run`, with separate counters | They measure different quantities — estimated context against reported billing, the second including output and scaffolding the first never saw. One shared counter would make the ceiling bind at roughly half the number the user set. |

Two things the tests are deliberately *not* asked to prove. T-10-21 does not
assert a verdict: whether a model confirms a defect is a property of the model,
and pinning it would fail on every release for no reason a reader could act on.
And redaction is tested as best-effort with a stated pattern set, not as a
guarantee that a repository holds no secret this code has never seen the shape
of.

## Out of scope and risks

- Verification of the model's claims is part 11 — deliberately a separate component so it cannot be softened to make adjudication look better.
- A local/offline model backend is an interface here, not an implementation.
- **Risk:** provider schema support changes and the flattened response schema drifts from part 02's model. Mitigation: the mapping is committed and tested (T-02-17 plus the cassette contract tests); a drift fails CI.
- **Risk:** cassettes rot as prompts evolve, quietly testing a prompt that no longer exists. Mitigation: cassettes are keyed by prompt version; a prompt version bump without re-recording fails the cache-key test (T-10-14).
- **Risk:** cost estimates diverge from real billing. Mitigation: accounting is derived from reported usage, not estimated locally, and the per-run ceiling is enforced on reported numbers.

### Amended by part 11 (2026-08-13)

`Adjudication` gained two optional fields — `quoted_evidence` and
`asserted_call_edges` — because AC-11-5 and AC-11-6 check claims a model
otherwise has no channel to make: a location is a handle into a bundle rather
than a string, so a fabricated snippet and a fabricated call edge had no way to
reach the gate. `policy_versions.prompt` moved to `2` with templates that invite
both, `prompts/v1/` was kept so a pinned run still gets the instructions it
names, and every committed cassette was re-recorded against v2. The mitigation
above worked exactly as designed: the bump failed loudly rather than replaying
v1 recordings against v2 instructions. See part 11's implementation notes, rows
3 and 4, for why the two fields default to an empty list where
`unresolved_assumptions` is required.

## Amended by part 12 (2026-08-13)

`adjudicate` is wired into `caudit scan` now, on the consented branch only —
no provider is constructed without consent, so a run that may not transmit has
nothing in the process that could open a socket. `RunAccount.records()` and
`cost_usd()` reach the manifest as `models` and `total_cost_usd`.

Two consequences worth knowing:

- **Call counts and token totals are in the manifest and nowhere else.** A
  warm-cache run makes zero calls where the cold run that filled the cache made
  several, so rendering either number in `report.md` or `results.sarif` would
  break the byte-identical requirement those two files are held to.
- **A cached answer does not charge the run ceiling**, which is correct — it
  cost nothing — and means a warm run can adjudicate candidates a cold run's
  budget stopped. AC-12-7 is therefore about two runs *both* warm, and part
  12's perf test primes the cache before comparing.

Part 12's end-to-end tests use a `ScriptedProvider` rather than a cassette,
because a cassette pins one recording to one candidate's evidence ids and a
whole-repository scan gives every candidate its own. It is a plumbing double;
answer quality is measured by `caudit eval --no-baseline`.

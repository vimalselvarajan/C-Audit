# Domain contracts and invariants

## Core distinction: candidate, proposal, finding

| Stage | Type | Meaning |
| --- | --- | --- |
| Analyzer output | `Candidate` | A normalized diagnostic. It can have multiple or no suggested CWEs and is not yet a verified vulnerability. |
| Model output | `Adjudication` | A typed proposal with evidence IDs, claims, rationale, and a verdict. It is never itself a finding. |
| Gate output | `GateOutcome` | Exactly one of an accepted `Finding` or a `ReviewItem`; no third “discarded” state. |
| Report value | `Finding` | Either confirmed (`high`/`medium`) or `review_required`. These populations are never combined. |

`application.pipeline.adjudicate_candidates` and `verify.gate.verify` enforce that
every candidate remains visible even if retrieval, the provider, or verification fails.
A model verdict of `rejected` is not permission to remove a static-analysis candidate.

## Source and evidence

- `SourceRegion` is a repository-relative POSIX span with 1-based inclusive line
  bounds, half-open byte bounds, and a lowercase SHA-256 hash. Absolute paths,
  `..`, drive letters, and Windows separators are rejected at the model boundary.
- Hashes cover exact bytes. Do not normalize whitespace, encoding, or line endings
  before comparing a region or a quoted source string.
- `EvidenceItem.evidence_id` is content-addressed from evidence kind, path, byte
  range, and region hash. Use `EvidenceItem.create`; do not make IDs by hand.
- `EvidenceBundle` captures source before retrieval selection. A dropped context unit
  remains addressable through a handle, which is why compression can be reversible.
- `SourceStore` is the authoritative file-access policy. Bypassing it risks leaking
  excluded or over-limit source and bypassing containment/hash checks.

## Stable identifiers and ordering

`model/ids.py` keeps several intentionally different hashes:

- `candidate_id`: one analyzer observation; includes producer/rule/path/line/message.
- `dedup_fingerprint`: one likely defect across code motion; omits line and normalizes
  diagnostic text.
- `finding_id`: one exact report entry; includes CWE, path, symbol, message, and byte
  range.
- `evidence_id`: one issued source region in a particular evidence role.

Do not reuse one identifier for another job. Candidate processing is sorted by path,
line, and ID before run-budget spending; ranking uses a stable `finding_id` tie break.

## Finding contract

`Finding` requires identity, CWE/rationale, location, evidence, preconditions, impact,
reachability, exploitability, provenance, confidence/reason, remediation,
maintainability impact, limitations, and schema version.

These facts must remain separate:

- **Impact** says what could happen.
- **Reachability** says how the triggering path is supported (`demonstrated`, `argued`,
  or `unknown`).
- **Exploitability** is another evidence-limited claim, not an implication of impact.
- **Confidence** is the deterministic gate’s decision, never the model’s self-report.

The gate may downgrade over-strong impact/reachability/exploitability claims when
evidence supports a weaker one. Fabricated or unresolved evidence routes the item to
review instead.

## CWE policy

`model/cwe.py` holds the checked allowlist. Its six in-scope families are:

- out of bounds
- memory lifetime
- null/uninitialized
- integer
- resource leak
- injection

Class and Pillar mappings are prohibited; some broad mappings are discouraged and need
a rationale. An out-of-scope analyzer candidate is still reported as
`review_required` with `out_of_scope_family`; do not force an inaccurate allowlisted
CWE just to make a candidate fit a score.

## Verification boundary

`verify.gate.verify` is deterministic and model-free. It accumulates applicable
failures instead of stopping at the first one. Checks include:

1. cited evidence IDs were issued in this candidate’s context before any file is opened;
2. cited regions, symbols, and asserted call edges resolve against the scanned revision;
3. quotations exactly match captured bytes;
4. analyzer provenance names a tool that actually ran;
5. unresolved assumptions, verdict semantics, CWE mapping, and evidence preconditions
   are internally supportable;
6. reachability/exploitability claims do not exceed evidence.

Keep verification local and reproducible. A check that calls an LLM or re-reads a
different source snapshot breaks the product’s central trust boundary.

## Schemas and manifests

- JSON Schemas under `schemas/` are generated from model contracts. Change models
  first, then run `make schemas` and verify with `make schema-check`.
- `SCHEMA_VERSION` in `model/finding.py` must move when the exported finding shape
  changes. CI rejects model/schema drift.
- `RunManifest` is the machine-specific reproducibility record. It derives `partial`
  from stage records, rather than trusting a caller-set Boolean. `report.md` and
  `results.sarif` deliberately exclude timestamps, timings, and absolute paths so
  unchanged inputs can render byte-identically.

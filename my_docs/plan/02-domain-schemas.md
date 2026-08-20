# Part 02 — Domain schemas

## Goal

Encode the spec's [finding contract](../specification/core_idea.md) as typed models, and export them as JSON Schema so the same definitions constrain Gemini's output (part 10) and validate it (part 11). Every field in the contract table becomes a required field here; a finding that cannot fill one is not a finding.

This is the part where the spec's separation of *impact* from *reachability* and *exploitability* stops being prose and becomes something the type system enforces.

## Depends on / Unlocks

- **Depends on:** 01.
- **Unlocks:** 03, 04, 07, 08, 10, 11.

## Deliverables

| Path | Contents |
| --- | --- |
| `src/caudit/model/source.py` | `SourceRegion`, `RegionHash`, `Symbol` |
| `src/caudit/model/evidence.py` | `EvidenceItem`, `EvidenceKind`, `Provenance` |
| `src/caudit/model/candidate.py` | `Candidate` — analyzer output, pre-adjudication |
| `src/caudit/model/finding.py` | `Finding`, `Confidence`, `ReviewReason`, `Impact`, `Reachability`, `Exploitability`, `Limitation`, `MaintainabilityImpact` |
| `src/caudit/model/manifest.py` | `RunManifest` |
| `src/caudit/model/cwe.py` | Allowlist, family mapping, prohibited-mapping rules |
| `src/caudit/model/ids.py` | `finding_id`, `dedup_fingerprint`, `evidence_id` |
| `schemas/*.schema.json` | Exported JSON Schema, versioned, committed |
| `tests/unit/test_model_*.py`, `tests/golden/schemas/` | This part's tests |

## Interfaces

```python
class SourceRegion(BaseModel):
    path: PurePosixPath        # always repository-relative
    start_line: int            # 1-based, inclusive
    end_line: int              # 1-based, inclusive
    start_byte: int
    end_byte: int
    sha256: str                # of the exact bytes in [start_byte, end_byte)

class Provenance(BaseModel):
    producer: Producer         # clang_diagnostic | csa | clang_tidy | index | llm
    tool_name: str
    tool_version: str
    rule_id: str | None        # e.g. "bugprone-use-after-move", "core.NullDereference"
    detail: str | None

class EvidenceItem(BaseModel):
    evidence_id: str           # content-addressed; see ids.py
    kind: EvidenceKind         # primary_code | supporting_code | type_decl | macro_def |
                               # call_edge | analyzer_diagnostic | control_flow_step
    region: SourceRegion
    symbol: Symbol | None
    provenance: list[Provenance]   # never empty

class Candidate(BaseModel):
    candidate_id: str
    fingerprint: str
    region: SourceRegion
    suggested_cwe: list[CweId]
    message: str
    provenance: list[Provenance]   # grows on merge; entries are never dropped

class Finding(BaseModel):
    finding_id: str
    fingerprint: str
    cwe: CweId
    cwe_rationale: str
    location: SourceRegion
    symbol: Symbol | None
    evidence: list[EvidenceItem]           # min_length=1
    preconditions: list[str]
    impact: Impact                         # what can happen
    reachability: Reachability             # unknown | argued | demonstrated
    exploitability: Exploitability         # unknown | unlikely | plausible | demonstrated
    provenance: list[Provenance]
    confidence: Confidence                 # high | medium | review_required
    confidence_reason: ReviewReason        # machine-checkable enum, always present
    remediation: Remediation
    maintainability_impact: MaintainabilityImpact
    limitations: list[Limitation]
    schema_version: str

def finding_id(cwe: CweId, path: PurePosixPath, symbol: str | None, message: str) -> str: ...
def dedup_fingerprint(cwe: CweId, path: PurePosixPath, symbol: str | None,
                      normalized_message: str) -> str: ...
def evidence_id(region: SourceRegion, kind: EvidenceKind) -> str: ...
```

## Invariants

- **`confidence` never stands alone.** Every `Finding` carries a `confidence_reason` from a closed enum (`all_citations_resolved`, `hash_mismatch`, `symbol_unresolved`, `impact_exceeds_evidence`, `assumptions_unstated`, `analyzer_only`, …). "Machine-checkable reason" from the spec means a value part 11 can branch on, not free text.
- **Impact, reachability, and exploitability are three fields.** No code path may infer one from another. The spec's risk table names conflating them as a distinct failure mode.
- **Fingerprints survive code motion; IDs identify a report entry.** `dedup_fingerprint` excludes line numbers and normalizes the message (strip digits, quoted identifiers, and paths) so the same defect matches across revisions. `finding_id` is stable for identical inputs and is what SARIF `partialFingerprints` and cross-run comparison use.
- **Evidence lists are never empty and provenance lists are never empty.** A claim with no producer is not representable.
- **Paths are repository-relative POSIX paths.** Absolute paths, `..` segments, and platform separators are rejected at the model boundary — this is the first line of defence against a citation pointing outside the scanned tree.
- **Schema changes are deliberate.** The exported JSON Schema is committed; CI diffs it against a fresh export and fails on drift unless `schema_version` was bumped in the same change.

## CWE mapping rules

MITRE's guidance is to map to the most specific accurate Base or Variant entry and follow each entry's mapping notes ([CWE mapping guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html)). Encoded as data, not judgement:

- An allowlist per in-scope weakness family (out-of-bounds read/write, UAF/double-free, null deref/uninitialized, integer overflow/truncation/signedness, resource leak, format string/command injection).
- A prohibited set — Class-level and Pillar entries such as CWE-664, CWE-118, CWE-707 — rejected when a Base or Variant in the same family applies.
- A "discouraged" set that is accepted only with an explicit rationale string.
- Every allowlist entry records the family it belongs to so part 04 can compute per-family macro-F2.

## Acceptance criteria

- **AC-02-1** Every field of the spec's finding contract table is a required field of `Finding`, with no catch-all `extra` dict.
- **AC-02-2** Models round-trip through JSON without loss, including nested evidence and provenance.
- **AC-02-3** `dedup_fingerprint` is unchanged when the defect moves to a different line; `finding_id` is deterministic across processes and machines.
- **AC-02-4** A CWE outside the allowlist, or a prohibited Class-level mapping where a Base entry applies, is rejected at construction.
- **AC-02-5** A `Finding` cannot be constructed with empty `evidence` or empty `provenance`.
- **AC-02-6** A `Finding` cannot be constructed with a `confidence` but no `confidence_reason`.
- **AC-02-7** An absolute path, a `..` segment, or a Windows separator in `SourceRegion.path` is rejected.
- **AC-02-8** Exported JSON Schema matches the committed files byte for byte unless `schema_version` changed.
- **AC-02-9** The exported schema is accepted as a response schema by the Gemini structured-output validator (shape check only, offline).

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-02-01 | unit | Contract field list from the spec, as data | Every listed field exists on `Finding` and is required | AC-02-1 |
| T-02-02 | unit | Fully populated `Finding` | `model_validate(json.loads(dump))` equals the original | AC-02-2 |
| T-02-03 | unit | Same defect at line 40 and line 118 | Fingerprints equal | AC-02-3 |
| T-02-04 | unit | Two different defects in the same function | Fingerprints differ | AC-02-3 |
| T-02-05 | unit | Identical inputs, computed in two subprocesses | `finding_id` identical (no hash randomization leak) | AC-02-3 |
| T-02-06 | unit | Message differing only in a buffer size digit | Normalized fingerprint equal; raw message retained | AC-02-3 |
| T-02-07 | unit | CWE-9999 | Rejected with a message naming the allowlist | AC-02-4 |
| T-02-08 | unit | CWE-664 on an out-of-bounds write | Rejected; error suggests CWE-787 | AC-02-4 |
| T-02-09 | unit | Discouraged mapping without rationale, then with one | Rejected, then accepted | AC-02-4 |
| T-02-10 | unit | `Finding` with `evidence=[]` | `ValidationError` | AC-02-5 |
| T-02-11 | unit | `EvidenceItem` with `provenance=[]` | `ValidationError` | AC-02-5 |
| T-02-12 | unit | `confidence="high"`, reason omitted | `ValidationError` | AC-02-6 |
| T-02-13 | unit | `Impact` describing remote code execution, `reachability="unknown"` | Both fields retained independently; no inference occurs | AC-02-1 |
| T-02-14 | unit | Paths `/etc/passwd`, `../x.c`, `src\\x.c` | All three rejected | AC-02-7 |
| T-02-15 | golden | Fresh schema export | Byte-identical to `schemas/*.schema.json` | AC-02-8 |
| T-02-16 | unit | Model changed without a `schema_version` bump (simulated) | Drift check fails with a message naming the bump | AC-02-8 |
| T-02-17 | contract | Exported `Finding` schema | Passes the structured-output schema shape validator (no unsupported constructs) | AC-02-9 |
| T-02-18 | unit | `RunManifest` with a missing analyzer version | `ValidationError` — reproducibility fields are required | AC-02-1 |

## Out of scope and risks

- No hashing of real files (part 03), no analyzer parsing (part 07), no prompt construction (part 10).
- **Risk:** Gemini's structured-output support does not accept every JSON Schema construct (`$ref` depth, `oneOf`, tuple forms). Mitigation: T-02-17 checks shape offline, and part 10 keeps a flattened response schema separate from the internal model if they must diverge — with a documented mapping.
- **Risk:** over-strict CWE allowlisting suppresses real findings in families the MVP does not cover. Mitigation: out-of-family candidates are not dropped; they are recorded with `confidence=review_required` and reason `out_of_scope_family`.

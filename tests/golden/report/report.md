# C Audit report

Compiler-aware, evidence-gated analysis of `demo` at revision `demo-revision`.

| | |
| --- | --- |
| Confirmed findings | 5 |
| Items needing review | 1 |
| Coverage | 3/3 source files (1.00), 3/3 translation units selected |
| caudit | 0.1.0 |
| Analyzers | clang 18.1.8, clang-static-analyzer 18.1.8, clang-tidy 18.1.8, libclang 18.1.1 |
| Models | none consulted — this report is the deterministic analyzer baseline |
| Policies | matching v1, profile v1, prompt v1, retrieval v1 |

> Confirmed findings and items needing review are counted separately and are never added together. A review-required item is a candidate whose evidence did not fully resolve — it is not a vulnerability, and it is not a false positive either. It is unfinished work.

## Confirmed findings (5)

### 1. CWE-787 — Out-of-bounds Write

`src/alpha.c:12`

Call to function 'strcpy' is insecure as it does not provide bounding

- **Impact** memory_corruption (severity high); evidence supports: A static analyzer reported this at src/alpha.c:12. The evidence is the diagnostic and the cited region, nothing more.
- **Reachability** unknown · **Exploitability** unknown · **Confidence** medium (analyzer_only)
- **CWE mapping** Mapped from the analyzer rule clang-analyzer-security.insecureAPI.strcpy using the committed rule-to-CWE table; no model was involved.
- **Reported by** clang-tidy 18.1.8 [clang-analyzer-security.insecureAPI.strcpy]
- **Why this rank** severity high (from the out_of_bounds family, capped at what memory_corruption can do) · confidence medium · reachability unknown · reported by one analyzer · local fix

Evidence, and what produced each fact:

- `src/alpha.c:12` — analyzer_diagnostic · from clang-tidy

**Provenance.** analyzers (clang-tidy): the diagnostic and its location; no model was consulted about this finding

Preconditions:

- Preconditions not established: the baseline records the analyzer's trigger location, not the inputs required to reach it.

**Remediation.** Bound the write to the destination's capacity and validate the index or length before the access.

Derived from the weakness family, not from repository-specific reasoning. The MVP recommends; it does not modify code.

**Maintainability.** Ownership, complexity, coupling and regression risk: Not assessed: the analyzer-only baseline reports where a check fired and does not evaluate this dimension. Effort: medium.

Limitations on this finding:

- **no_evidence_expansion** (`src/alpha.c`) Analyzer-only baseline: no cross-function evidence expansion and no adjudication were performed for this candidate.

<sub>finding id `caudit-34f14deb73c5c165` · fingerprint `fp-e1a90c0a08acc65b`</sub>

### 2. CWE-134 — Use of Externally-Controlled Format String

`src/gamma.c:5`

format string is not a string literal (potentially insecure)

- **Impact** code_execution (severity high); evidence supports: A static analyzer reported this at src/gamma.c:5. The evidence is the diagnostic and the cited region, nothing more.
- **Reachability** unknown · **Exploitability** unknown · **Confidence** medium (analyzer_only)
- **CWE mapping** Mapped from the analyzer rule -Wformat-security using the committed rule-to-CWE table; no model was involved.
- **Reported by** clang 18.1.8 [-Wformat-security]
- **Why this rank** severity high (from the injection family, capped at what code_execution can do) · confidence medium · reachability unknown · reported by one analyzer · local fix

Evidence, and what produced each fact:

- `src/gamma.c:5` — analyzer_diagnostic · from clang

**Provenance.** analyzers (clang): the diagnostic and its location; no model was consulted about this finding

Preconditions:

- Preconditions not established: the baseline records the analyzer's trigger location, not the inputs required to reach it.

**Remediation.** Use a constant format string, and pass untrusted data as an argument rather than as part of the command or format.

Derived from the weakness family, not from repository-specific reasoning. The MVP recommends; it does not modify code.

**Maintainability.** Ownership, complexity, coupling and regression risk: Not assessed: the analyzer-only baseline reports where a check fired and does not evaluate this dimension. Effort: medium.

Limitations on this finding:

- **no_evidence_expansion** (`src/gamma.c`) Analyzer-only baseline: no cross-function evidence expansion and no adjudication were performed for this candidate.

<sub>finding id `caudit-3874de658c7b9913` · fingerprint `fp-4d4188a05e42a132`</sub>

### 3. CWE-476 — NULL Pointer Dereference

`src/alpha.c:17`

Access to field 'size' results in a dereference of a null pointer

- **Impact** undefined_behavior (severity medium); evidence supports: A static analyzer reported this at src/alpha.c:17. The evidence is the diagnostic and the cited region, nothing more.
- **Reachability** unknown · **Exploitability** unknown · **Confidence** medium (analyzer_only)
- **CWE mapping** Mapped from the analyzer rule core.NullDereference using the committed rule-to-CWE table; no model was involved.
- **Reported by** clang-static-analyzer 18.1.8 [core.NullDereference]
- **Why this rank** severity medium (from the null_uninitialized family, capped at what undefined_behavior can do) · confidence medium · reachability unknown · reported by one analyzer · local fix

Evidence, and what produced each fact:

- `src/alpha.c:17` — analyzer_diagnostic · from clang-static-analyzer

**Provenance.** analyzers (clang-static-analyzer): the diagnostic and its location; no model was consulted about this finding

Preconditions:

- Preconditions not established: the baseline records the analyzer's trigger location, not the inputs required to reach it.

**Remediation.** Check the result before dereferencing it, and initialise the variable on every path that reaches its use.

Derived from the weakness family, not from repository-specific reasoning. The MVP recommends; it does not modify code.

**Maintainability.** Ownership, complexity, coupling and regression risk: Not assessed: the analyzer-only baseline reports where a check fired and does not evaluate this dimension. Effort: medium.

Limitations on this finding:

- **no_evidence_expansion** (`src/alpha.c`) Analyzer-only baseline: no cross-function evidence expansion and no adjudication were performed for this candidate.

<sub>finding id `caudit-9479da53560b9a88` · fingerprint `fp-52e115b9f60097d2`</sub>

### 4. CWE-401 — Missing Release of Memory after Effective Lifetime

`src/beta.c:10`

Use of memory after it is released

- **Impact** resource_exhaustion (severity medium); evidence supports: A static analyzer reported this at src/beta.c:10. The evidence is the diagnostic and the cited region, nothing more.
- **Reachability** unknown · **Exploitability** unknown · **Confidence** medium (analyzer_only)
- **CWE mapping** Mapped from the analyzer rule unix.Malloc using the committed rule-to-CWE table; no model was involved.
- **Reported by** clang-static-analyzer 18.1.8 [unix.Malloc]
- **Why this rank** severity medium (from the resource_leak family, capped at what resource_exhaustion can do) · confidence medium · reachability unknown · reported by one analyzer · function fix

Evidence, and what produced each fact:

- `src/beta.c:10` — analyzer_diagnostic · from clang-static-analyzer
- `src/beta.c:5` — control_flow_step · from clang-static-analyzer
- `src/beta.c:6` — control_flow_step · from clang-static-analyzer
- `src/beta.c:9` — control_flow_step · from clang-static-analyzer
- `src/beta.c:10` — control_flow_step · from clang-static-analyzer

**Provenance.** analyzers (clang-static-analyzer): the diagnostic and its location; no model was consulted about this finding

Preconditions:

- Preconditions not established: the baseline records the analyzer's trigger location, not the inputs required to reach it.

**Remediation.** Release the resource on every exit path, including early error returns.

Derived from the weakness family, not from repository-specific reasoning. The MVP recommends; it does not modify code.

**Maintainability.** Ownership, complexity, coupling and regression risk: Not assessed: the analyzer-only baseline reports where a check fired and does not evaluate this dimension. Effort: medium.

Limitations on this finding:

- **no_evidence_expansion** (`src/beta.c`) Analyzer-only baseline: no cross-function evidence expansion and no adjudication were performed for this candidate.

<sub>finding id `caudit-0ca56dcfc53193e6` · fingerprint `fp-f022035c89d78556`</sub>

### 5. CWE-190 — Integer Overflow or Wraparound

`src/beta.c:15`

Loop variable has narrower type than the bound it is compared against

- **Impact** incorrect_result (severity medium); evidence supports: A static analyzer reported this at src/beta.c:15. The evidence is the diagnostic and the cited region, nothing more.
- **Reachability** unknown · **Exploitability** unknown · **Confidence** medium (analyzer_only)
- **CWE mapping** Mapped from the analyzer rule bugprone-too-small-loop-variable using the committed rule-to-CWE table; no model was involved.
- **Reported by** clang-tidy 18.1.8 [bugprone-too-small-loop-variable]
- **Why this rank** severity low (from the integer family, capped at what incorrect_result can do) · confidence medium · reachability unknown · reported by one analyzer · local fix

Evidence, and what produced each fact:

- `src/beta.c:15` — analyzer_diagnostic · from clang-tidy

**Provenance.** analyzers (clang-tidy): the diagnostic and its location; no model was consulted about this finding

Preconditions:

- Preconditions not established: the baseline records the analyzer's trigger location, not the inputs required to reach it.

**Remediation.** Perform the arithmetic in a width that cannot wrap, and reject inputs that would overflow before they reach the calculation.

Derived from the weakness family, not from repository-specific reasoning. The MVP recommends; it does not modify code.

**Maintainability.** Ownership, complexity, coupling and regression risk: Not assessed: the analyzer-only baseline reports where a check fired and does not evaluate this dimension. Effort: medium.

Limitations on this finding:

- **no_evidence_expansion** (`src/beta.c`) Analyzer-only baseline: no cross-function evidence expansion and no adjudication were performed for this candidate.

<sub>finding id `caudit-1011fbdd96733ded` · fingerprint `fp-e80cfb9d1840ee5d`</sub>

## Needs review (1)

### 1. CWE-908 — Use of Uninitialized Resource

`src/gamma.c:10`

non-literal format string passed to fprintf

- **Impact** undefined_behavior (severity low); evidence supports: A static analyzer reported this at src/gamma.c:10. The evidence is the diagnostic and the cited region, nothing more.
- **Reachability** unknown · **Exploitability** unknown · **Confidence** review_required (out_of_scope_family)
- **CWE mapping** The analyzer rule caudit-demo-unmapped has no accurate entry in the rule-to-CWE table. CWE-908 is provisional, derived from the diagnostic text alone, which is why this item is routed to review-required with reason out_of_scope_family rather than reported as a confirmed finding.
- **Reported by** clang-tidy 18.1.8 [caudit-demo-unmapped]
- **Why this rank** severity medium (from the null_uninitialized family, capped at what undefined_behavior can do) · confidence review_required · reachability unknown · reported by one analyzer · local fix

Evidence, and what produced each fact:

- `src/gamma.c:10` — analyzer_diagnostic · from clang-tidy

**Provenance.** analyzers (clang-tidy): the diagnostic and its location; no model was consulted about this finding

Preconditions:

- Preconditions not established: the baseline records the analyzer's trigger location, not the inputs required to reach it.

**Remediation.** Review the diagnostic and the surrounding code.

Derived from the weakness family, not from repository-specific reasoning. The MVP recommends; it does not modify code.

**Maintainability.** Ownership, complexity, coupling and regression risk: Not assessed: the analyzer-only baseline reports where a check fired and does not evaluate this dimension. Effort: medium.

Limitations on this finding:

- **no_evidence_expansion** (`src/gamma.c`) Analyzer-only baseline: no cross-function evidence expansion and no adjudication were performed for this candidate.

<sub>finding id `caudit-2af982616c3d273a` · fingerprint `fp-99d142bcb4fcb258`</sub>

## Coverage

| | |
| --- | --- |
| Entries in the compilation database | 3 |
| Translation units selected | 3 |
| Source files covered | 3/3 (1.00) |

Complete.

## Excluded from the scan

Nothing was excluded.

## Limitations

None recorded. Every unit the plan selected was examined as described.

## Reproducing this run

`run-manifest.json` beside this file records the timestamps, the resolved tool paths, the effective configuration and its hash (`abababababab…`), and the source-region hash of every finding here. It is the only artifact of the three that contains machine-specific values, which is what makes the other two comparable across machines.

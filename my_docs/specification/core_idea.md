# C Audit: Evidence-Backed AI Auditing for C and C++

> Research and product assumptions last checked: 2026-08-11.

## One-sentence product definition

C Audit is a compiler-aware C/C++ auditing tool that combines deterministic static analysis with Gemini-assisted repository reasoning and produces a reproducible, evidence-backed vulnerability report rather than an ungrounded list of suspected bugs.

The project was inspired by access to the Gemini API in an Intro to Software Engineering class. [RepoAudit](https://github.com/PurCL/RepoAudit) is the closest existing project, but C Audit would take a narrower position: C and C++ only, build-aware, and optimized for findings that can be traced back to exact source evidence.

## Product thesis

Static analyzers are good at generating candidates but can be noisy or lack repository-level context. Large language models are good at connecting dispersed code and explaining a finding, but can hallucinate or miss small semantic details. C Audit should combine them without treating either as an oracle:

1. The compiler and static analyzers generate facts and candidate paths.
2. Structure-aware retrieval expands only the code needed to evaluate each candidate.
3. Gemini adjudicates, explains, and prioritizes candidates using a strict output schema.
4. Deterministic validation rejects findings whose cited locations, symbols, or evidence do not exist.
5. The final report distinguishes confirmed findings from unresolved review candidates.

The core principle is:

> **Use AI to connect and explain evidence, not to invent it.**

## First usable version

After scanning a repository, the MVP produces an evidence-backed audit report with two artifacts:

- `report.md`: a human-readable report for developers.
- `results.sarif`: a machine-readable report that can be consumed by compatible code-scanning systems.

SARIF is an OASIS standard for static-analysis results and can represent source locations, rules, severity, and ordered code flows. [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

A small `run-manifest.json` should also record the commit hash, configuration, analyzer versions, model identifiers, prompt/retrieval policy versions, and hashes of cited source regions. This makes a report reproducible and allows two runs to be compared.

### Finding contract

Every reported vulnerability must contain:

| Field | Requirement |
| --- | --- |
| Identity | Stable finding ID and deduplication fingerprint |
| Classification | Specific CWE when justified; avoid overly broad or prohibited mappings |
| Location | Repository-relative file, line range, symbol, and source-region hash |
| Evidence | Exact relevant code regions with source-to-sink or control-flow steps when applicable |
| Preconditions | Inputs, build flags, call paths, or runtime state required to trigger the issue |
| Impact | What can happen, separated from whether the path is reachable or exploitable |
| Provenance | Which analyzer, compiler fact, or retrieval step produced each supporting fact |
| Confidence | `high`, `medium`, or `review-required`, with a machine-checkable reason |
| Remediation | A concrete fix strategy, not an automatically applied patch in the MVP |
| Maintainability impact | How the recommendation affects ownership, complexity, coupling, and future regression risk |
| Limitations | Missing build targets, unresolved indirect calls, unavailable generated code, or other blind spots |

MITRE recommends mapping vulnerabilities to the most specific accurate CWE Base or Variant entry and following each entry's mapping notes. [CWE mapping guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html)

### Evidence gate

A candidate becomes a reported vulnerability only if:

1. Every cited file, line, symbol, and call edge resolves against the scanned revision.
2. The evidence supports the stated weakness and trigger conditions.
3. The reported impact does not exceed what the evidence proves.
4. The model identifies any unresolved assumptions.

If these checks fail, the item is placed in a separate **Needs review** section. It must not be counted as a confirmed vulnerability.

## MVP repository requirements

The first version should intentionally require a well-described build rather than pretend to understand every repository.

### Required

- A local C or C++ repository.
- A `compile_commands.json` compilation database covering the targets to scan.
- Source and generated headers needed to parse those targets.
- A supported Clang/LLVM toolchain on Linux for the initial implementation.
- A Gemini API key supplied at runtime and never stored in the repository.

A compilation database records the working directory, input file, and real compilation command for each translation unit. Clang tooling uses it to recover include paths, macros, language standards, and other flags. [Clang JSON compilation database specification](https://clang.llvm.org/docs/JSONCompilationDatabase.html)

For CMake projects, users can normally generate it with:

```bash
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

The CLI could then look like:

```bash
caudit scan . --compile-commands build/compile_commands.json --out caudit-report
```

### Deliberate MVP behavior

- If the compilation database is absent or materially incomplete, stop with actionable setup instructions.
- Do not silently fall back to guessed include paths or compiler flags in the MVP.
- Record how many translation units parsed successfully and list excluded targets in the report.
- Treat third-party and generated code as excluded by default, with explicit opt-in controls.

A later best-effort mode may accept `compile_flags.txt` or inferred flags, but its findings must be visibly labeled lower confidence. Clangd itself supports both compilation databases and a shared flags file for simpler projects. [clangd compile-command design](https://clangd.llvm.org/design/compile-commands)

## MVP scope

### In scope

- C11-or-newer and C++17-or-newer code that Clang can parse.
- Repository-level auditing of selected build targets.
- Candidate generation from Clang diagnostics, Clang Static Analyzer, and selected `clang-tidy` checks.
- Evidence retrieval across functions, types, macros, callers, callees, and include relationships.
- Vulnerability classification, explanation, prioritization, and remediation guidance.
- Maintainability risks that materially affect security, such as high-complexity validation paths, unclear ownership, duplicated security checks, and fragile error handling.
- Markdown and SARIF 2.1.0 output.

Initial weakness families should be limited to areas with strong C/C++ tooling and benchmark coverage:

- Out-of-bounds reads and writes.
- Use-after-free, double-free, and ownership errors.
- Null dereferences and uninitialized values.
- Integer overflow, truncation, and signedness errors.
- Resource leaks and incomplete cleanup paths.
- Format-string and command-injection risks.

### Out of scope for the MVP

- Automatically editing or committing code.
- Claiming exploitability without evidence of reachability and attacker control.
- Whole-program guarantees in the presence of unavailable generated code, plugins, inline assembly, or unresolved dynamic dispatch.
- Replacing compiler diagnostics, fuzzing, formal verification, or human security review.
- Supporting every build system by guessing build flags.
- Persisting source code or model prompts by default.

## Goals

1. Produce reports whose claims can be traced to exact source evidence.
2. Use lower-cost Gemini models for triage and reserve stronger models for ambiguous findings.
3. Mitigate context rot with compiler-aware retrieval, reversible compression, and strict token budgets.
4. Measure security detection and maintainability equally without allowing one to hide unacceptable performance on the other.
5. Keep model and analyzer providers configurable so the design is not pinned to a single version.

## Model strategy

Use capability tiers rather than hard-coding a model family in the architecture:

| Role | Desired behavior | Current Gemini example |
| --- | --- | --- |
| Triage | Cheap classification, deduplication, and query planning | Gemini 3.5 Flash-Lite |
| Adjudication | Repository reasoning and evidence synthesis | Gemini 3.6 Flash or Gemini 3.5 Flash |
| Escalation | Optional second opinion for ambiguous, high-impact findings | A stronger supported Gemini model selected by configuration |

Google's model catalog changes over time, so the exact defaults should live in configuration and be recorded in the run manifest. The current catalog lists Gemini 3-series stable models, including Flash and Flash-Lite variants. [Gemini model catalog](https://ai.google.dev/gemini-api/docs/models)

Gemini should return a typed finding object constrained by JSON Schema rather than free-form prose. The API supports structured JSON output, which can be validated before report generation. [Gemini structured output](https://ai.google.dev/gemini-api/docs/structured-output)

## Success criteria and evaluation

The primary score should weight security and maintainability equally:

\[
\text{OverallScore} = 0.5 \times \text{SecurityScore} + 0.5 \times \text{MaintainabilityScore}
\]

However, this average is valid only after hard safety gates are met. A gain in maintainability must not compensate for invented evidence or very poor vulnerability recall.

### Hard gates

- At least 95% of cited locations and symbols resolve exactly.
- Zero fabricated files, functions, analyzer names, or source snippets in the scored evaluation set.
- Confirmed findings and review-required candidates are never merged into one count.
- Security recall and precision floors are established against the non-AI static-analysis baseline before an overall score is reported.

### Security score

Use macro-averaged F2 across supported CWE families so recall matters more than precision, while still reporting precision, false positives per thousand lines of code, and evidence-validity rate separately. Do not rely on one aggregate number alone.

Evaluation should progress through three levels:

1. [CASTLE](https://github.com/CASTLE-Benchmark/CASTLE-Benchmark): 250 small C programs covering 25 CWEs; useful for fast regression tests and comparison with multiple analyzer types.
2. [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112): 64,099 cases across 118 CWEs; useful for broad synthetic coverage.
3. A manually adjudicated real-repository set drawn from CVE-linked vulnerable and fixed revisions, such as [CVEfixes](https://github.com/secureIT-project/CVEfixes); useful for repository-scale realism.

Synthetic suites are necessary but insufficient. They often make the vulnerable function and build environment easier to isolate than real projects do.

### Maintainability score

For the report-only MVP, maintainability means the ability to identify and explain security-relevant maintenance hazards, not the ability to generate long-lived patches. Build a small, versioned C/C++ evaluation set whose examples are independently labeled by at least two reviewers for:

- Complexity in security-critical control flow.
- Duplicated or inconsistent validation.
- Ownership and lifetime ambiguity.
- Coupling that makes a security fix likely to regress.
- Error-handling and cleanup fragility.

Score category-level macro F1, ranking quality for the top findings, and the factual accuracy/actionability of recommendations. Clang-tidy's `bugprone`, `readability`, and related check families can generate candidates, but labels must be independently adjudicated to avoid scoring the tool against its own output. [Clang-tidy check categories](https://clang.llvm.org/extra/clang-tidy/)

### Editing benchmarks belong to a later phase

The following benchmarks assess code generation or repository modification, not vulnerability-report generation:

- [MaintainCoder / MaintainBench](https://github.com/IAAR-Shanghai/MaintainCoder)
- [SWE-CI](https://github.com/SKYLENAGE-AI/SWE-CI)
- [NITR](https://github.com/ucr-riple/NITR)

Keep them as Phase 2 benchmarks for an optional remediation agent. Do not use them as primary evidence that the report-only MVP detects vulnerabilities or assesses existing-code maintainability.

## Proposed architecture

1. **Repository intake**
   - Resolve the repository root and revision.
   - Load and validate `compile_commands.json`.
   - Apply target, third-party, generated-code, and file-size filters.

2. **Deterministic indexing**
   - Parse translation units with Clang.
   - Build symbol, reference, include, call, type, and macro indices.
   - Store source locations and content hashes.

3. **Candidate generation**
   - Run Clang diagnostics, Clang Static Analyzer, and a curated `clang-tidy` profile.
   - Normalize diagnostics into a shared candidate schema.
   - Merge duplicate findings while preserving provenance.

4. **Evidence expansion**
   - Start from the candidate location.
   - Retrieve the complete containing function plus relevant types and macros.
   - Expand callers, callees, and error-handling paths within a token budget.
   - Keep handles to original source so any compressed context is reversible.

5. **LLM adjudication**
   - Ask Gemini for a typed decision: confirmed, rejected, or review-required.
   - Require cited evidence IDs, trigger conditions, CWE rationale, impact, and remediation.
   - Escalate only ambiguous high-impact cases to a stronger configured model.

6. **Deterministic verification**
   - Resolve every citation and source hash.
   - Check the output schema and allowed CWE mappings.
   - Reject claims that refer to absent evidence.

7. **Report generation**
   - Rank findings by severity, confidence, reachability, and likely developer effort.
   - Render Markdown and SARIF 2.1.0.
   - Record coverage gaps and run metadata.

## Main context techniques

| Technique | How it works | Tools using it |
| --- | --- | --- |
| Symbol-level retrieval | Parses code into functions, classes, types, and references. The agent requests a symbol or its callers instead of reading entire files. | [Serena](https://github.com/oraios/serena), LeanCTX |
| Repository graph ranking | Builds a graph of files and symbols and their references, then applies a PageRank-like algorithm to select important definitions within a token budget. | [Aider Repo Map](https://aider.chat/docs/repomap.html) |
| AST-based structural compression | Uses Tree-sitter or another parser to retain imports, declarations, and signatures while removing function bodies or other detail. | [Repomix](https://github.com/yamadashy/repomix), Headroom |
| Semantic retrieval | Embeds queries and chunks as vectors and retrieves those with the highest similarity. | LlamaIndex, RAGFlow, Mem0 |
| Keyword retrieval | Uses lexical algorithms such as BM25. This often handles exact identifiers, error codes, and unusual names better than embeddings. | RAGFlow, Graphiti, Mem0 |
| Hybrid retrieval | Combines semantic similarity, keyword scores, metadata, and sometimes graph relationships; a reranker then sorts the candidates. | [Graphiti](https://github.com/getzep/graphiti), RAGFlow, Mem0 |
| Token-level compression | Estimates which words or tokens contain little useful information and removes them before calling the main LLM. | [LLMLingua](https://github.com/microsoft/LLMLingua) |
| Hierarchical loading | Stores short abstracts, medium summaries, and complete content. It expands only the relevant branches to full detail. | [OpenViking](https://github.com/volcengine/OpenViking) |
| Reversible compression | Sends a compressed representation but caches the original. The agent can request the complete original if necessary. | [Headroom](https://github.com/headroomlabs-ai/headroom), LeanCTX |
| External memory | Extracts durable facts or experiences, stores them in vector or graph databases, and retrieves them in later sessions. | Mem0, Letta, LangMem, Graphiti |
| History compaction | Summarizes old messages or tool output, removes them from the active window, but preserves the originals externally. | Letta, LeanCTX, Headroom |
| Context evaluation | Records the exact prompt, retrieved chunks, token usage, latency, and output quality so different retrieval policies can be tested. | [Langfuse](https://langfuse.com/docs/observability/overview) |
| Context evolution | Converts successful and failed interactions into an incrementally updated playbook of strategies. | [ACE](https://github.com/ace-agent/ace) |

### 1. Structure-aware code retrieval

Serena asks language servers such as `clangd` for:

- Symbol definitions
- References
- Callers and callees
- Type declarations
- Symbol outlines
- Selected function bodies

This is considerably more precise than splitting code every 1,000 characters. For C++, the results depend on `clangd` having the correct `compile_commands.json`, include paths, macros, and language standard.

Aider takes a different approach. It extracts definitions and references with Tree-sitter, forms a repository dependency graph, and ranks nodes so that the most relevant declarations fit within the available token budget. [Aider's explanation](https://aider.chat/docs/repomap.html)

Repomix can use Tree-sitter to convert implementation-heavy files into structural summaries containing primarily declarations and signatures. That is useful for an initial repository map, but not for inspecting an actual vulnerability because important statement-level behavior is removed. [Repomix compression documentation](https://github.com/yamadashy/repomix)

### 2. Learned prompt compression

The LLMLingua family uses small auxiliary models:

- **LLMLingua:** uses a smaller language model's token probabilities to identify relatively expendable prompt tokens.
- **LongLLMLingua:** first ranks larger context segments using the question, allocates different compression budgets, reorders important evidence, and then performs finer token pruning.
- **LLMLingua-2:** uses a bidirectional encoder trained through data distillation to classify tokens as retain or remove.

This is lossy compression. It can be effective for prose and repetitive retrieval results, but code such as:

```cpp
if (length < buffer_size)
```

cannot safely become an approximate textual representation. A single removed operator or cast can reverse the security meaning.

### 3. Code-specific learned compression

[LongCodeZip](https://arxiv.org/abs/2510.00446) uses a coarse-to-fine process:

1. Parse the input into function-level units.
2. Score each function's relevance to the task using conditional perplexity or approximate mutual information.
3. Retain the most relevant functions.
4. Divide those functions into smaller blocks.
5. Choose blocks under an adaptive token budget, formulated as a selection or knapsack problem.

This is better aligned with code structure than generic prompt compression, but it can still break dependency closure: a discarded macro, `typedef`, cleanup path, or indirect caller might be essential to proving a vulnerability.

### 4. Format-specific and reversible compression

Headroom routes different input types through different compressors:

- Structured reduction for JSON
- AST-aware processing for code
- A learned compressor for natural language
- Pattern-based reduction for logs and tool output
- Caching of originals for later retrieval

Its reversible retrieval is an important idea: a summary can include a handle pointing to the original data, allowing the model to "zoom in" when evidence is incomplete. [Headroom architecture](https://github.com/headroomlabs-ai/headroom)

LeanCTX applies a similar collection of techniques: token-budgeted filling, symbol outlines, single-symbol reads, compressed shell output, cached originals, conversation checkpoints, and persistent project knowledge. [LeanCTX tools](https://github.com/yvgude/lean-ctx/blob/main/docs/reference/appendix-mcp-tools.md)

### 5. Hierarchical context

OpenViking creates three versions of stored information:

- **L0:** very short abstract
- **L1:** overview and structure
- **L2:** complete details

Retrieval begins with intent analysis, searches likely directories, recursively explores promising branches, and reranks the results. The complete files are loaded only at the end. [OpenViking retrieval design](https://github.com/volcengine/OpenViking/blob/main/docs/en/concepts/07-retrieval.md)

This resembles how a human explores a repository: directory tree, file outline, relevant function, and related definitions.

### 6. Persistent memory

Different systems use different memory representations:

- **Mem0:** extracts facts from interactions and retrieves them using semantic, keyword, and entity-based signals. [Mem0](https://github.com/mem0ai/mem0)
- **Letta:** keeps small, important memory blocks permanently inside the prompt while putting larger archival memories in a semantic database queried on demand. [Letta context hierarchy](https://docs.letta.com/v1-sdk/memory/context-hierarchy)
- **LangMem:** distinguishes semantic facts, episodic examples of previous experiences, and procedural instructions. [LangMem concepts](https://langchain-ai.github.io/langmem/concepts/conceptual_guide/)
- **Graphiti:** represents entities and relationships in a temporal graph, preserving both current facts and their historical validity. Retrieval combines embeddings, BM25, and graph traversal.

Persistent cross-repository memory is not required for the MVP. It creates privacy, staleness, and data-isolation risks before it creates clear product value. Start with per-run state and versioned evaluation traces.

### 7. Context evaluation

Langfuse does not directly shrink context. It makes the context pipeline measurable:

- Which chunks were retrieved
- Their ranking and metadata
- The final prompt
- Input/output token counts
- Latency and cost
- Human, code-based, or model-judge scores
- Comparisons across retrieval and prompt versions

This matters because using fewer tokens is not enough. For an auditor, the important measurement is whether vulnerability recall and evidence accuracy remain stable. [Langfuse evaluation system](https://langfuse.com/docs/evaluation/overview)

## Recommended technical sequence

Use the techniques in this order:

1. **Compiler-aware selection:** compilation database, Clang AST, symbol references, include graph, and call graph.
2. **Static-analysis-directed retrieval:** use compiler diagnostics, Clang Static Analyzer, and selected `clang-tidy` checks to provide candidate locations.
3. **Dependency expansion:** retrieve relevant types, macros, global state, callers, callees, and error-handling paths.
4. **Budgeted assembly:** rank complete code units, but never token-compress the primary evidence.
5. **Compress only secondary material:** duplicate diagnostics, build logs, old conversation turns, and unrelated repository outlines.
6. **Reversible retrieval:** retain hashes and source locations so Gemini can request any original region.
7. **Structured adjudication:** require schema-valid decisions and evidence identifiers.
8. **Deterministic verification:** resolve all citations before rendering a finding.
9. **Evaluation:** measure vulnerability recall, false positives, evidence completeness, maintainability quality, tokens, latency, and cost.

> **Guiding principle:** Select code structurally, but compress prose and noise. For security auditing, lossy compression inside the decisive code path is usually an unacceptable tradeoff.

## Implementation roadmap

### Milestone 0: Evaluation harness

- Define the candidate and finding schemas.
- Wrap CASTLE and a small Juliet subset.
- Run compiler/static-analysis baselines before adding Gemini.
- Implement exact location and evidence validation.

### Milestone 1: Deterministic scanner

- Load `compile_commands.json`.
- Index symbols and source hashes.
- Run the curated Clang toolchain.
- Normalize and deduplicate candidates.
- Emit baseline Markdown and SARIF.

### Milestone 2: Evidence-aware Gemini adjudication

- Add symbol-level and dependency retrieval.
- Add structured Gemini output.
- Implement confirmed, rejected, and review-required states.
- Compare recall, precision, evidence accuracy, cost, and latency against Milestone 1.

### Milestone 3: Repository-scale validation

- Add real vulnerable/fixed repository pairs.
- Create the independently labeled maintainability set.
- Test context budgets and retrieval ablations.
- Calibrate confidence labels and severity ranking.

### Phase 2: Optional remediation agent

- Generate patch proposals in an isolated worktree.
- Build and test each patch.
- Re-run the audit and measure regressions.
- Only then use MaintainBench, SWE-CI, and NITR as relevant benchmarks.

## Major risks

| Risk | Mitigation |
| --- | --- |
| Hallucinated evidence | Typed evidence IDs, source hashes, and deterministic citation checks |
| Incorrect build context | Require and validate the compilation database; report coverage gaps |
| Static-analyzer bias | Preserve provenance, compare multiple signals, and include analyzer-silent benchmark cases |
| Context truncation | Retrieve complete code units and expand dependencies; never lossy-compress decisive code |
| Benchmark overfitting | Separate development and held-out repositories; include synthetic and real-world sets |
| Data leakage to a hosted model | Explicit consent, configurable exclusions, no retention by default, and a future local-model path |
| Uncontrolled API cost | Cheap triage tier, caching by content hash, per-finding budgets, and escalation only when needed |
| Misleading severity | Separate weakness, reachability, exploitability, and deployment impact in the schema |

## Decisions made so far

- The first usable output is an evidence-backed vulnerability report.
- The MVP requires a valid `compile_commands.json` rather than guessing build flags.
- The report is human-readable Markdown plus SARIF 2.1.0, with a reproducibility manifest.
- Security and maintainability have equal weight in the primary product score, subject to non-negotiable evidence and security gates.
- The MVP recommends remediations but does not modify code.
- Gemini model names are configurable and recorded per run rather than embedded in the architecture.

## Open product questions

1. Is the first target a local CLI for an individual developer, a CI check for a team, or both?
2. May the tool send selected source regions to the Gemini API with explicit consent, or must private repositories have a no-cloud mode from the first release?
3. Should the MVP analyze only explicitly selected targets, or every translation unit present in `compile_commands.json` by default?

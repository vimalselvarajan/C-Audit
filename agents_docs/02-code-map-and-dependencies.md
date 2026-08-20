# Code map and dependency rules

## Package map

| Package | Owns | Useful entry points |
| --- | --- | --- |
| `application/` | Use-case orchestration, stage records, schema export | `scan.run_scan`, `pipeline.adjudicate_candidates`, `evaluation.run_suite` |
| `analyzers/` | Profile loading, subprocess runners, parser adapters, normalization, deduplication | `service.generate_candidates`, `profile.load_profile` |
| `cli/` | Typer commands and presentation of application results | `main.app`, `scan_cmd.apply_scan_overrides`, `eval_cmd.run_eval` |
| `config/` | Immutable Pydantic config, precedence and toolchain probing | `loader.load_config_with_sources`, `schema.Config`, `toolchain.ToolchainProbe` |
| `evidence/` | Safe source access, hashing, bundles, citation resolution | `store.SourceStore`, `resolver.CitationResolver` |
| `eval/` | Benchmark adapters, matching, metrics, hard gates, compare, pairs, ablations, calibration | `runner`, `metrics`, `gates`, `compare` |
| `finding_policy/` | Deterministic candidate promotion, per-claim provenance, ranking | `promotion.promote_candidate`, `ranking.rank_findings` |
| `index/` | libclang parsing, index storage, graph traversal/resolution | `store.build_index`, `resolver.IndexResolver` |
| `intake/` | Compilation database and target-selection policy | `loader.load_scan_plan`, `compdb.load_entries` |
| `llm/` | Consent, prompt/version routing, Gemini client, response cache, redaction, retry and accounting | `service.adjudicate`, `provider.route`, `gemini.GeminiProvider` |
| `model/` | Pure shared contracts, enums, IDs and source regions | `Candidate`, `Adjudication`, `Finding`, `RunManifest` |
| `report/` | Markdown/SARIF/manifest construction and console rendering | `service.build_report`, `service.write_report` |
| `retrieval/` | Evidence closure, policy variants, token budgets and context handles | `service.expand`, `budget.RunLedger` |
| `verify/` | Citation, quote, edge, CWE and claim verification | `gate.verify` |

## Enforced import boundaries

`.importlinter` is part of `make check`; a passing type check does not excuse an
architecture violation. Preserve these rules:

- `model` is pure and must not depend on CLI, reporting, evaluation, LLM, or
  application orchestration.
- Capability modules (`analyzers`, `evidence`, `index`, `intake`, `retrieval`,
  `llm`, `verify`) must not depend on `cli`, `report`, or `eval`.
- `report` must not import `application.pipeline` or `application.scan`.
- `cli.main` only composes commands/use cases. It must not directly import
  capability packages; commands use local/lazy imports to keep this true.
- `application` must not import `cli`.

When a change appears to need a forbidden import, prefer passing a typed value,
protocol, or result into the lower-level module. `application/ports.py` and the
existing provider/source protocols are examples of this approach.

## Data ownership

The values below have one authoritative owner. Avoid parallel representations or
recalculation from lossy text.

| Data | Authoritative type/package | Rule |
| --- | --- | --- |
| Scan scope, exact build argv, exclusions, coverage | `intake.plan.ScanPlan` | Downstream stages consume the plan instead of rediscovering build context |
| Parsed symbols and graphs | `index.store.Index` | Use the index resolver for symbol/call-edge facts whenever indexed data exists |
| Read source bytes and hashes | `evidence.store.SourceStore` / `EvidenceBundle` | Respect repository containment, exclusions, file-size caps, and captured bytes |
| Analyzer diagnosis | `model.candidate.Candidate` | Preserve provenance and ordered control-flow evidence through deduplication |
| LLM response | `model.adjudication.Adjudication` | Treat it as a proposal only; never construct a confirmed `Finding` directly from it |
| Final report item | `model.finding.Finding` | Confirmation/confidence are gate-derived; review-required items are a separate state |
| Reproducibility record | `model.manifest.RunManifest` | Include tool/model/config/policy/coverage/stage facts rather than scattered metadata |

## Where to make common changes

- New configuration setting: `config/schema.py` → loader tests → CLI/display if
  appropriate → manifest behavior → documentation.
- New model field: `model/` validator → every producer/consumer → regenerate
  `schemas/` → update schema and golden tests.
- New analyzer input/output format: a focused adapter in `analyzers/` →
  normalization → service integration → fixtures and integration tests.
- New retrieval rule: `retrieval/policy.py`, `closure.py`, `paths.py`, or
  `service.py` depending on whether it is selection policy, graph closure, or
  context construction. Preserve full decisive code units.
- New check on a model proposal: add it under `verify/`, collect all failures in
  `gate.verify`, and ensure a failure routes to a visible review item.
- New report field: build it from contracts/manifest in `report/`; do not make the
  renderer perform business decisions.

## Naming and implementation conventions

- Python 3.12, strict mypy, Pydantic v2, immutable `BaseModel` contracts using
  `ConfigDict(extra="forbid", frozen=True)` where practical.
- Use repository-relative POSIX paths in domain values; never put host-specific
  absolute paths in deterministic report artifacts.
- Sort externally observable collections deliberately. Candidate visit order,
  findings, report sections, exclusions, and serialized artifacts are expected to be
  deterministic.
- Use a typed project exception (`CauditError` subclass) for an expected,
  user-actionable failure. Do not catch broad `Exception` merely to continue.
- Keep user-derived strings out of Rich markup; the console is configured with markup
  disabled for that reason.

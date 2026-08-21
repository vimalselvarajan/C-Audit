# C Audit: agent briefing

This directory is a working map for agents modifying C Audit. It is a guide to the
implementation; the canonical product decisions remain in [`my_docs/`](../my_docs/README.md).

## Documentation authority

This README is the single entry point for repository agent instructions. The top-level
`AGENTS.md`, `AGNETS.md`, `AGNETS.md.orig`, and `CLAUDE.md` files are compatibility
pointers only; keep project guidance here instead of duplicating it in those files.

Use the narrowest canonical source for facts that change independently:

- [`my_docs/`](../my_docs/README.md) owns product decisions, the design specification,
  the implementation plan, setup, measured results, and project gaps.
- The root [README](../README.md) summarizes current project status and public usage.
- [Evaluation results](../my_docs/project/evaluation-results.md) owns measured figures
  and their policy-version caveats; [project gaps](../my_docs/project/project-gaps.md)
  owns unvalidated claims and the proof roadmap.
- The [setup guide](../my_docs/guides/setup.md) owns machine setup and repository
  maintenance procedures, including generated-history cleanup.

Agent docs should contain durable implementation guidance and links to those records,
not copied status, measurements, local-machine facts, or historical incident narratives.

## Start here

1. Read the [product and repository overview](../README.md), then the
   [design specification](../my_docs/specification/core_idea.md).
2. Read [`my_docs/plan/00-overview.md`](../my_docs/plan/00-overview.md) before
   changing a feature. The numbered plan files identify the acceptance criteria and
   test tables for their area.
3. Use the notes below to find the implementation and its non-negotiable invariants.
4. Inspect `git status` before editing. This checkout may contain work unrelated to
   the task; preserve it and do not reset, clean, or reformat it broadly.

| Need | Read |
| --- | --- |
| Understand the end-to-end scanner | [Architecture and flow](01-architecture-and-flow.md) |
| Find the owning module or preserve import boundaries | [Code map](02-code-map-and-dependencies.md) |
| Change models, evidence, or verification safely | [Domain contracts](03-domain-contracts-and-invariants.md) |
| Run, configure, or troubleshoot C Audit | [CLI, configuration, and operations](04-cli-configuration-and-operations.md) |
| Work on retrieval, model calls, gating, or reports | [Pipeline behavior](05-pipeline-evidence-llm-and-outputs.md) |
| Choose and run the right checks | [Testing and quality gates](06-testing-ci-and-development.md) |
| Interpret or extend benchmarks and measurements | [Evaluation and benchmarks](07-evaluation-and-benchmarks.md) |
| Follow a task-specific implementation checklist | [Change playbooks and boundaries](08-change-playbooks-and-boundaries.md) |

## What this repository is

C Audit is a Python 3.12 CLI for compiler-aware C/C++ security auditing. Static
analysis creates candidates; optional Gemini-assisted adjudication can connect those
candidates to evidence; a deterministic verification gate decides whether a proposal
is confirmed or needs review. The product deliberately does **not** generate or apply
patches.

The central rule is: **use AI to connect and explain evidence, not to invent it.** A
model response is only a proposal. Cited source, symbols, call edges, quotes, CWE
mapping, and claim strength are checked locally before a finding can be confirmed.

## Repository ownership

| Path | Purpose | Agent rule |
| --- | --- | --- |
| `src/caudit/` | Package source | Main implementation area |
| `tests/` | Unit, integration, contract, adversarial, end-to-end, and golden tests | Extend the closest existing test layer |
| `schemas/` | Generated JSON Schemas from Pydantic models | Never hand-edit; regenerate/check them through the provided tooling |
| `my_docs/` | Canonical design, setup, plan, measurements, and project gaps | Update when a product claim, plan, or measured result changes |
| `benchmarks/` | Mini suite and formats/manifests for other corpora | Treat committed recordings and truth data as experimental inputs |
| `audit-targets/` | User-controlled repositories being scanned | Do not modify unless the task explicitly targets that checkout |
| `inspiration_repos/` | Independent upstream reference clones | Read-only; do not edit, reformat, or import wholesale |
| `caudit-report/`, `caudit-eval/`, and related `caudit-*` paths | Generated artifacts | Disposable; do not commit |

## Fast orientation

- CLI composition is in `src/caudit/cli/`; scan orchestration is
  `src/caudit/application/scan.py::run_scan`.
- The domain boundary is `src/caudit/model/`. Models are immutable Pydantic
  contracts with `extra="forbid"`.
- The package is intentionally layered. `.importlinter` makes the import rules
  executable; read [the code map](02-code-map-and-dependencies.md) before moving
  imports across layers.
- `make check` is the local equivalent of the principal CI quality gate. It runs
  guard, lint, strict typing, schema drift, docs validation, import-layer checks, and
  the default offline test suite.

Use the canonical docs for design rationale and external references; use this folder
to turn a task into a small, correctly scoped code change.

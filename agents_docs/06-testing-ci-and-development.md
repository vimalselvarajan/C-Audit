# Testing, CI, and development workflow

## Primary commands

```bash
make bootstrap          # create .venv and install package + dev dependencies
make doctor             # inspect LLVM/libclang tooling
make lint               # ruff check and format check
make typecheck          # mypy --strict
make schema-check       # detect generated-schema drift
make docs-check         # validate canonical documentation and local links
make architecture-check # enforce .importlinter contracts
make test               # default pytest suite with coverage
make check              # all of the above plus tracked-artifact guard
```

`make check` is CI’s principal quality target. Run the narrowest relevant tests while
iterating, then run the broadest proportionate target before handoff.

## Test layout

| Directory | Purpose |
| --- | --- |
| `tests/unit/` | Pure behavior and edge cases by package |
| `tests/integration/` | Components joined together, including indexing/analyzers/pipeline |
| `tests/contract/` | Architecture and artifact contracts such as import layers/SARIF |
| `tests/adversarial/` | Fabricated citations/claims, privacy, malformed LLM output, gate failures |
| `tests/e2e/` | Complete scan/evaluation flows |
| `tests/golden/` | Stable ranking and Markdown/schema output |
| `tests/fixtures/` | Tiny C/C++ projects, analyzer output, compdb, encoding, and source fixtures |
| `tests/cassettes/` | Committed model/provider recordings for deterministic tests |

Default pytest options deselect `needs_clang`, `needs_network`, and `slow`, making the
normal suite offline and deterministic. `needs_libclang` tests remain selected when the
wheel can be loaded. CI additionally installs controlled Clang tools and runs
`pytest -m needs_clang --no-cov`.

## Current enforced standards

- Ruff uses a 100-character line length and targets Python 3.12.
- Mypy is strict across `src`, `tests`, and `tools`; warning handling is intentionally
  strict.
- Branch coverage measures `src/caudit` with a current configured floor of **90%**.
  Treat `pyproject.toml` as authoritative if prose elsewhere is older.
- Warnings are errors in pytest.
- The source package, tests, and tools must remain compatible with Python 3.12.

## Schema, documentation, and generated artifacts

- `schemas/` is generated from Pydantic contracts via `tools/export_schemas.py`. Use
  `make schemas` after an intentional model-shape change; use `make schema-check` to
  prove no update was missed.
- `tools/check_docs.py` validates root and `my_docs/` documents and their local links.
  Keep the canonical tree under `my_docs/`; do not recreate a legacy `docs/` tree.
- Golden tests make report order and wording part of the external behavior. Update a
  golden only after confirming the behavior change is intentional and deterministic.
- `make guard` and pre-commit refuse generated output, nested repositories, and `.env`
  in the Git index. Do not force-add any of them.

## Choosing tests for a change

| Change | Minimum focused verification |
| --- | --- |
| Model/schema/ID/validation | Relevant `tests/unit/test_model_*.py`, schema tests/check, adversarial tests if a trust boundary changed |
| Intake or compdb behavior | `tests/unit/test_intake_*.py` plus `tests/integration/test_intake_cmake.py` when appropriate |
| Index/graph/traversal | Matching unit tests plus `tests/integration/test_index_*.py` |
| Analyzer normalization/profile/runner | `tests/unit/test_analyzer_*.py` and `tests/integration/test_analyzers_*.py` |
| Retrieval or budgets | `tests/unit/test_retrieval_*.py`, expansion integration tests, ablation tests if policy changes |
| Prompt/provider/consent/redaction | `tests/unit/test_llm_*.py` and privacy/adversarial tests |
| Gate/report/ranking | `tests/unit/test_verify_*.py`, report/ranking/golden tests, SARIF contract tests |
| CLI behavior | The matching `test_cli_*.py` and an end-to-end scan test where output/exit status changes |

Prefer fixtures and cassettes over live tool/network tests. A live benchmark or API run
is valuable for a measurement, but it is not a replacement for a deterministic
regression test.

## Working-tree safety

Do not use `git reset --hard`, `git checkout --`, broad `make clean`, or bulk formatter
runs as a substitute for understanding the task. The checkout can contain unrelated
changes, including documentation moves. Inspect status and limit edits to task-owned
files; explain any existing failure that is outside that scope.

# Part 01 — Engineering baseline

## Goal

Stand up the package, the CLI shell, configuration loading, and the quality gates that every later part relies on. Also solve the problem this machine makes obvious: **no Clang toolchain is installed**. The tool must detect that precisely, pin the versions it expects, and tell the user how to fix it — the same posture the spec demands for a missing compilation database ("stop with actionable setup instructions", [MVP behavior](../specification/core_idea.md)).

No analysis happens in this part. `caudit scan` exists but exits with "not implemented" until part 05.

## Depends on / Unlocks

- **Depends on:** nothing.
- **Unlocks:** every other part.

## Deliverables

| Path | Contents |
| --- | --- |
| `pyproject.toml` | Package metadata, pinned dependencies, ruff/mypy/pytest config |
| `src/caudit/cli/main.py` | Command group: `scan`, `doctor`, `eval`, `compare`, `--version` |
| `src/caudit/cli/exit_codes.py` | Exit-code enum, single source of truth |
| `src/caudit/config/loader.py` | Layered configuration with precedence and policy versions |
| `src/caudit/config/toolchain.py` | Toolchain discovery, version parsing, requirement checks |
| `src/caudit/logging.py` | Structured logging, secret-safe formatter |
| `tests/unit/test_cli_*.py`, `tests/unit/test_config_*.py` | This part's tests |
| `.pre-commit-config.yaml`, `Makefile` or `justfile` | `lint`, `typecheck`, `test`, `bootstrap` targets |
| `my_docs/guides/setup.md` | Toolchain install instructions the `doctor` command points at |

Dependencies to pin: `pydantic>=2`, `libclang`, `google-genai`, `jsonschema`, `typer`, `rich`, `pytest`, `pytest-cov`, `hypothesis`, `ruff`, `mypy`.

`libclang` comes from the PyPI wheel, which ships its own shared library. That decouples *indexing* (part 06) from a system LLVM install. The `clang-tidy` and Clang Static Analyzer binaries (part 07) cannot be obtained that way and remain a genuine system requirement.

## Interfaces

```python
class ExitCode(IntEnum):
    OK = 0                # ran, no confirmed findings
    FINDINGS = 1          # ran, confirmed findings present
    USAGE = 2             # bad arguments or configuration
    ENVIRONMENT = 3       # missing/incompatible toolchain, missing compile DB
    INTERNAL = 4          # unexpected failure; always prints a traceback id

@dataclass(frozen=True)
class ToolInfo:
    name: str
    path: Path | None
    version: str | None          # normalized "18.1.8"
    satisfies_requirement: bool
    install_hint: str

class ToolchainProbe:
    def probe(self, required: Mapping[str, VersionSpec]) -> list[ToolInfo]: ...
    def require(self, *names: str) -> None:
        """Raise EnvironmentError with an actionable message if any tool is missing."""

class Config(BaseModel):
    llvm_version: str                 # pinned major, e.g. "18"
    models: ModelTierConfig           # part 10 fills this in
    policy_versions: PolicyVersions   # prompt/retrieval/matching policy version strings
    exclude_globs: list[str]
    token_budget: TokenBudget

def load_config(
    cli_overrides: Mapping[str, object],
    config_file: Path | None,
    env: Mapping[str, str],
) -> Config:
    """Precedence: CLI > env (CAUDIT_*) > config file > packaged defaults."""
```

## Invariants

- **Never guess.** If a required tool is absent or its version is outside the pinned range, exit `ENVIRONMENT` with the exact install command. Do not silently fall back to a different analyzer or a system default. This mirrors the spec's refusal to guess build flags.
- **Versions are facts to record.** Every discovered tool version is retained for the run manifest (part 08). A run whose analyzer versions are unknown is not reproducible.
- **Secrets never reach logs.** The logging formatter redacts anything matching known key patterns and any value read from `GEMINI_API_KEY`. Enforced here so part 10 inherits it rather than reinventing it.
- **Policy versions are configuration, not constants.** Prompt, retrieval, and matching-policy versions live in config so a report can name the policy that produced it.

## Acceptance criteria

- **AC-01-1** `caudit --version` prints the package version and exits `OK`.
- **AC-01-2** `caudit doctor` reports every required tool with its path, version, and whether it satisfies the pin; exits `OK` when all are satisfied and `ENVIRONMENT` when any is not.
- **AC-01-3** On a machine with no Clang (the current one), `doctor` names each missing tool and prints a copy-pasteable install command; it does not raise a traceback.
- **AC-01-4** Configuration precedence is CLI > env > file > defaults, and the effective config is dumped by `--print-config`.
- **AC-01-5** An unknown configuration key is a `USAGE` error, not a silent ignore.
- **AC-01-6** No log record, at any level, contains the value of `GEMINI_API_KEY`.
- **AC-01-7** `ruff`, `mypy --strict`, and a coverage floor of 85% run as one `make check` target and are wired into CI.
- **AC-01-8** `caudit scan` exists, validates its arguments, and exits `USAGE`/`INTERNAL` cleanly with a "not implemented until part 05" message.
- **AC-01-9** `make clean` removes every generated category the `UNTRACKABLE` guard names, and stops there: the virtualenv, the reference clones, and `.env` survive it. The two lists are checked against each other, so a category added to the guard cannot quietly go unclean — nor can an unclearnable one start being cleaned.
- **AC-01-10** The API key may be kept in a project-local `.env`, loaded into the shell by `tools/load-env.sh`. `caudit` itself never reads that file: there is no dotenv dependency and no `load_dotenv` call, so the key still reaches the process only through the environment. `.env` is refused by `make guard` and by a pre-commit hook, and never printed by the loader.

## Test cases

| ID | Type | Fixture | Assertion | Covers |
| --- | --- | --- | --- | --- |
| T-01-01 | unit | — | `--version` output matches package metadata, exit 0 | AC-01-1 |
| T-01-02 | unit | Fake `PATH` with all tools present, stub `--version` output | `doctor` reports all satisfied, exit 0 | AC-01-2 |
| T-01-03 | unit | Empty `PATH` | `doctor` lists every tool as missing, exit 3, output contains an install command per tool | AC-01-2, AC-01-3 |
| T-01-04 | unit | Stub `clang-tidy` reporting version 15 against a pin of 18 | Reported unsatisfied with both versions named; exit 3 | AC-01-2 |
| T-01-05 | unit | Stub emitting unparseable `--version` text | Version recorded as `unknown`, treated as unsatisfied, no exception | AC-01-2, AC-01-3 |
| T-01-06 | unit | Config file + env var + CLI flag setting the same key | CLI value wins; env beats file; file beats default | AC-01-4 |
| T-01-07 | unit | Config file with key `llvm_versionn` | Exit 2, error names the unknown key and the closest valid one | AC-01-5 |
| T-01-08 | unit | `--print-config` with layered sources | Dump shows effective values and the source of each | AC-01-4 |
| T-01-09 | adversarial | `GEMINI_API_KEY=sk-secret123`, logging at DEBUG, config dumped | The literal key value appears in no log record and not in `--print-config` output | AC-01-6 |
| T-01-10 | unit | Log record containing an inline `AIza…`-shaped token | Formatter replaces it with `***redacted***` | AC-01-6 |
| T-01-11 | unit | — | Every `ExitCode` member is referenced by at least one CLI path (guards drift) | AC-01-8 |
| T-01-12 | unit | `caudit scan .` with no compile-commands flag | Exit 2, message names the missing required flag | AC-01-8 |
| T-01-13 | unit | Simulated unexpected exception in a command | Exit 4, stderr carries a traceback id, no raw traceback dumped to the user | AC-01-8 |
| T-01-14 | integration | Real toolchain installed (`needs_clang`) | `doctor` finds real `clang-tidy`, parses its true version, exit 0 | AC-01-2 |
| T-01-15 | unit | Repo with a deliberate lint error, a type error, and coverage below the floor | `make check` fails on each independently; CI invokes the same target, so local and CI verdicts cannot diverge | AC-01-7 |
| T-01-16 | unit | Temporary tree seeded with one probe per untrackable category, plus a `.venv/`, an `inspiration_repos/` clone and a `.env`, with the real recipe run over it | `make clean` removes every generated probe and no preserved one; every top-level alternative of `UNTRACKABLE` is exercised by a probe, so a new guard category cannot go unclean; `clean` carries a `## ` string and so appears in `make help` | AC-01-9 |
| T-01-17 | unit | `tmp_path` reproducing the `tools/` layout with the shipped `load-env.sh`, and a `.env` holding a fake key | Sourcing exports the key, from the repo root and from a subdirectory; the value appears in no output; no `_caudit_*` variable outlives the call; `allexport` is restored as the caller had it; a missing, empty or malformed `.env` each return non-zero with an actionable message; executing rather than sourcing exits 64 rather than acting on a shell it does not own | AC-01-10 |

## Out of scope and risks

- No scanning, indexing, or reporting logic — later parts.
- **Risk:** the pinned LLVM major will age. Mitigation: the pin is a config value with a documented supported range, and `doctor` distinguishes "missing" from "outside supported range" so users can override deliberately.
- **Risk:** the PyPI `libclang` wheel and the system `clang-tidy` can drift apart in version, producing subtly different ASTs. Mitigation: `doctor` reports both and warns when the majors differ; the manifest records both.

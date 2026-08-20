# CLI, configuration, and operations

## Environment

- Supported runtime: Python `>=3.12,<3.13`.
- `make bootstrap` creates `.venv` and installs the project with development tools.
- Indexing uses the `libclang` wheel. Candidate generation additionally needs a
  compatible `clang`, `clang-tidy`, and Static Analyzer driver on `PATH`; run
  `.venv/bin/caudit doctor` for a precise report.
- The default LLVM major is configured as `llvm_version = "18"`; toolchain support
  is probed rather than assumed.

Consult the canonical [setup guide](../my_docs/guides/setup.md) for installation,
resource-directory, corpus, and API-key procedures.

## Configuration model

Precedence is fixed: **CLI `--set` > `CAUDIT_*` environment > TOML config file >
packaged defaults**. Unknown keys are errors, not ignored settings.

```bash
.venv/bin/caudit --print-config
.venv/bin/caudit --config caudit.toml --set retrieval.caller_depth=3 doctor
CAUDIT_TOKEN_BUDGET__PER_RUN=100000 .venv/bin/caudit doctor
```

- A TOML file may use a bare root table or `[caudit]` table.
- Environment nesting is `__`: `CAUDIT_MODELS__TRIAGE` maps to `models.triage`.
- Lists in environment values are comma-separated; boolean/int/float values are
  parsed according to their schema field.
- Policy versions (`prompt`, `retrieval`, `matching`) and models belong in config
  because they are recorded and must be comparable between runs.
- Secrets do not belong in `Config`. `GEMINI_API_KEY` (with `GOOGLE_API_KEY` fallback)
  is read from the runtime environment only and is never printed or logged.

## Scanning safely

A scan needs a real compilation database. C Audit will not infer include paths,
defines, compiler choice, or language standard.

```bash
.venv/bin/caudit scan /path/to/repo \
  --compile-commands /path/to/repo/build/compile_commands.json \
  --out /absolute/path/to/c_audit/caudit-report/run-1
```

For CMake projects, generate it with:

```bash
cmake -S /path/to/repo -B /path/to/repo/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Important scan options:

| Option | Effect |
| --- | --- |
| `--target PATH` | Restricts selected translation units without falsifying build-database coverage |
| `--allow-partial-coverage` | Explicitly proceeds below the configured coverage floor and records the gap |
| `--consent-cloud` | Allows selected/redacted evidence to reach the configured model for this run |
| `--remember-consent` | Records repository-local consent and implies `--consent-cloud` |
| `--dry-run-prompts` | Writes the exact assembled requests under `<out>/prompts` and sends nothing |

Use a unique output directory per run. The report output is disposable; never place it
inside a target repository and do not rely on it surviving `make clean`.

## Consent and privacy

- A key is insufficient to send source. Cloud consent is an independent, explicit
  condition; without it no provider object is constructed.
- `.env` is an optional local developer convenience, not an application input. Load it
  in the shell with `source tools/load-env.sh`; the application never calls dotenv.
- `.env` is secret material: do not add it, print it, or delete it as cleanup.
- Retrieval filters excluded paths before prompt construction and checks again
  afterward. Credential-shaped text is redacted and counted. Raw prompts/responses are
  not retained unless `llm.retain_raw` is explicitly enabled.

## Commands and outputs

| Command | Use |
| --- | --- |
| `caudit doctor` | Verify required toolchain components and versions |
| `caudit scan` | Run one repository pipeline and write artifacts |
| `caudit eval` | Score mini/CASTLE/Juliet/pairs benchmark inputs and hard gates |
| `caudit compare` | Compare like-for-like baseline and adjudicated run reports |
| `caudit ablate` | Run retrieval/budget ablation grid; always includes flat-window control |
| `caudit pairs` | Score vulnerable/fixed repository pairs from a pinned manifest |
| `caudit calibrate` | Check confidence labels against benchmark truth |

`scan` writes exactly:

- `report.md`: human report, with confirmed and needs-review sections kept separate;
- `results.sarif`: SARIF 2.1.0, with review items encoded so code-scanning systems do
  not count them as confirmed vulnerabilities;
- `run-manifest.json`: reproducibility and runtime facts, including configuration hash,
  policy/tool/model records, coverage, stage status, citations, and cost.

Exit codes are stable: `0` clean completed run, `1` findings/failed evaluation gate,
`2` usage or configuration error, `3` environment/input/run-availability issue, and
`4` internal error. A `scan` with review-required items only is not a confirmed-finding
exit, but a partial scan cannot exit `0`.

## Cleanup and protected paths

`make clean` removes generated caches/artifacts but preserves `.venv`, `.env`,
`audit-targets/`, and `inspiration_repos/`. Never broaden the cleanup targets casually:
the two repository directories are independent checkouts and `.env` cannot be safely
regenerated.

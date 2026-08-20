# Setup

> Last checked: 2026-08-14.

`caudit doctor` points here whenever a required component is missing. It
distinguishes **missing** from **outside the supported range**, so an
override is a decision rather than an accident.

## 1. Python environment

Python 3.12 is required. On Debian and Ubuntu the system pip is
[PEP 668](https://peps.python.org/pep-0668/) externally managed, so a
virtualenv is mandatory rather than merely advisable.

```bash
make bootstrap
```

That creates `.venv`, installs the package in editable mode with the dev
extras, and prints the next step. Everything below assumes `.venv/bin` is on
your `PATH` or that you prefix commands with `.venv/bin/`.

## 2. LLVM toolchain

Parts 01–06 run with **no Clang installed at all** — the default test suite is
offline and toolchain-free by construction, and indexing uses the `libclang`
wheel rather than a system LLVM. Parts 07 and later need a real toolchain,
because `clang-tidy` and `scan-build` are invoked as subprocesses.

The pinned major is `llvm_version` in configuration (default `18`), and the
supported range is that major through major + 2.

### Ubuntu and Debian

```bash
sudo apt-get update && sudo apt-get install -y clang-18 clang-tidy-18 clang-tools-18
```

`clang-tools-18` is the package that provides `scan-build`, the Clang Static
Analyzer driver. Distribution packages install versioned binaries
(`clang-18`, `clang-tidy-18`), so either add them to `PATH` under their plain
names or install the `update-alternatives` entries:

```bash
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100
sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-18 100
sudo update-alternatives --install /usr/bin/scan-build scan-build /usr/bin/scan-build-18 100
```

### Any distribution

The LLVM project publishes an installer script that adds its apt repositories:

```bash
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 18 all
```

### Using a different major

```bash
caudit --set llvm_version=19 doctor
```

or put it in a configuration file:

```toml
# caudit.toml
llvm_version = "19"
```

## 3. libclang

Indexing (part 06) uses the PyPI `libclang` wheel, which bundles its own
shared library. No system LLVM is needed just to index, and `make bootstrap`
already installed it.

`doctor` reports the wheel version alongside the system `clang-tidy` version
and warns when their majors differ — the two can produce subtly different
ASTs, and the run manifest records both.

### Clang's builtin headers

The wheel ships `libclang.so` and **nothing else** — no resource directory. A
translation unit that includes `<stddef.h>`, `<stdint.h>`, or anything that
pulls one in therefore fails to parse with:

```
'stddef.h' file not found
```

C Audit will not go looking for a resource directory on its own: that is an
include path, and guessing include paths is the one thing this MVP promises
never to do. The parse failure names the fix instead, which is to point at a
real toolchain's directory:

```bash
caudit --set index.resource_dir="$(clang -print-resource-dir)" scan . --compile-commands build/compile_commands.json
```

The setting is recorded, and the units that failed without it stay listed as
limitations rather than disappearing from the report.

### Indexing knobs

| Key | Default | What it does |
| --- | --- | --- |
| `index.jobs` | `0` | Worker processes; `0` means one per CPU, capped at the number of units |
| `index.per_tu_timeout_seconds` | `120` | Wall-clock ceiling per unit; exceeding it records a limitation naming the file |
| `index.in_process` | `false` | Parse in the main process — easier to debug, but nothing can interrupt a runaway parse, so no timeout applies |
| `index.resource_dir` | unset | Clang's builtin header directory, as above |
| `index.cache_dir` | unset | Where parsed units are cached; defaults to `<--out>/index-cache` |

The cache is keyed by the unit's flags and the content of every
in-repository file it read, itself included. A second scan of an unchanged
tree parses nothing; editing a header re-parses exactly the units that
include it. The index format version is part of that key, so upgrading C Audit
across a format change re-parses everything once rather than reading an older
layout as if it were the current one.

## 4. Compilation database

C Audit requires a valid `compile_commands.json` and will not guess include
paths or compiler flags. For a CMake project:

```bash
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

For Make-based projects, [Bear](https://github.com/rizsotto/Bear) can record
one:

```bash
bear -- make
```

Then:

```bash
caudit scan . --compile-commands build/compile_commands.json --out caudit-report
```

See the [Clang JSON compilation database

### Keeping audited repositories inside C Audit

The three housekeeping areas have different ownership and cleanup rules:

| Directory | Purpose | `make clean` |
| --- | --- | --- |
| `inspiration_repos/` | Read-only upstream projects used as design references | Preserved |
| `audit-targets/` | User-controlled repositories being scanned | Preserved |
| `caudit-report/` | Generated scan artifacts | Removed |

Create target checkouts manually. They remain independent Git repositories:

```bash
mkdir -p /home/vimdim/personal/c_audit/audit-targets
git clone \
  https://github.com/vimalselvarajan/Combat-Chess.git \
  /home/vimdim/personal/c_audit/audit-targets/Combat-Chess

cmake \
  -S /home/vimdim/personal/c_audit/audit-targets/Combat-Chess \
  -B /home/vimdim/personal/c_audit/audit-targets/Combat-Chess/build \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Use absolute input, compilation-database, and output paths so results always
land inside C Audit regardless of the shell's current directory:

```bash
cd /home/vimdim/personal/c_audit

.venv/bin/caudit \
  --set index.resource_dir="$(clang -print-resource-dir)" \
  scan /home/vimdim/personal/c_audit/audit-targets/Combat-Chess \
  --compile-commands /home/vimdim/personal/c_audit/audit-targets/Combat-Chess/build/compile_commands.json \
  --out /home/vimdim/personal/c_audit/caudit-report/combat-chess/scan
```

Use `/home/vimdim/personal/c_audit/caudit-report/combat-chess/dryrun` with
`--dry-run-prompts`, and
`/home/vimdim/personal/c_audit/caudit-report/combat-chess/adjudicated` with
`--consent-cloud`. Each output directory is a self-contained run.
specification](https://clang.llvm.org/docs/JSONCompilationDatabase.html) for
what the file must contain.

### What a scan writes

Three files land in `--out`:

| File | Contents |
| --- | --- |
| `report.md` | The human artifact: confirmed findings and items needing review under separate headings with separate counts, then coverage, exclusions and limitations. |
| `results.sarif` | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), validated against the official schema. Confirmed results are `kind="fail"`; review-required are `kind="review"` at `level="none"`, so a code-scanning system cannot count them as vulnerabilities. |
| `run-manifest.json` | Timestamps, tool versions and paths, the effective configuration and its hash, the source-region hash of every finding, per-stage timings, the run's total spend, and one record per configured model tier when a model stage participated. An empty `models` list is the claim that none did. |

`report.md` and `results.sarif` contain no timestamp, no duration and no
absolute path, so two runs of one revision produce byte-identical files and a
report diffs cleanly against the last one. Everything machine-specific is in
the manifest — including call counts and token totals, which is why a report
from a warm-cache run is identical to the cold run that filled the cache even
though the second made no calls.

Each finding renders a **why this rank** line: severity, confidence,
reachability, how many independent analyzers agreed, and how far the fix
reaches. Severity comes from the CWE family table capped by the impact kind,
not from anything a model wrote, so the ordering is auditable rather than an
opinion. `results.sarif` carries the same values under
`properties.rank`, `properties.rankExplanation` and
`properties.claimProvenance`.

The exit code distinguishes three outcomes that a count of zero cannot:

| Code | Meaning |
| --- | --- |
| `0` | The analyzers ran, every stage completed, and nothing was confirmed. |
| `1` | At least one confirmed finding. Review-required items alone do not raise it. |
| `3` | The scan could not run as described — a missing database, no analyzer available, or a stage that failed. The artifacts are still written, and the report opens by saying so. |

### When a stage fails

A run whose index, analyzers or model provider fails does not lose its report.
The stage is recorded in `run-manifest.json` with its status and duration,
`partial` becomes `true`, the report's title line reads `# C Audit report
(PARTIAL)`, and the SARIF invocation reports `executionSuccessful: false`. Every
candidate that had already been found is still in the report, and a partial run
never exits `0`.

A translation unit that will not parse is deliberately **not** a partial
report. It is counted in `coverage.translation_units_failed`, named in a
limitation, and printed in the coverage section — the index doing its job and
saying so. Partial is reserved for a stage that did not do its job.

### When intake refuses

`caudit scan` stops with exit code 3 when the database is missing,
unparseable, empty, or **materially incomplete** — defined as covering less
than `intake.coverage_floor` (default `0.60`) of the source files under the
repository root. The stop always prints the observed ratio, the floor, and the
files that had no build entry.

Two deliberate escapes, neither of them a default:

```bash
caudit scan . --compile-commands build/compile_commands.json --allow-partial-coverage
```

records the gap as a limitation in the report instead of stopping, and

```bash
caudit scan . --compile-commands build/compile_commands.json --target src/parser.c
```

narrows the scan; the remaining units are recorded as `not_selected` rather
than quietly dropped. Narrowing does not change the coverage ratio, which
measures the build description rather than the scan.

Third-party and generated code are excluded by default — vendoring
directories (`third_party/`, `vendor/`, `external/`, `node_modules/`, …),
generator filename conventions (`*.pb.cc`, `moc_*.cpp`, `ui_*.h`, …), and
generated-file banners in the first five lines. Opt back in explicitly:

```bash
caudit --set intake.include_third_party=true scan . --compile-commands build/compile_commands.json
```

Every opt-in in force is listed in the scan plan, so a report can say why it
looked at code the defaults would have skipped.

## 5. Gemini API key and cloud consent

The key is read from the environment at call time. It is never stored in the
repository, never written to a configuration file, and never logged —
redaction is enforced in `caudit.logging`, below every component that could
leak it. `GOOGLE_API_KEY` is accepted as a fallback.

```bash
export GEMINI_API_KEY='...'
```

### Keeping the key in a `.env`

Exporting by hand in every new shell gets old, so the key can live in a
project-local `.env` instead. **`caudit` does not read that file.** There is no
dotenv dependency and no `load_dotenv` call anywhere in `src/`; the shell
exports what the file contains and `caudit` reads the environment at call time,
exactly as above. The paragraph before this one is unqualified by what follows.

```bash
cp .env.example .env
```

Fill in `GEMINI_API_KEY`, then load it — once per terminal:

```bash
source tools/load-env.sh
```

The helper resolves the repository root from its own path, so it works from any
subdirectory. It reports *which* variable is set, never the value, and returns
non-zero if `.env` is missing, unfilled, or not valid shell. It must be sourced
rather than executed: a subprocess that sets a variable and exits has done
nothing.

If you would rather not use the helper, this is the whole of what it does:

```bash
set -a; source .env; set +a
```

To skip the per-terminal step entirely, [direnv](https://direnv.net/) loads a
directory's environment on `cd`. It is not installed by default and is not a
dependency of this project; with it, an `.envrc` containing `dotenv` is enough.

`.env` is gitignored, refused by `make guard` and by the `no-committed-secrets`
pre-commit hook, and never deleted by `make clean` — it is the one untrackable
path in the repository that no later run can regenerate. `.env.example` is a
different filename and stays tracked; it holds no key. If a `.env` ever does
reach a commit, treat the key as compromised and rotate it: removing the file
in a later commit leaves it in history.

A key on its own transmits nothing. Sending source to a hosted model
additionally requires explicit consent, and
consent is a component rather than a flag: the only class that can open a
socket takes the decision as a constructor argument. Grant it for one run:

```bash
caudit scan . --compile-commands build/compile_commands.json --consent-cloud
```

or record it for the repository, which writes `.caudit/cloud-consent.json`:

```bash
caudit scan . --compile-commands build/compile_commands.json --remember-consent
```

Deleting that file withdraws consent. Without either signal the scan still
runs, produces the deterministic baseline report, and records a limitation
saying no model looked at anything.

### Reading what would be sent

```bash
caudit scan . --compile-commands build/compile_commands.json --dry-run-prompts
```

Writes every assembled request body to `<out>/prompts/` and transmits none of
them. It runs the real assembly path — the same exclusion filtering, the same
credential scrubbing, the same second check — so the files are the requests,
not a rendering of them.

Two rules shape what lands there. A file matching `exclude_globs` is removed
before assembly and its absence is stated in the prompt without naming the
file. Credential-shaped strings — AWS key ids, PEM blocks, `password = "..."`
literals — are replaced with a labelled placeholder, and the count is recorded;
when the rewritten text is inside a function the model had to reason about,
that becomes a limitation on the finding, because the model then read something
the compiler never saw.

### Adjudication settings

| Key | Default | What it does |
| --- | --- | --- |
| `models.triage` / `.adjudication` / `.escalation` | see `--print-config` | Model ids. They live here, never in the code, and all three are recorded per run. |
| `policy_versions.prompt` | `2` | Which prompt templates are used. Part of the cache key, so changing it misses every cached response. Older versions stay on disk under `src/caudit/llm/prompts/`, so a run pinned to one sends the instructions it names rather than the current ones. |
| `llm.triage_enabled` | `true` | Run the cheap tier first. Disabling it sends every candidate straight to adjudication. |
| `llm.allow_escalation` | `true` | Permit the strongest tier. It fires only when a verdict is ambiguous *and* the impact is high. |
| `llm.max_attempts` | `3` | Attempts at a schema-valid response, with the validation error fed back between them. |
| `llm.max_transport_attempts` | `3` | Attempts at reaching the provider — rate limits and timeouts, counted separately. |
| `llm.backoff_seconds` / `.backoff_multiplier` | `1.0` / `2.0` | Wait before each transport retry. |
| `llm.cache_enabled` / `.cache_dir` | `true` / `<--out>/llm-cache` | Responses cache on the request's content. A repeated run over an unchanged revision costs nothing. |
| `llm.retain_raw` | `false` | Persist prompts and raw responses alongside the parsed result. Off by default; recorded in the manifest when on. |
| `llm.max_run_cost_usd` | unset | Stop calling once reported usage costs this much. |
| `llm.pricing.<tier>.input_per_million_usd` / `.output_per_million_usd` | `0.0` | Prices are configuration, because a vendor's catalogue is not this repository's to hard-code. A cost ceiling with no prices cannot bind, and the run says so. |

The cache stores a *fingerprint* of the prompt and the parsed result — not the
source, not the raw exchange. Its key covers the prompt, the model id, the
prompt version, and the schema version, so a change to any one of them misses.

### What the verification gate does with the answer

Nothing a model returns is a finding until it has been verified against the
scanned revision, and the verification consults no model. Every cited evidence
id has to have been issued to that candidate and still resolve; every quotation
has to be the bytes it claims to be, whitespace included; every asserted call
edge has to be in the compiler's call graph; and the claimed weakness has to
have its structural preconditions among the cited code — a use-after-free needs
a release site, an out-of-bounds *write* needs the write.

Two behaviours are worth knowing before reading a report:

- **A claim that outruns its evidence is weakened, not discarded.**
  `reachability="demonstrated"` with no control-flow evidence is reported as
  `argued`, the finding survives, and the change appears in its limitations as
  `claim_downgraded`. A real defect thrown away for over-claiming is a real
  defect nobody fixes.
- **A model's rejection does not delete a candidate.** It lands in **Needs
  review** with the model's argument attached, for a human to confirm the
  dismissal. The same is true of an inconclusive answer, and the two are
  separate reasons because "I disagree" and "I could not tell" are different
  answers.

Everything that failed is reported, not just the first thing, and `confidence`
comes from whether the citations resolved rather than from how sure the model
said it was.

Every finding also says **which producer stands behind which fact**: the
diagnostic and its location came from an analyzer, the surrounding function and
its types from the index, and the argument connecting them from the model. That
is one line per cited region plus a `**Provenance.**` summary, not a single
badge saying a model was involved somewhere.

## 6. Measuring the model against the baseline

The point of the evidence gate is that it can be measured. Score the analyzers
alone, then score the same suite with the model in the loop, then difference
the two:

```bash
caudit eval --suite mini --baseline --out runs/baseline
```

```bash
caudit --set cloud_consent=true eval --suite mini --no-baseline --out runs/adjudicated
```

```bash
caudit compare runs/baseline/metrics-mini.json runs/adjudicated/metrics-mini.json --out runs/comparison.json
```

`--no-baseline` sends source regions to a hosted model, so it refuses to run
without consent and a key rather than quietly falling back to the analyzers —
a run that finished and wrote a file labelled `adjudicated` containing the
baseline's numbers is the one measurement nobody could trust.

`compare` reports per-family and macro deltas, the two counts separately, and
what the adjudicated run cost beyond the baseline in calls, tokens, spend and
wall time. It refuses two runs scored under different matching or check-profile
versions, or over different cases, naming both values. The *prompt* version is
compared only when both runs had a model in them: an analyzer-only baseline
never assembled a prompt, and requiring one to match would refuse exactly the
comparison this is for. Anything it could not check — an unrecorded version, an
unrecorded case list — is printed as a caveat.

A comparison drawn from a run with a failing hard gate is printed and then
flagged: the spec makes the overall score valid only once the gates pass, and
`compare` exits non-zero in that case.

## 7. Verify

```bash
caudit doctor
make check
```

`make check` is the whole quality gate: ruff, mypy `--strict`, the schema
drift check, and pytest with an 85% coverage floor. CI runs the same target,
so a local pass and a CI pass cannot disagree.

It needs no Clang, no API key, and no network: adjudication is tested from
committed recordings in `tests/cassettes/`. The one test that calls the real
API is marked `needs_network` and deselected; run it with a key set:

```bash
.venv/bin/pytest -m needs_network
```

## Benchmark corpora

The mini suite is committed and needs nothing. Everything else is data this
repository does not ship, and each one is empty or absent on purpose rather
than by oversight:

| Corpus | State | What it needs |
| --- | --- | --- |
| `benchmarks/mini/` | committed, 6 cases | nothing |
| CASTLE, Juliet | fetched into a cache, `slow` only | a clone, per the adapter's message |
| `benchmarks/pairs/manifest.yaml` | **empty** | pinned SHAs and a build recipe confirmed to work per project |
| `benchmarks/maintainability/` | **no labels** | ≥2 independent human labellers per case |

The last two are why [my_docs/project/evaluation-results.md](../project/evaluation-results.md) reads
the way it does. Its tables are mostly "not run", and that is the honest state:
the harness for each is built and tested, and no number has been produced from
a corpus that does not exist. A manifest of unverified SHAs, or a label set one
person wrote, would look like evidence and be worse than nothing.

CASTLE and Juliet are fetched once into a cache directory and are only
exercised under the `slow` marker. Neither adapter will download anything on
its own; each raises with the exact command to run.

```bash
export CAUDIT_BENCHMARK_CACHE=/path/to/cache   # optional
git clone https://github.com/CASTLE-Benchmark/CASTLE-Benchmark "$CAUDIT_BENCHMARK_CACHE/castle"
```

Juliet C/C++ 1.3 is downloaded manually from
<https://samate.nist.gov/SARD/test-suites/112>; extract the pinned CWE
directories into `$CAUDIT_BENCHMARK_CACHE/juliet`.

## Removing the generated blobs from history

Not required to build or run anything. This is a one-off cleanup, written down
because the decision to defer it is easy to forget and the procedure is easy to
get wrong.

`bf28823` untracked the generated output; it removed nothing already committed.
The repository still carries, in history:

| | |
| --- | --- |
| Generated paths ever committed | 1008, across `f830911` and `64bfa65` |
| `.pyc` blobs | 216, **every one** embedding the build machine's absolute source path (`/home/<user>/…`) |
| Generated blob bytes | ~4.4 MB `__pycache__`, ~1.3 MB `.coverage`, ~0.6 MB `caudit-*/` |

Two consequences worth weighing before deciding it does not matter: every clone
pays for those bytes, and the build-machine username and directory layout are
published in a public repository.

### The procedure

Rewriting history changes every commit SHA on `main` and requires a force-push.
Do it when nobody else has work in flight against the remote.

`64bfa65` is 146 generated paths and no real ones, so it becomes empty and is
dropped: the history goes from 11 commits to 10. That is expected, not a
mistake. `inspiration_repos/` is stripped in the same pass — those entries are
mode-`160000` gitlinks with no `.gitmodules`, which is what made
`git submodule status` fail outright before they were untracked.

```bash
git bundle create ~/c-audit-pre-rewrite.bundle --all
```

```bash
pipx install git-filter-repo
```

Work in a **fresh clone**, never in the checkout you use. `git filter-repo`
refuses to run against a repository with linked worktrees, and rewriting the
one you are standing in leaves every worktree pointing at SHAs that no longer
exist.

```bash
git clone https://github.com/vimalselvarajan/C-Audit.git /tmp/c-audit-rewrite
```

The path expression is the `UNTRACKABLE` regex from the `Makefile`, so the
guard stays the single definition of what must never be tracked:

```bash
git -C /tmp/c-audit-rewrite filter-repo --invert-paths --path-regex '(^|/)__pycache__/|\.py[cod]$|^\.coverage|^caudit-(report|eval)/|^\.(pytest|mypy|ruff)_cache/|^\.hypothesis/|^htmlcov/|^inspiration_repos/'
```

A second pass is needed, and it is easy to miss. Deleting paths does not touch
*content*, so any blob that survives the first pass keeps whatever absolute
paths it contains — including earlier revisions of files that have since been
edited to remove them. Removing a string from the current version of a file
does nothing to the versions already committed.

```bash
printf 'literal:%s==>/home/<user>\n' "$HOME" > /tmp/replacements.txt
git -C /tmp/c-audit-rewrite filter-repo --force --replace-text /tmp/replacements.txt
```

`--force` is required only because the repository is no longer a fresh clone
after the first pass. Check what the replacement will touch before running it,
using the search in the next section: if the count is already zero, skip it.

### Verifying before pushing

The tree check is the one that matters. Nothing generated is tracked at `HEAD`
any more, so a correct rewrite is **invisible at the tip**: the two tree hashes
must be identical. A mismatch means something real was removed — stop.

```bash
git -C /tmp/c-audit-rewrite rev-parse HEAD^{tree}
```

Then confirm no blob still carries the build machine's absolute path. The
search is for `$HOME` rather than for `/home/`, because the paragraphs above
mention the placeholder form and would otherwise match themselves:

```bash
git -C /tmp/c-audit-rewrite rev-list --objects --all | awk '{print $1}' | git -C /tmp/c-audit-rewrite cat-file --batch-check='%(objecttype) %(objectname)' | awk '$1=="blob"{print $2}' | while read -r o; do git -C /tmp/c-audit-rewrite cat-file blob "$o" | grep -qa "$HOME/" && echo "$o"; done
```

That should print nothing. Then rebuild and run the gate in the rewritten
clone, which is the check that the rewrite removed only generated output:

```bash
cd /tmp/c-audit-rewrite && make bootstrap && make check
```

`filter-repo` removes the `origin` remote deliberately, so it goes back by
hand before the push:

```bash
git -C /tmp/c-audit-rewrite remote add origin https://github.com/vimalselvarajan/C-Audit.git
```

### The push, and the cleanup after it

Pin the lease to the SHA the remote is expected to be on, so a stale remote
aborts the push rather than clobbering someone else's work:

```bash
git -C /tmp/c-audit-rewrite push --force-with-lease=main:$(git rev-parse origin/main) origin main
```

Afterwards every existing checkout points at SHAs that no longer exist. Remove
the worktrees first — `git worktree remove` refuses less confusingly than a
reset does — then re-point the checkout:

```bash
git fetch origin && git reset --hard origin/main
```

Any other clone of this repository needs the same treatment, and a fresh clone
is usually less trouble than repairing one.

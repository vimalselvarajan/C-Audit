# Project gaps and credibility roadmap

> Current-state assessment, verified 2026-08-16. This is a boundary on the
> claims the project can support today, not a product pitch.

## Evidence we can claim today

C Audit has one encouraging result, and it is narrower than repository-scale
validation. In the published CASTLE run, Gemini adjudication improved the
analyzer-only result on the 110 cases inside C Audit's claimed scope:

| Metric | Analyzer only | With adjudication | Change |
| --- | ---: | ---: | ---: |
| Macro-F2 | 0.2290 | 0.2903 | +0.0613; **+26.8% relative** |
| False positives/KLOC | 13.665 | 5.797 | -7.868 |
| True positives | 23 | 28 | +5 |
| False positives | 33 | 14 | -19 |
| Citation resolution | 792/792 (100%) | 593/593 (100%) | no unresolved citations |

All four evaluation gates passed. The model did not create more candidates:
the 157 analyzer-generated candidates were held constant. It moved useful
candidates into the confirmed set while moving more noise into review. The
case-level results and scoring caveats are in the
[evaluation record](evaluation-results.md).

The six-case mini suite moved in the other direction: macro-F2 **0.6667 ->
0.5000**. That suite has no baseline false positives for a model to remove and
its two misses generate no candidates, so it is a useful regression test for
pipeline and policy changes, not legitimacy evidence. The regression is one
case where the model returned CWE-120 for an unbounded `strcpy`, while C
Audit's current allowlist expects a different in-scope mapping. It should stay
visible rather than be tuned away after the fact.

The strongest defensible public statement is therefore:

> In one run over the 110 CASTLE cases inside C Audit's claimed scope, Gemini
> adjudication improved macro-F2 by 26.8% relative, reduced false positives
> from 33 to 14, raised true positives from 23 to 28, and resolved every cited
> location. This is promising microbenchmark evidence, not proof of
> repository-scale effectiveness or generalization.

Six limitations keep that statement narrow:

- This is one published model run, with no repeat-to-repeat variance or
  uncertainty estimate.
- The CASTLE score covers 110 of 250 cases: 11 of the benchmark's 25 CWEs. The
  remaining 140 cases are outside the current claim, not successful tests.
- CASTLE and the mini suite are microbenchmarks. The
  [CASTLE paper](https://arxiv.org/abs/2503.09433) describes 250 compact,
  single-file C programs and itself distinguishes their value from the
  complexity of production-scale systems.
- Actual dollar cost is unknown. Tokens and wall time were recorded, but the
  configured price table was zero, so `$0.0000` means "not priced," not
  "free."
- The recorded model names use `*-latest` aliases. Google's
  [model-version documentation](https://ai.google.dev/gemini-api/docs/models)
  says those aliases are hot-swapped, while a stable ID points to a specific
  model that usually does not change.
- The summary is public, but the generated `caudit-eval/` and
  `caudit-report/` directories are ignored by [Git](../../.gitignore), and no
  machine-readable run bundle is tracked. The raw evidence behind the summary
  is therefore not yet durable or independently auditable.

One hundred percent citation resolution is important evidence that the gate
worked on these runs. It is not, by itself, evidence that every confirmed
finding is correct or that the tool found defects for which no analyzer
candidate existed.

## Ranked gaps

### 1. No completed held-out, repository-scale CVE evidence

There is no completed before/after result on a real vulnerable and fixed
repository pair, and no held-out result. That is the largest gap because it is
the experiment that tests real build systems, cross-file context, repository
noise, and whether a finding disappears at the fixing revision.

The current [pair manifest](../../benchmarks/pairs/manifest.yaml) pins a
**development** pair for libarchive/CVE-2024-20696, including full revisions,
a build recipe, affected paths, and manually reviewed truth lines. This is
active benchmark work, not completed evidence: the workspace contains no pair
outcome for it. Its first successful vulnerable/fixed run will establish one
development observation, not a held-out corpus and not repository-scale
generalization.

The documentation also needs reconciliation after that first successful run.
The current [pair procedure](../../benchmarks/pairs/README.md) and
[evaluation record](evaluation-results.md) still say the manifest is empty and
the pair suite has not run. Until a valid before/after artifact exists, "in
progress" is the accurate status; once it exists, those documents and this one
must be updated together.

### 2. Recall is bounded by analyzer-generated candidates

C Audit asks the model to adjudicate candidates emitted by its deterministic
analyzers. If no analyzer flags a site, no evidence bundle or model request is
created. CASTLE already exposes this ceiling: some vulnerable cases have no
candidate, so model quality cannot recover them. The current result shows that
adjudication can improve recall *within* the candidate set by classifying
previously review-only items, but it cannot widen the set. Any claim of broad
recall requires either additional candidate generators or a separately tested
proposal stage, followed by the same deterministic evidence gate.

### 3. Benchmark results are not yet statistically or operationally reproducible

The current results lack independent repetitions, confidence intervals, exact
stable model versions, priced runs, and a durable artifact bundle. Moving
model aliases make a later rerun a potentially different experiment, while
the absent price configuration prevents cost-effectiveness claims. A prose
table is useful for readers but insufficient for reanalysis.

### 4. Juliet and direct established-tool comparisons remain unrun

The Juliet adapter exists, but Juliet has not been fetched or run. NIST's
[Juliet C/C++ 1.3 suite](https://samate.nist.gov/SARD/test-suites/112) contains
64,099 cases across 118 CWEs, making a pinned, deterministic subset useful for
broader synthetic coverage. It still cannot replace real repositories.

C Audit also has no like-for-like result against established tools on the same
selected cases. Comparative claims must wait until identical revisions,
targets, configurations, and matching rules have been used for analyzer-only
C Audit, full C Audit, [CodeQL](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/c-cpp-built-in-queries),
and [Cppcheck](https://cppcheck.sourceforge.io/manual.html).

### 5. Maintainability claims are unmeasured and partly unrepresentable

There are no human labels, so maintainability has not been scored. The
[maintainability protocol](../../benchmarks/maintainability/README.md) correctly
requires at least two independent labelers and reports agreement. The current
finding-to-category bridge can represent `complexity`, `coupling`, and
`ownership_ambiguity`, but not `duplicated_validation` or `error_handling`.
The scorer refuses a macro-average when either unrepresentable category is
present. That refusal is honest; it also means no overall security-plus-
maintainability score or maintainability benefit should be claimed until the
schema can express all five categories and an independently labelled set has
been run.

### 6. Adoption remains developer-oriented

The working product is a local Python CLI. Setup requires a checkout, Python
3.12, Clang tools on `PATH`, and a valid `compile_commands.json`; the
[setup guide](../guides/setup.md) documents the process and the tool intentionally does
not guess missing build flags. The repository has its own
[quality CI](../../.github/workflows/ci.yml) and emits SARIF, but consumer-facing
CI packaging, PR annotations, and baseline-diff integration remain explicitly
post-MVP in the [implementation plan](../plan/12-ranking-and-e2e.md). There is no
tagged release or release workflow. This is usable by motivated developers,
not yet a polished install-and-enable path for teams.

### 7. Public trust needs artifacts, security documentation, and release hygiene

Security-relevant invariants are described throughout the design, including
consent, redaction, evidence validation, and failure handling. The repository
does not yet publish a focused threat model or `SECURITY.md`, and it has no
versioned benchmark bundle, changelog, tagged release, or automated release
pipeline. Before asking teams to submit private source to a hosted model, the
project should document trust boundaries, prompt-injection assumptions,
secret handling, retention and cache behavior, dependency/supply-chain risks,
supported versions, and a vulnerability-reporting process.

## Proof roadmap

The roadmap is cumulative: later claims depend on the earlier measurement
contract remaining frozen.

### 1. Freeze the experiment

- Replace all three `*-latest` aliases with exact stable Gemini model IDs and
  record those IDs in every run. Record any forced migration as a new policy
  version; do not pool results across it.
- Snapshot the applicable input, output, caching, and batch prices from
  Google's official [Gemini pricing](https://ai.google.dev/gemini-api/docs/pricing),
  including currency, billing tier, retrieval date, and thresholds. Configure
  those values so manifests report actual cost.
- Freeze the C Audit revision, corpus revisions, prompt/retrieval/matching/
  analyzer policy versions, Clang version, dependency lock or environment,
  operating system, hardware description, and cache policy.

### 2. Repeat CASTLE and publish uncertainty

- Run at least three cold-cache repetitions of the adjudicated configuration.
  Preserve every repetition rather than publishing only the best or last.
- Publish paired, case-level analyzer-only versus adjudicated deltas and 95%
  bootstrap intervals for macro-F2, precision, recall, and FP/KLOC. Keep
  confirmed and review-required outcomes separate and retain per-family
  results.
- Report two explicit CASTLE views: the 110-case claimed-scope view and an
  all-250 comparability view. The latter must show unsupported cases and
  coverage in its denominator rather than silently skipping them.

### 3. Add broad, deterministic synthetic coverage

- From NIST Juliet, select up to 20 vulnerable and 20 safe cases per supported
  CWE using a committed deterministic algorithm and seed. Publish the selected
  SARD IDs, suite hash, exclusions, build results, and good/bad pairing rules.
- Run the same frozen analyzer-only and adjudicated configurations. Use Juliet
  to expose family-level blind spots and regressions, not as a substitute for
  repository evidence.

### 4. Build development and held-out CVE corpora

- Build at least **10 development and 10 held-out vulnerable/fixed pairs**
  spanning at least **five repositories and four weakness families**. Keep the
  sets disjoint from selection onward and consult held-out pairs only after a
  policy version is frozen.
- Use full revision SHAs, reproducible build recipes, affected paths, reviewed
  truth locations, and recorded exclusions. Both revisions must build and scan
  before a pair enters a score.
- Use primary project advisories and commits for final verification.
  [CVEfixes](https://github.com/secureIT-project/CVEfixes), whose published
  dataset links CVEs to fixing commits and changed code at repository, file,
  and method levels, is an appropriate discovery source rather than an
  automatic ground-truth oracle.
- Publish detection at the vulnerable revision, persistence at the fixed
  revision, citation validity, coverage, tokens, latency, and actual cost.
  Report every exclusion and the number of held-out accesses.

### 5. Run like-for-like tool comparisons

- On the same CASTLE, Juliet, and CVE cases, compare analyzer-only C Audit,
  full C Audit, CodeQL, and Cppcheck. Pin each tool and ruleset version.
- Give each tool the same source revision and equivalent build information;
  publish exact commands and configuration. Define the line/CWE matching
  policy before running and apply it uniformly, while separately reporting
  findings a single-label corpus cannot adjudicate.
- Report absolute results and paired deltas. Do not claim that C Audit
  outperforms an established tool unless the held-out comparison and its
  uncertainty support that exact claim.

### 6. Publish a reproducible evidence bundle

For every public result, release a versioned, immutable bundle containing:

- corpus and selection manifests, pair partitions, per-case ground truth,
  outcomes, exclusions, and coverage;
- repository, source, corpus, prompt, configuration, and artifact hashes;
- exact commands, environment and tool versions, model IDs, pricing snapshot,
  and policy versions;
- analyzer outputs, structured adjudication outcomes, citation resolutions,
  and confirmed versus review-required records;
- per-call and aggregate latency, input/output/cache tokens, and actual cost;
- machine-readable summary tables plus the script that regenerates the public
  Markdown from those artifacts.

The release should carry checksums and a durable archive identifier. A reader
must be able to recompute the published tables without access to the original
developer machine or a mutable model alias.

### 7. Close the maintainability, adoption, and trust gaps

- Extend the schema so all five maintainability categories are representable,
  then create a versioned label set with at least two independent reviewers per
  case. Publish agreement, category macro-F1, nDCG@10, and recommendation
  accuracy/actionability separately.
- Ship a supported package and pinned release, a minimal consumer CI example,
  SARIF upload and baseline-diff guidance, and a release workflow that reruns
  the reproducibility checks.
- Publish a threat model, data-flow and retention description, `SECURITY.md`,
  support policy, changelog, release notes, and artifact checksums before
  presenting the tool as ready for organizational adoption.

## Claim gates

| Claim | Minimum evidence required |
| --- | --- |
| "Improves CASTLE performance" | Repeated frozen-model 110-case result with paired 95% intervals; all-250 view beside it |
| "Covers supported weakness families broadly" | Deterministic Juliet sample plus family-level coverage and error analysis |
| "Works on real repositories" | Development CVE-pair target met, with both revisions built and exclusions published |
| "Generalizes to unseen repository vulnerabilities" | Frozen-policy held-out CVE-pair target met, with access count and uncertainty published |
| "Outperforms CodeQL or Cppcheck" | Like-for-like held-out paired comparison against the named tool and version |
| "Improves maintainability" | All five categories representable and independently labelled results published |
| "Is cost-effective" | Stable model IDs, actual billing configuration, repeated cost/latency distributions, and a named comparator |
| "Is ready for team adoption" | Supported release and CI path, threat/security documentation, and reproducible evidence bundle |

Until those gates are met, the right posture is evidence-first: keep the
current CASTLE gain visible, keep the mini regression visible, and label every
repository-scale activity as in progress. Temporary lint or golden-test
failures from active development are intentionally not ranked here; they are
quality-gate work, not strategic evidence or product gaps.

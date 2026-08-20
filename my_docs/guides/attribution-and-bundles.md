# Attribution, repeated pilots, and evidence bundles

Track A asks a narrow question: what does C Audit add around the same cheap
Gemini model? The runnable matrix keeps the analyzer candidate set, corpus
revision, truth frame, exact model id, thinking level, and output limit fixed.

```bash
# Offline contract and artifact shape only.
.venv/bin/caudit attribute --suite mini --through A0 --out caudit-attribution

# A1-A5 transmit selected public/non-sensitive source after explicit consent.
.venv/bin/caudit attribute --suite castle --use-clang --through A5 \
  --consent-cloud --out caudit-attribution
```

The cumulative rows are:

- A0 analyzer-only promotion.
- A1 diagnostic plus a fixed +/-40-line window, without API-enforced JSON.
- A2 A1 plus a compact verdict schema.
- A3 structural retrieval and issued evidence identifiers, without verification.
- A4 A3 plus deterministic citation, quotation, call-edge, and CWE verification.
- A5 A4 plus compact triage and routing.
- A6/A7 are predeclared and marked deferred. The command refuses to fake them:
  bounded evidence tools are sequenced after the first six strategic changes.

Every selected row writes its own immutable run report. The matrix refuses a
candidate, corpus, revision, or truth-frame mismatch. A6/A7 leave-one-out rows
are also predeclared, but remain unmeasured until a real A7 exists.

The first repeated CASTLE pilot is analyzer-only, so it sends no source and
does not estimate Gemini variance:

```bash
.venv/bin/caudit pilot --repetitions 5 --seed 20260820 \
  --out caudit-castle-pilot
```

It selects one case per in-scope CWE and regenerates candidates into a fresh
directory five times. Every attempt, including a failure, is recorded. The
committed pilot summary is
[the stratified CASTLE control artifact](../../benchmarks/castle/results/analyzer-control-stratified-pilot.json).
Its five runs had identical candidate, corpus, and metric identities. That is
harness repeatability evidence only; an adjudicated repeated run still needs
explicit consent and a recorded quota/pricing snapshot.

Public artifacts can be packed into a byte-reproducible tar:

```bash
.venv/bin/caudit bundle \
  caudit-castle-pilot benchmarks/pairs/results benchmarks/castle/results \
  --root . --out benchmarks/bundles/strategic-sequence.tar
```

The generator sorts paths, normalizes tar metadata, writes SHA-256 and sizes
for every artifact, regenerates compact result tables, and verifies the
finished tar. It excludes source-bearing prompt, cache, workspace,
compile-command, and checkpoint directories. Identical inputs produce
byte-identical bundles.

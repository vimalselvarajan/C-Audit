# Repository pairs

Real vulnerable/fixed revisions of real projects. The strongest evaluation
signal C Audit has, because it needs no hand-labelling: scan the same project
at the revision that had the defect and at the revision that fixed it. A
detection that appears in the first and disappears in the second is real. One
that survives the fix is a **false positive with a known answer**.

`manifest.yaml` is currently empty, and that is a statement rather than an
oversight. Filling it means cloning each repository, checking out both
revisions, running the build recipe, and confirming it produces a usable
compilation database. None of that has been done here — the development machine
has no Clang and no network access to these projects — and a manifest of
plausible-looking SHAs nobody has ever checked out would be worse than an empty
one: it would look like evidence.

The harness that consumes this file is built and tested
(`src/caudit/eval/pairs.py`, `tests/unit/test_eval_pairs.py`). What is missing
is the data.

## Adding a pair

1. Find a CVE-linked fix commit — [CVEfixes](https://github.com/secureIT-project/CVEfixes)
   is the usual starting point — in a C or C++ project that builds with CMake
   or produces a compilation database some other way.
2. Record the **parent** of the fix commit as `vulnerable_rev` and the fix
   itself as `fixed_rev`, both as full SHAs. A tag or a branch would let the
   pair change underneath a recorded result.
3. Write the build recipe. It runs from the checkout root and must leave a
   compilation database where `compile_commands` says. Name the packages it
   needs in `requires`, so a failure can say what was missing rather than only
   that a command exited non-zero.
4. List `affected_paths` — the files the fix touched. A detection outside them
   at the vulnerable revision is not evidence that this pair was detected.
5. Put it in `development` unless you are deliberately growing the held-out
   set. The two are disjoint, enforced by `PairManifest`'s validator and by
   T-13-04.

```yaml
version: "1"
pairs:
  - pair_id: example-cve-2021-0000
    repo_url: https://github.com/example/project
    vulnerable_rev: 0123456789abcdef0123456789abcdef01234567
    fixed_rev: 89abcdef0123456789abcdef0123456789abcdef
    cve: CVE-2021-0000
    cwe: CWE-787
    pair_set: development
    affected_paths:
      - src/parser.c
    build_recipe:
      steps:
        - cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
      compile_commands: build/compile_commands.json
      requires: [cmake, ninja]
```

## The held-out set

Held-out pairs are used **once per finalized policy version**, and every access
is recorded in the ledger `HeldOutLedger` maintains. A second access under the
same policy version warns and is still recorded, because refusing would block a
legitimate re-run after a crash and the workaround would be to delete the
ledger. The count belongs in any published result: a held-out set consulted
five times is a development set with a more reassuring name.

## What is never done here

- A pair is never dropped for failing to build. It is excluded **with a
  reason**, and excluded pairs appear in neither the numerator nor the
  denominator of any rate.
- Results are never pooled across policy versions. Each outcome records the
  versions it was produced under, and `score_pairs` raises rather than
  averaging two different tools.

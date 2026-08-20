# The labelled maintainability set

The spec scores maintainability at 50% of the overall number, and defines it
for the report-only MVP as identifying and explaining **security-relevant
maintenance hazards** across five categories: complexity, duplicated
validation, ownership ambiguity, coupling, and error handling.

`labels.json` does not exist yet, and `load_labels` treats its absence as an
empty set rather than an error. That is deliberate. This set is human work — it
cannot be generated, and generating it would defeat its purpose twice over.

## The two rules, and why they are code rather than prose

**At least two independent labellers per case.** `MaintainabilityLabel`
refuses a case naming fewer than two *distinct* labellers. A single-labeller
set measures one person's taste and reports it as a benchmark; the agreement
statistic is published beside the scores rather than kept as a footnote,
because a set with 60% agreement and a set with 95% agreement support very
different claims.

**Labels are not derived from `clang-tidy` output.** The loader rejects a label
whose `source` names an analyzer this project runs. Adjudicating labels from
the tool's own checks scores the tool against itself — the spec names this trap
directly, and this is the one place the rule can be made checkable instead of
merely intended.

A disagreement is allowed, but it has to be adjudicated *and written down*:
`agreed: false` with no `adjudicator_note` is refused, because a label with a
hidden third opinion in it is not a label anyone can audit later.

## Format

```json
{
  "version": "1",
  "labels": [
    {
      "case_id": "openssl-bn-ownership",
      "category": "ownership_ambiguity",
      "path": "crypto/bn/bn_lib.c",
      "line": 412,
      "labelers": ["alice", "bob"],
      "agreed": true,
      "source": "manual review of the allocation and free paths"
    }
  ],
  "verdicts": [
    {
      "case_id": "openssl-bn-ownership",
      "accurate": true,
      "actionable": false,
      "reviewer": "carol",
      "note": "Correct about the double ownership; the suggested fix would need the caller changed too."
    }
  ]
}
```

`accurate` and `actionable` are two booleans rather than one score because they
fail independently: advice can be perfectly correct and impossible to act on,
and a plausible-sounding action can be wrong about the code. Which one failed
is the part worth knowing.

## What the predictor can and cannot name

Worth reading *before* labelling, because it changes what a label buys you.

Scoring needs a category per case from the tool as well as from you, and
`predict_category` supplies it from two signals: the weakness family, and the
span of the finding's verified citations. That reaches three categories.

| Category | How the tool reaches it |
| --- | --- |
| `ownership_ambiguity` | A `memory_lifetime` weakness — use-after-free, double-free. The defect *is* an ownership question |
| `coupling` | Citations in more than one file |
| `complexity` | More than one cited region inside one file |
| `duplicated_validation` | **Nothing reaches it.** No signal in the current schema |
| `error_handling` | **Nothing reaches it.** Same |

Two consequences for a labelling session:

- A case you label `duplicated_validation` or `error_handling` is not wasted,
  but it will not be scored. It makes `macro_f1` come back as `None` with the
  category named, rather than as a low number — the tool cannot be graded on a
  category it has no way to express, so it declines to be. Closing that gap
  needs a model-facing hazard field, which means a prompt version bump.
- The tool abstains on resource leaks rather than guessing. A leak is genuinely
  ambiguous between "nobody owns the close" and "the close is skipped on the
  error path", and the family table refuses to pick. If your labelling turns up
  a consistent answer across many real leaks, that is evidence worth bringing
  back to `_CATEGORY_BY_FAMILY`.

## Scoring

Three numbers, reported together and never averaged:

| Metric | Question it answers |
| --- | --- |
| Category macro-F1 | Did we name the right hazard? |
| nDCG@10 | Did we put the important ones first? |
| Useful-recommendation rate | Was the advice accurate *and* actionable? |

`MaintainabilityScore` has no combined field and no method that averages them,
for the same reason `Metrics` has no `total_findings`: a single number is the
one everybody quotes and nobody can act on.

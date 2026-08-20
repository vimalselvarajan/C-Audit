# Change playbooks and boundaries

## Before editing

1. Identify the relevant plan part in [`my_docs/plan/`](../my_docs/plan/00-overview.md)
   and read its interfaces, invariants, acceptance criteria, and test table.
2. Locate the owning capability package from the [code map](02-code-map-and-dependencies.md).
3. Read the nearest unit and integration tests before changing public behavior.
4. Inspect `git status` and preserve unrelated work. Do not modify target or inspiration
   repositories unless the task explicitly authorizes it.

## Playbook: model or schema change

1. Change the immutable Pydantic contract in `model/` and add validators at the
   earliest trustworthy boundary.
2. Update every producer, consumer, fallback path, and serializer explicitly; do not
   rely on unknown-field tolerance because models forbid it.
3. Regenerate schemas with `make schemas` and run `make schema-check`.
4. Update model, report, SARIF, manifest, and golden tests as needed.
5. If a JSON/schema shape changed, consider whether `SCHEMA_VERSION` must change.

## Playbook: add a verification rule

1. Put evidence/claim checking in `verify/`, not in a renderer or prompt parser.
2. Check all applicable facts and return all actionable failures in stable order.
3. Decide whether the rule is a safe downgrade or a blocking review reason. Do not
   discard candidates.
4. Keep the gate model-free and constrained to the exact scanned/captured evidence.
5. Add unit tests plus adversarial cases for fabrication, stale evidence, and the
   fallback review item.

## Playbook: change retrieval or model prompting

1. Preserve full decisive code units and the capture-before-selection policy.
2. Make new knobs configuration, validate them, and record their policy version if they
   affect outcomes.
3. Count prompt instructions/schema and source against the same budget; do not trim
   primary code to squeeze in a call.
4. Keep no-consent and dry-run paths network-free; ensure exclusions/redaction are
   applied before and after assembly.
5. Use cassettes/fixtures to test routing, retries, redaction, budget exhaustion, and
   schema-invalid responses deterministically.

## Playbook: add an analyzer or change normalization

1. Keep raw analyzer adapters format-specific; normalize into `Candidate` at the shared
   boundary.
2. Retain exact tool/version/rule provenance and analyzer flow/note ordering.
3. Do not silently ignore unavailable checkers, timeout output, or diagnostics outside
   the repository. Report limitations and coverage gaps.
4. Reconsider deduplication only with fixtures that prove independent provenance and
   distinct defects are handled correctly.
5. Keep the profile/version manifest value aligned with the behavior actually run.

## Playbook: change scan/report behavior

1. Make decisions in `application/` or `finding_policy/`; render them in `report/`.
2. Preserve three artifacts and their division: deterministic human/SARIF output versus
   machine-specific manifest facts.
3. Keep confirmed and review-required counts/sections separate. Preserve stable sorting
   and canonical output paths.
4. Revisit exit-code behavior and partial-run semantics; zero findings must never hide
   no analysis, an unavailable analyzer, or a failed stage.
5. Update unit, integration, SARIF contract, golden, and end-to-end tests appropriate
   to the visible change.

## Non-negotiable boundaries

- Never infer build flags, include directories, macro definitions, standards, or a
  compilation database.
- Never send bytes to a provider without explicit consent, and never persist raw
  prompts/responses by default.
- Never turn malformed model prose into a finding.
- Never let a model remove an analyzer candidate.
- Never merge confirmed and review-required populations into one “total findings”
  number.
- Never claim a source quote after normalizing it, a symbol after a text-only match, or
  a call edge merely because its endpoints exist.
- Never edit or clean `audit-targets/`, `inspiration_repos/`, `.env`, or generated
  outputs unless the requested scope specifically includes that action.
- Never pool scores across policy versions or hide excluded benchmark cases.

## Completion checklist

- [ ] Focused tests cover the changed branch and its failure/fallback behavior.
- [ ] `make schema-check`, `make docs-check`, or `make architecture-check` ran when
      the change touches their scope.
- [ ] Broader `make check` was run when practical, or any pre-existing/unrelated
      failure is stated clearly.
- [ ] Generated artifacts and secrets are not staged.
- [ ] Canonical docs/plan/results are updated if the implementation changed a public
      contract, workflow, or measured claim.

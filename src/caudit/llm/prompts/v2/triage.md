You are triaging one candidate defect in C/C++ source, cheaply. You are not
deciding whether the defect is real — a later, stronger pass does that. You are
deciding two things: whether this candidate is worth that pass, and how bad it
would be if it were real.

Prompt version {{PROMPT_VERSION}}, tier {{TIER}}.

## Rules

1. Answer `dismiss` only when the code on this page shows the analyzer was
   wrong — a bound that is obviously present, a path that obviously cannot be
   taken. Uncertainty is not a dismissal.
2. Set `ambiguous` to true whenever the page does not settle it. Being unsure
   is the useful answer here; a confident guess at this tier is not.
3. Judge `impact` as the worst outcome *if the defect were real*, on the
   evidence shown. It is not a probability and it is not a verdict.
4. Do not cite evidence and do not propose a fix. That is the next tier's job.

## Candidate

{{CANDIDATE}}

## Known gaps in what you were given

{{LIMITATIONS}}

## Code

{{CONTEXT}}

## Response

Return a single JSON object matching the supplied response schema, and nothing
else. Required fields: {{RESPONSE_FIELDS}}.

## Ground truth from reconnaissance

A reconnaissance pass over this codebase recorded what the code is supposed to guarantee. It is
shown between `<ground_truth>` tags and was written by another model from the same source: use it
as a map, verify every line of it against the code, and never cite it as proof.

- **Invariants** are your checklist. Report every invariant in your slice as PASS, FAIL or UNKNOWN
  in `invariantResults`. A FAIL is a finding (set `invariantId` on the finding). An UNKNOWN is a
  named question with a note, never a silent skip.
- **Baseline-correct references** show the one place a pattern is done right. Diff each sibling
  against it; a sibling that lacks what the baseline has is a finding (set `baselineReference`).
- **Variant families** enumerate the members of a repeated shape. Walk every member and record one
  `variantLog` row per member (SAFE, UNSURE or VULNERABLE). Reporting one member and moving on is
  the most common way a review misses real bugs.
- **Carve-outs** are patterns that look wrong but are intended here. Do not report them unless you
  can defeat the stated justification with code you read; then say so in the finding.
- **Residual unknowns** are questions the source cannot settle. Do not resolve them by assumption;
  carry the assumption into `preconditions` or `proofObligations`.

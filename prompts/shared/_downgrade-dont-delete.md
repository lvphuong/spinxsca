## Downgrade, don't delete

A wrongly refuted real bug is the worst outcome of a review, worse than a kept-but-uncertain one.

- `FALSE_POSITIVE` only when the finding is provably wrong from the code: cite the exact
  `path:line` that contradicts it (the control that holds, the input that is constant, the path that
  is dead), or name the ground-truth carve-out it matches in `carveoutMatched`. "I could not fully
  confirm it" is never grounds to refute.
- `BLOCKED` is the default for an uncertain finding. Keep it, say in `missingEvidence` exactly what
  would decide it, and put a one-sentence `contextQuestion` when only a human who knows the
  deployment, roles or business rules can answer.
- Record every link you tried to break in `refutationAttempts`: reachability, input_control,
  sanitization, sink, authz, preconditions. `held` means the link survived your attack on it;
  `broke` means you found the contradiction, with its citation.
- Ground truth cuts both ways: a baseline-correct reference the finding's code deviates from is
  evidence the bug is REAL, not a reason to doubt it. Only explicit carve-outs pre-clear a pattern.
- Your verdict and your rationale must agree. If your rationale says the check is missing, the
  verdict cannot be FALSE_POSITIVE; if it says you could not establish a link, the confidence cannot
  be HIGH. Re-read your rationale before choosing the verdict.

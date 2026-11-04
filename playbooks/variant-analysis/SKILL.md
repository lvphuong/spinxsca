---
name: variant-analysis
description: "Variant hunting from a confirmed finding with a validated Semgrep rule."
allowed_tools: [semgrep_rule, read_file]
categories: [SQL_INJECTION, COMMAND_INJECTION, PATH_TRAVERSAL, XSS, SSRF, BROKEN_OBJECT_LEVEL_AUTHORIZATION]
---
# Variant hunting from a confirmed finding with a validated Semgrep rule.

1. Describe the seed precisely: the sink call, how the tainted value is built, and the missing control.
2. Write a rule that matches the seed (give `seed` so the host checks it): start from `pattern` on the sink with metavariables, add `pattern-inside` for the function context, `pattern-not` for the safe form. Prefer `mode: taint` with `pattern-sources` on request objects when the flow spans statements.
3. Run it on the whole snapshot (no `paths`), then refine until the matches are plausible; at most five rules per call.
4. A match is a lead: read each one and report only those whose path you establish. Every reported variant is validated independently.
5. Record the final rule in the journal so a human can promote it to the rule bundle.

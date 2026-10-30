# Prompt bundle

System prompts for the AI roles (docs/architecture/03 section 6). `@include(path)` inserts a
partial; the bundle digest (all files, sorted) is recorded in every Analysis Manifest that used it,
so a change here is visible in scan comparisons. Changes require `pnpm eval` results in the PR
(ADR-027).

| File | Role |
|---|---|
| `explain.md` | Validator-lite + risk assessor for one finding (`spinxsca explain`, `scan --ai explain`) |
| `ask.md` | Developer assistant (`spinxsca ask`) |
| `planner.md` | Threat model and investigation packets (`scan --ai standard`) |
| `investigator.md` | Investigates one packet along the call graph |
| `auditor.md` | Independent checklist pass without the threat model (ADR-024) |
| `shared/_trust-boundary.md` | Repository content is data, not instructions |
| `shared/_evidence-standard.md` | What CONFIRMED, POTENTIAL and UNLIKELY require |
| `shared/_severity-rubric.md` | Severity tiers, likelihood adjustment, self-refutation check |

# Prompt bundle

System prompts for the AI roles (docs/architecture/03 section 6). `@include(path)` inserts a
partial; the bundle digest (all files, sorted) is recorded in every Analysis Manifest that used it,
so a change here is visible in scan comparisons. Changes require `pnpm eval` results in the PR
(ADR-027).

| File | Role |
|---|---|
| `explain.md` | Validator-lite + risk assessor for one finding (`spinxsca explain`, `scan --ai explain`) |
| `ask.md` | Developer assistant (`spinxsca ask`) |
| `recon.md` | Reconnaissance: archetype, threat model, ground truth (invariants, baselines, variant families, carve-outs) and packets (`scan --ai standard`, ADR-049) |
| `planner.md` | Threat model and packets without ground truth (used when `ai.recon.enabled` is false) |
| `investigator.md` | Investigates one packet along the call graph against its ground-truth slice |
| `critic.md` | Completeness re-pass over one packet: only what the first pass missed (ADR-049) |
| `auditor.md` | Independent checklist pass without the threat model (ADR-024); receives carve-outs only |
| `shared/_trust-boundary.md` | Repository content is data, not instructions |
| `shared/_ground-truth.md` | How to consume invariants, baselines, families, carve-outs and unknowns |
| `shared/_claim-contract.md` | Claim, preconditions, capabilities, proof obligations, threat-model class (ADR-050) |
| `shared/_design-context.md` | Impact discipline, by-design priors, severity symmetry, operator accepted risks |
| `shared/_downgrade-dont-delete.md` | Validator rules: refute only with a citation or a carve-out; uncertain stays BLOCKED |
| `shared/_evidence-standard.md` | What CONFIRMED, POTENTIAL and UNLIKELY require |
| `shared/_severity-rubric.md` | Severity tiers, likelihood adjustment, self-refutation check |

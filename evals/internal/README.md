# Internal evaluation suite

Each case directory has a `case.yaml` (ground truth, schema `EvalCase` in packages/schemas) and the
source to scan. Dependency cases are matched against the curated knowledge base in
`evals/fixtures/osv/`, imported as authoritative for npm, PyPI and Maven so results never depend on
the live OSV database. Run with `pnpm eval`.

| Case | Layer | Phase |
|---|---|---|
| 001 SQL injection (Express) | sast | 0 |
| 002 XSS (React) | sast | 0 |
| 003 IDOR (NestJS) | ai | 2 (pending) |
| 004 secure code, negative control | all | 0 |
| 005 lodash advisories (npm) | sca | 1 |
| 006 command injection (Flask) | sast | 0 |
| 007 hardcoded secrets | secrets | 1 |
| 008 Dockerfile misconfiguration | iac | 1 |
| 009 path traversal (Express) | sast | 1 |
| 010 SSRF (Express) | sast | 1 |
| 011 requests advisories with aliases (PyPI) | sca | 1 |
| 012 log4j-core advisories (Maven) | sca | 1 |

The secrets in case 007 are fabricated generic values. Provider-formatted tokens are avoided on
purpose so pushing this repository does not trigger push protection.

Thresholds stay at `phase: 1`: case 003 (IDOR) is detectable only by the AI investigation roles,
which the evaluation runs with a scripted provider in CI. Run `pnpm spinxsca eval --ai standard
--ai-provider anthropic` with credentials to grade it with a real model.

# spinxsca Semgrep rule bundles

Rules here are executed by the Semgrep adapter inside a network-less container (ADR-021), so they
must be self-contained. Each bundle directory is versioned by the sha256 of its rule files and the
digest is frozen into every scan's Analysis Manifest.

Rule metadata conventions:

```yaml
metadata:
  cwe: ["CWE-89: ..."]          # at least one CWE
  confidence: HIGH | MEDIUM | LOW
  spinxsca:
    category: SQL_INJECTION     # packages/schemas/src/taxonomy.ts
    family: sqli                # groups equivalent rules across scanners
    title: Short finding title
```

Every rule has a test target next to it with `ruleid:` / `ok:` annotations. Run `pnpm rules:test`.
Third-party registry rulesets (for example `p/default`) are not vendored here because the Semgrep
Rules License restricts redistribution in competing products; enabling them is a phase 1 decision.

---
name: deps-npm
description: "npm dependency applicability."
allowed_tools: [deps_reachability, kb_lookup]
categories: [VULNERABLE_DEPENDENCY, PROTOTYPE_POLLUTION]
---
# npm dependency applicability.

1. Check the installed version from the lockfile against the advisory's affected range; a package can appear several times at different versions.
2. Name the vulnerable functions (for lodash: `template`, `zipObjectDeep`, `merge`, `defaultsDeep`, `toNumber`/`trim` for ReDoS; for minimist: argument parsing of untrusted argv) and call `deps_reachability` with them.
3. Read each call site: is the argument attacker-controlled? `template` on a constant string is not exploitable.
4. devDependencies used only by build or test tooling are LOW unless the tool processes untrusted input in CI.
5. The fix is the smallest version that resolves the advisory; transitive packages may need an override or a parent upgrade.

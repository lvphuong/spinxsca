---
name: deps-maven
description: "Maven dependency applicability."
allowed_tools: [deps_reachability, kb_lookup]
categories: [VULNERABLE_DEPENDENCY]
---
# Maven dependency applicability.

1. Resolve the version, including properties and dependency management; `provided` and `test` scopes do not ship.
2. Know the vulnerable feature: log4j-core JNDI lookups in logged user input (2.0-beta9 to 2.14.1), Jackson polymorphic typing, SnakeYAML `new Yaml()` constructors, Spring `DataBinder` on class loaders.
3. Check imports of the affected packages and whether the vulnerable feature is configured (lookups disabled, default typing off, safe constructors).
4. A KEV-listed advisory reachable from request handling is CRITICAL.

---
name: insecure-defaults-fail-open
description: "Insecure defaults and fail-open controls: a security check that silently allows when it cannot decide."
allowed_tools: [read_file, search_code, auth_context, resource_matrix, data_access_sites]
categories: [MISSING_AUTHENTICATION, MISSING_AUTHORIZATION, INSECURE_CONFIGURATION]
---
# Insecure defaults and fail-open controls

1. Read every authentication and authorization control body, not its name (`auth_context` lists
   them). Follow each error path: a `catch` that calls `next()` or returns `true`, a missing
   `return` after `res.status(401)`, a token verification whose failure only logs, a policy lookup
   that defaults to allow when the policy is missing, an `if (!config.auth) skip`.
2. Enumerate security-relevant defaults: `authEnabled: false`, `allowAnonymous: true`, an empty
   allow-list meaning "allow all", a missing `issuer`/`audience` check, `algorithms` left open
   (`none`), CORS `*` with credentials, debug or metrics endpoints registered unconditionally.
3. Decide fail-closed vs fail-open for each: a control that cannot evaluate (dependency down,
   configuration absent, parse error) must deny. The one that allows is the finding, rated by the
   control it defeats (severity symmetry), even when a default deployment sets the option.
4. Check mounting order: middleware registered after the routes it should protect, a router
   mounted before the global guard, a route added by a plugin outside the guarded prefix.
5. Distinguish by-design: a documented dev-only server or a component disabled by default is a
   LOW note unless the code shows it is reachable in a normal deployment. `live_only` in evals when
   the oracle needs a failing dependency; static when the fall-through is in the code.

---
name: authn-session
description: "Authentication and session weaknesses on reachable routes."
allowed_tools: [read_file, search_code, auth_context]
categories: [MISSING_AUTHENTICATION, CSRF, WEAK_CRYPTO, INSECURE_RANDOMNESS]
---
# Authentication and session weaknesses on reachable routes.

1. Find routes without authentication middleware that expose data or state changes; check global middleware order and route mounts before concluding.
2. JWT: algorithm pinned (`algorithms: [...]`), signature verified (not `decode`), secret not hardcoded, expiry checked.
3. Sessions: cookies `HttpOnly`, `Secure`, `SameSite`; regeneration on login; logout invalidates server-side.
4. Password storage: bcrypt/scrypt/argon2 with cost; never fast hashes. Reset tokens: random, single use, expiring.
5. CSRF: state-changing routes using cookie auth need a token or `SameSite=strict/lax` plus method checks.

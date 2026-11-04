---
name: ssrf
description: "Server-side request forgery: input controls where the server sends a request."
allowed_tools: [read_file, search_code]
categories: [SSRF, OPEN_REDIRECT]
---
# Server-side request forgery: input controls where the server sends a request.

1. Sinks: `fetch`/`axios`/`http.request`/`got`, `requests.*`, `urllib`, `HttpClient`, image or PDF renderers that load URLs, webhooks, XML parsers with external entities.
2. Trace the URL, host or path to request data or stored user configuration (webhooks are stored SSRF).
3. Controls that count: an allow-list of hosts checked after DNS resolution, blocking private, loopback and link-local ranges (169.254.169.254), disabling redirects or re-checking each hop, a fixed scheme. String prefix checks on the URL are bypassable.
4. Impact: cloud metadata credentials and internal admin services make it HIGH or CRITICAL; a fixed host with a user-controlled path is usually lower.

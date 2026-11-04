---
name: xss
description: "Cross-site scripting: untrusted data rendered as HTML or script without context-aware encoding."
allowed_tools: [read_file, search_code]
categories: [XSS]
---
# Cross-site scripting: untrusted data rendered as HTML or script without context-aware encoding.

1. Sinks: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`, `res.send` of HTML built with strings, templates with unescaped output (`{{{ }}}`, `|safe`, `<%- %>`, `th:utext`), `href`/`src` attributes accepting `javascript:`.
2. Framework templates escape by default; find where escaping is turned off or bypassed.
3. Trace the value to request data or stored user content (stored XSS has wider reach).
4. Controls that count: framework escaping in the right context, a vetted sanitizer (DOMPurify) with a strict config, Content-Security-Policy without `unsafe-inline` (mitigation, not a fix).
5. Severity depends on whose browser runs it (admin panels raise it) and what the session can do.

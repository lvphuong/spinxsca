---
name: deps-pypi
description: "PyPI dependency applicability."
allowed_tools: [deps_reachability, kb_lookup]
categories: [VULNERABLE_DEPENDENCY]
---
# PyPI dependency applicability.

1. Normalise the name (case, `-`/`_`) and map it to its import name (`PyYAML` → `yaml`, `python-jose` → `jose`).
2. Find the vulnerable API in the advisory (for requests: proxy credential leakage, `verify=False` defaults; for PyYAML: `load` without `SafeLoader`; for Jinja2: sandbox escapes).
3. `deps_reachability` with those functions, then read the call sites and the data they receive.
4. Packages pinned only in requirements-dev or test extras are LOW when not imported by application code.

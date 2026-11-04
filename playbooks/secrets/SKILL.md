---
name: secrets
description: "Hardcoded secrets: real credentials in code, configuration or history."
allowed_tools: [read_file, search_code]
categories: [HARDCODED_SECRET]
---
# Hardcoded secrets: real credentials in code, configuration or history.

1. Decide whether the value is real: placeholders (`changeme`, `xxx`, `<token>`), documentation examples, public keys and test fixtures are not credentials. High entropy assigned to a credential-like name in shipped code is.
2. Identify what it unlocks from the name and the code that uses it (database, cloud account, payment API, signing key).
3. Exposure: committed to git (history keeps it), shipped in a client bundle or image, logged.
4. Recommend rotation first, then moving it to a secret manager or environment, then purging history if required.
5. Never print, test or reconstruct the value.

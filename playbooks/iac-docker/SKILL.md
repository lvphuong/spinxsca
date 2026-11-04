---
name: iac-docker
description: "Container and deployment configuration."
allowed_tools: [read_file, list_files]
categories: [INSECURE_CONFIGURATION, HARDCODED_SECRET]
---
# Container and deployment configuration.

1. Runtime user: a final stage without `USER` runs as root; check the stage that is actually shipped.
2. Secrets: `ENV`/`ARG` with credentials, copied `.env` files, build secrets left in layers.
3. Base images: pinned by digest or at least a version; no `latest`.
4. Compose and Kubernetes: `privileged`, host network or PID, host path mounts (docker socket), added capabilities, exposed admin or database ports, missing resource limits, `allowPrivilegeEscalation`.
5. Distinguish development files from production manifests and say which deployment is affected.

`apps/desktop/scripts/stage-sidecar.mjs` stages the local service here before `tauri build`
(`build-macos.sh`, `build-windows.ps1` and the release workflow call it):

- `node/bin/node` (`node/node.exe` on Windows) — the official Node.js runtime of the target,
  checksum-verified against the release's `SHASUMS256.txt` (`scripts/fetch-node.mjs`)
- `cli/dist/` — the bundled spinxsca CLI with its rules, prompts and playbooks
- `cli/node_modules/` — production dependencies for the target platform, flat (no symlinks),
  pruned to the target's native binaries (better-sqlite3, Temporal core bridge)
- `manifest.json` — target triple, Node version and checksum

In development set `SPINXSCA_SIDECAR="node <repo>/apps/cli/dist/index.mjs"` instead.

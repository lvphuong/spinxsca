The release workflow (`.github/workflows/desktop-release.yml`, `apps/desktop/scripts/stage-sidecar.mjs`)
stages the local service here before `tauri build`:

- `node/` — the Node.js runtime for the target platform
- `cli/` — `apps/cli/dist` (the bundled spinxsca CLI) with its production `node_modules`
  (better-sqlite3 native module, tree-sitter WASM grammars)

In development set `SPINXSCA_SIDECAR="node <repo>/apps/cli/dist/index.mjs"` instead.

# spinxsca for VS Code

Findings from spinxsca inline in the editor, with explain and verified fixes.

- **Local mode** (default) runs the `spinxsca` CLI on this machine: *Scan workspace*, *Scan current file* (targeted scan), and diagnostics for open findings. KEV/EPSS are shown for dependency findings.
- **Server mode** shows the findings and the release gate of the current branch from a spinxsca server (`spinxsca.server.url`, `spinxsca.server.projectId`, token via *Set server API token*, stored in VS Code secret storage).
- Quick fixes on a finding: **Explain** (AI explanation) and **Propose a verified fix**. The fix is applied to a copy, re-scanned and tested by the CLI; the patch is written to the workspace only after you choose *Apply*.

The extension runs only in trusted workspaces. `spinxsca.cliPath` and `spinxsca.server.url` are machine-scoped, so a repository's `.vscode/settings.json` cannot redirect them.

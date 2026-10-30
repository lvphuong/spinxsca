import { cpSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bundleWorkflowCode } from '@temporalio/worker';
import { defineConfig } from 'tsdown';

/** Resolved from node_modules at runtime: native bindings, WASM grammars, the Temporal SDK and pg. */
const EXTERNAL = /^(better-sqlite3|web-tree-sitter|tree-sitter-[a-z]+|@temporalio\/[a-z-]+|pg)(\/|$)/;

export default defineConfig({
  entry: ['src/index.ts'],
  format: 'esm',
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  clean: true,
  dts: false,
  banner: { js: '#!/usr/bin/env node' },
  deps: {
    alwaysBundle: [new RegExp(`^(?!${EXTERNAL.source.slice(1)})`)],
    neverBundle: [EXTERNAL],
  },
  onSuccess: async () => {
    for (const [from, to] of [
      ['../../rules/semgrep', 'dist/rules/semgrep'],
      ['../../prompts', 'dist/prompts'],
    ] as const) {
      rmSync(resolve(to), { recursive: true, force: true });
      cpSync(resolve(from), resolve(to), { recursive: true });
    }
    // Temporal workers load workflow code as a prebuilt bundle (no webpack at runtime).
    const { code } = await bundleWorkflowCode({ workflowsPath: resolve('../../packages/temporal/src/workflows.ts') });
    writeFileSync(resolve('dist/temporal-workflows.js'), code);
  },
});

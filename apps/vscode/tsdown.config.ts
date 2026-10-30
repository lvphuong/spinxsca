import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: { extension: 'src/extension.ts' },
  format: 'cjs',
  platform: 'node',
  target: 'node20',
  outDir: 'dist',
  clean: true,
  dts: false,
  deps: { neverBundle: ['vscode'] },
});

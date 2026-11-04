import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '@spinxsca/core';
import type { SnapshotFile, SourceSnapshot } from '@spinxsca/schemas';
import { afterAll, describe, expect, it } from 'vitest';
import { CodeIntelService, dependencyUsage, importMatcher } from '../src/index';

const dir = mkdtempSync(join(tmpdir(), 'spx-reach-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function graphOf(set: Record<string, string>) {
  const service = new CodeIntelService(dir);
  const files: SnapshotFile[] = Object.entries(set).map(([path, text]) => ({
    path,
    digest: sha256(text),
    size: text.length,
  }));
  const artifacts = new Map<string, string>();
  const store = {
    put: async (data: string | Uint8Array) => {
      const text = typeof data === 'string' ? data : Buffer.from(data).toString();
      const digest = sha256(text);
      artifacts.set(digest, text);
      return { digest, mediaType: 'application/json', size: text.length };
    },
    get: async (d: string) => Buffer.from(artifacts.get(d) ?? ''),
    getText: async (d: string) => artifacts.get(d) ?? '',
    has: async (d: string) => artifacts.has(d),
  };
  const built = await service.build({
    snapshot: { snapshotId: 's', contentManifestDigest: sha256('x') } as SourceSnapshot,
    files,
    source: { root: '/', listFiles: async () => files, readText: async (p) => set[p], gitInfo: async () => undefined },
    artifacts: store as never,
  });
  return built.graph;
}

const CASE_005 = join(import.meta.dirname, '../../../evals/internal/005-dep-cve-npm/src/index.js');

describe('dependency reachability', () => {
  it('case 005: lodash is imported but template (GHSA-35jh-r3h4-6jhm) is never called', async () => {
    const graph = await graphOf({ 'src/index.js': readFileSync(CASE_005, 'utf8') });
    const template = dependencyUsage(graph, {
      ecosystem: 'npm',
      name: 'lodash',
      symbols: ['template'],
      symbolSource: 'model',
      direct: true,
    });
    expect(template).toMatchObject({ level: 'IMPORTED_ONLY', confidence: 'MEDIUM', symbolSource: 'model' });
    expect(template.importSites).toEqual([{ path: 'src/index.js', line: 1, specifier: 'lodash' }]);
    const anyUse = dependencyUsage(graph, { ecosystem: 'npm', name: 'lodash', direct: true });
    expect(anyUse.level).toBe('CALLED');
    expect(anyUse.callSites[0]?.callee).toBe('_.defaultsDeep');
    expect(dependencyUsage(graph, { ecosystem: 'npm', name: 'minimist', direct: true }).level).toBe('NOT_IMPORTED');
    expect(dependencyUsage(graph, { ecosystem: 'npm', name: 'minimist', direct: false }).level).toBe(
      'UNKNOWN_TRANSITIVE',
    );
  });

  it('finds calls reachable from an HTTP endpoint', async () => {
    const graph = await graphOf({
      'src/app.js': [
        "const express = require('express');",
        "const _ = require('lodash');",
        'const app = express();',
        'function render(req, res) {',
        '  res.send(_.template(req.query.t)({}));',
        '}',
        "app.get('/preview', render);",
        'module.exports = app;',
      ].join('\n'),
    });
    const usage = dependencyUsage(graph, {
      ecosystem: 'npm',
      name: 'lodash',
      symbols: ['template'],
      symbolSource: 'advisory',
      direct: true,
    });
    expect(usage.level).toBe('CALLED_FROM_ENTRYPOINT');
    expect(usage.confidence).toBe('HIGH');
    expect(usage.entrypoints.map((e) => `${e.method} ${e.route}`)).toEqual(['GET /preview']);
  });

  it('maps package names to import specifiers per ecosystem', () => {
    expect(importMatcher('npm', '@scope/pkg')('@scope/pkg/sub')).toBe(true);
    expect(importMatcher('npm', 'lodash')('lodash.merge')).toBe(false);
    expect(importMatcher('PyPI', 'PyYAML')('yaml')).toBe(true);
    expect(importMatcher('PyPI', 'python-dateutil')('dateutil.parser')).toBe(true);
    expect(
      importMatcher(
        'Maven',
        'com.fasterxml.jackson.core:jackson-databind',
      )('com.fasterxml.jackson.databind.ObjectMapper'),
    ).toBe(true);
    expect(importMatcher('Maven', 'org.example:widget')('org.example.Widget')).toBe(true);
  });
});

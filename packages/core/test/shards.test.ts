import { describe, expect, it } from 'vitest';
import type { ResourceMatrix } from '../src/census/resource-matrix';
import { sha256 } from '../src/ids';
import type { CodeGraphView, CodeSymbol } from '../src/ports';
import {
  censusSignals,
  collectSignals,
  indexSignals,
  moduleOf,
  planShards,
  scanLexical,
  scannerSignals,
  shardTokenBudget,
  shouldShard,
} from '../src/shards/index';

const file = (path: string, size: number) => ({ path, digest: sha256(`${path}:${size}`), size });
const signal = (path: string, weight = 1, line = 1) => ({ path, line, selectorId: 'lex.test', weight, evidence: 'x' });

describe('lexical selectors', () => {
  it('fire on sinks in source files, not in docs, and redact evidence', () => {
    const py = scanLexical('app/views.py', "import os\ndef h(req):\n    os.system('ping ' + req.args['host'])\n");
    expect(py.map((s) => s.selectorId)).toContain('lex.rce.py_dangerous_call');
    expect(py[0]?.line).toBe(3);
    expect(scanLexical('README.md', 'os.system("x")')).toEqual([]);
    const secret = scanLexical(
      'config.js',
      'const key = "AKIAABCDEFGHIJKLMNOP"; const api_key = "sk-supersecretvalue123";',
    );
    expect(secret.map((s) => s.selectorId)).toEqual(
      expect.arrayContaining(['lex.secret.aws_key', 'lex.secret.assignment']),
    );
    expect(secret.every((s) => !s.evidence.includes('AKIAABCDEFGHIJKLMNOP'))).toBe(true);
    expect(scanLexical('lib/math.py', 'def add(a, b):\n    return a + b\n')).toEqual([]);
  });
});

describe('shard planner', () => {
  const files = [
    file('src/orders/controller.ts', 8_000),
    file('src/orders/service.ts', 6_000),
    file('src/users/controller.ts', 4_000),
    file('src/users/service.ts', 4_000),
    file('src/util/format.ts', 2_000),
    file('README.md', 1_000),
    file('assets/logo.png', 50_000),
  ];
  const signals = [
    signal('src/orders/controller.ts', 4, 10),
    signal('src/orders/controller.ts', 2, 20),
    signal('src/orders/service.ts', 2, 5),
    signal('src/users/controller.ts', 3, 3),
    signal('src/users/service.ts', 1, 7),
  ];
  const common = { files, signals, mapModel: 'm', contentManifestDigest: sha256('content') };

  it('is deterministic, keeps modules together and excludes zero-signal files', () => {
    const a = planShards({ ...common, tokenBudget: 4_000 });
    const b = planShards({
      ...common,
      files: [...files].reverse(),
      signals: [...signals].reverse(),
      tokenBudget: 4_000,
    });
    expect(a).toEqual(b);
    expect(a.shards.map((s) => s.files.map((f) => f.path))).toEqual([
      ['src/orders/controller.ts', 'src/orders/service.ts'],
      ['src/users/controller.ts', 'src/users/service.ts'],
    ]);
    expect(a.shards[0]).toMatchObject({
      shardId: 'shard-0001',
      module: 'src/orders',
      priority: 0,
      tokens: 3_500,
      score: 8,
    });
    expect(a.shards[1]?.digest).toMatch(/^sha256:/);
    expect(a.excluded).toMatchObject({ zeroSignal: 1, overCap: [] });
    expect(a.excluded.binaryOrLarge).toBe(2);
    expect(a.stats).toMatchObject({ files: 7, candidateFiles: 4, modules: 2, signals: 5 });
    expect(a.shards[0]?.signals[0]?.weight).toBe(4);
  });

  it('splits an oversized module file by file and marks giant files', () => {
    const plan = planShards({ ...common, tokenBudget: 1_600 });
    const orders = plan.shards.filter((s) => s.module === 'src/orders');
    expect(orders.map((s) => s.files.map((f) => f.path))).toEqual([
      ['src/orders/controller.ts'],
      ['src/orders/service.ts'],
    ]);
    expect(orders[0]?.oversized).toBe(true);
    expect(orders[1]?.oversized).toBe(false);
  });

  it('caps the number of shards and reports the dropped files, honours scope and file caps', () => {
    const capped = planShards({ ...common, tokenBudget: 4_000, options: { maxShards: 1 } });
    expect(capped.shards).toHaveLength(1);
    expect(capped.excluded.overCap).toEqual(['src/users/controller.ts', 'src/users/service.ts']);
    const scoped = planShards({ ...common, tokenBudget: 4_000, scope: ['src/users/controller.ts'] });
    expect(scoped.shards.flatMap((s) => s.files.map((f) => f.path))).toEqual(['src/users/controller.ts']);
    const perFile = planShards({ ...common, tokenBudget: 10_000, options: { maxFilesPerShard: 1 } });
    expect(perFile.shards).toHaveLength(4);
    const all = planShards({ ...common, tokenBudget: 10_000, options: { includeZeroSignal: true } });
    expect(all.stats.candidateFiles).toBe(5);
  });

  it('derives neighbours from imports and call edges without owning them', () => {
    const symbols: Record<string, CodeSymbol> = {
      'src/orders/controller.ts::findOne': {
        key: 'src/orders/controller.ts::findOne',
        path: 'src/orders/controller.ts',
        name: 'findOne',
        qualifiedName: 'findOne',
        kind: 'method',
        startLine: 1,
        endLine: 5,
        exported: true,
      },
      'src/util/format.ts::fmt': {
        key: 'src/util/format.ts::fmt',
        path: 'src/util/format.ts',
        name: 'fmt',
        qualifiedName: 'fmt',
        kind: 'function',
        startLine: 1,
        endLine: 2,
        exported: true,
      },
    };
    const graph: CodeGraphView = {
      symbolCount: 2,
      getSymbol: (k) => symbols[k],
      symbolAt: () => undefined,
      search: (q) => Object.values(symbols).filter((s) => s.path === q.path),
      callers: () => [],
      callees: (k) =>
        k === 'src/orders/controller.ts::findOne'
          ? [{ from: k, to: 'src/util/format.ts::fmt', path: 'src/orders/controller.ts', line: 3, confidence: 'HIGH' }]
          : [],
      endpoints: () => [],
      authContext: () => undefined,
      importsOf: (p) =>
        p === 'src/orders/controller.ts' ? [{ specifier: '../users/service', names: [], line: 1 }] : [],
    };
    const plan = planShards({ ...common, graph, tokenBudget: 4_000 });
    expect(plan.shards[0]?.neighbors).toEqual(['src/users/service.ts', 'src/util/format.ts']);
    expect(plan.shards[1]?.neighbors).toEqual([]);
  });

  it('exposes budget helpers and module keys', () => {
    expect(shardTokenBudget(24_576)).toBe(8_601);
    expect(shardTokenBudget(1_000_000)).toBe(60_000);
    expect(shardTokenBudget(1_000)).toBe(6_000);
    expect(shouldShard({ files: 61, tokens: 0 }, 100_000)).toBe(true);
    expect(shouldShard({ files: 10, tokens: 200_000 }, 100_000)).toBe(true);
    expect(shouldShard({ files: 10, tokens: 10_000 }, 100_000)).toBe(false);
    expect(moduleOf('a/b/c/d/e.ts', 3)).toBe('a/b/c');
    expect(moduleOf('e.ts', 3)).toBe('(root)');
  });
});

describe('signal sources', () => {
  it('turns index, census and scanner data into weighted signals and merges them with selectors', async () => {
    const graph = {
      endpoints: () => [
        {
          id: 'e1',
          path: 'api/orders.py',
          line: 4,
          method: 'GET',
          route: '/orders/<id>',
          framework: 'flask',
          handlers: [],
          controls: [
            {
              ref: 'login_required',
              name: 'login_required',
              kind: 'AUTHENTICATION',
              source: 'decorator',
              path: 'api/orders.py',
              line: 3,
            },
          ],
        },
      ],
    } as unknown as CodeGraphView;
    expect(indexSignals(graph).map((s) => [s.selectorId, s.weight, s.line])).toEqual([
      ['index.endpoint', 3, 4],
      ['index.control', 2, 3],
    ]);
    const matrix = {
      groups: [
        {
          group: 'orders',
          flaggedCount: 1,
          rows: [
            { path: 'api/orders.py', line: 4, method: 'GET', route: '/orders/<id>', flagged: true },
            { path: 'api/orders.py', line: 9, method: 'GET', route: '/orders', flagged: false },
          ],
        },
      ],
      sites: [
        { path: 'api/orders.py', line: 6, callee: 'Order.query.get', operation: 'read', scopedBy: 'none' },
        { path: 'api/orders.py', line: 11, callee: 'Order.query.filter_by', operation: 'read', scopedBy: 'user' },
      ],
    } as unknown as ResourceMatrix;
    expect(censusSignals(matrix).map((s) => [s.selectorId, s.weight])).toEqual([
      ['census.flagged', 4],
      ['census.data_access', 2],
    ]);
    expect(
      scannerSignals([
        {
          category: 'SQL_INJECTION',
          title: 'raw query',
          locations: [{ path: 'api/orders.py', startLine: 6, endLine: 6, role: 'primary' }],
        },
        {
          category: 'HARDCODED_SECRET',
          title: 'key',
          locations: [{ path: 'config.py', startLine: 1, endLine: 1, role: 'primary' }],
        },
      ]).map((s) => s.selectorId),
    ).toEqual(['scanner.sql_injection']);
    const all = await collectSignals({
      files: [file('api/orders.py', 300), file('logo.png', 10)],
      readText: async (p) =>
        p === 'api/orders.py'
          ? 'from flask import request\n\n@login_required\ndef get(id):\n    return Order.query.get(id)\n'
          : undefined,
      graph,
      matrix,
      codeIntel: {
        signals: async () => [{ path: 'api/orders.py', line: 5, selectorId: 'ast.test', weight: 1, evidence: 'ast' }],
      },
    });
    expect(all.map((s) => s.selectorId)).toEqual([
      'index.control',
      'lex.auth.boundary',
      'census.flagged',
      'index.endpoint',
      'ast.test',
      'census.data_access',
    ]);
  });
});

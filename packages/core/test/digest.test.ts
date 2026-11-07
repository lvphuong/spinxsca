import { describe, expect, it } from 'vitest';
import { buildRepoDigest, renderDigest } from '../src/digest/index';
import { sha256 } from '../src/ids';
import type { CodeGraphView } from '../src/ports';

const file = (path: string, size: number) => ({ path, digest: sha256(path), size });
const files = [
  file('src/orders/controller.ts', 4_000),
  file('src/orders/service.ts', 2_000),
  file('src/users/controller.ts', 1_000),
  file('src/util/a.ts', 400),
  file('README.md', 800),
];
const graph = {
  endpoints: () => [
    {
      id: 'e1',
      path: 'src/orders/controller.ts',
      line: 3,
      method: 'GET',
      route: '/orders/:id',
      framework: 'nestjs',
      handlers: [],
      controls: [
        {
          ref: 'g',
          name: 'JwtAuthGuard',
          kind: 'AUTHENTICATION',
          source: 'decorator',
          path: 'src/orders/controller.ts',
          line: 2,
        },
      ],
    },
    {
      id: 'e2',
      path: 'src/users/controller.ts',
      line: 3,
      method: 'GET',
      route: '/users',
      framework: 'nestjs',
      handlers: [],
      controls: [],
    },
  ],
  search: (q: { path?: string }) => (q.path === 'src/orders/controller.ts' ? [{}, {}] : []),
  importsOf: (p: string) =>
    p.startsWith('src/orders')
      ? [
          { specifier: '@nestjs/common', names: [], line: 1 },
          { specifier: './service', names: [], line: 2 },
        ]
      : [],
} as unknown as CodeGraphView;

describe('repository digest (ADR-056)', () => {
  const digest = buildRepoDigest({
    files,
    contentManifestDigest: sha256('c'),
    graph,
    sites: [
      {
        path: 'src/orders/service.ts',
        line: 4,
        callerKey: 'k',
        callee: 'prisma.order.findUnique',
        orm: 'prisma',
        operation: 'read',
        scopedBy: 'none',
        scopeTokens: [],
      },
    ],
    loc: new Map([['src/orders/controller.ts', 120]]),
  });

  it('aggregates counts up the directory tree deterministically', () => {
    const root = digest.nodes[''];
    const orders = digest.nodes['src/orders'];
    expect(root).toMatchObject({ files: 5, endpoints: 2, controls: 1, dataAccess: 1 });
    expect(orders).toMatchObject({ files: 2, endpoints: 1, controls: 1, dataAccess: 1, symbols: 2, loc: 120 + 50 });
    expect(orders?.externalImports).toEqual(['@nestjs/common']);
    expect(orders?.topEndpoints).toEqual(['GET /orders/:id']);
    expect(digest.nodes.src?.children).toEqual(['src/orders', 'src/users', 'src/util']);
    expect(digest.stats).toMatchObject({ files: 5, endpoints: 2 });
    const again = buildRepoDigest({
      files: [...files].reverse(),
      contentManifestDigest: sha256('c'),
      graph,
      sites: [],
      loc: new Map(),
    });
    expect(Object.keys(again.nodes)).toEqual(Object.keys(digest.nodes));
  });

  it('renders a bounded tree and drills into a subtree', () => {
    const text = renderDigest(digest, { depth: 1 });
    expect(text).toContain('Repository digest (5 files');
    expect(text).toContain('- src/ 4 files');
    expect(text).toContain('call repo_map with path="src"');
    expect(text).not.toContain('src/orders/');
    const sub = renderDigest(digest, { path: 'src/orders', depth: 1 });
    expect(sub).toContain('1 endpoints (GET /orders/:id)');
    expect(sub).toContain('- src/orders/controller.ts');
    expect(renderDigest(digest, { maxChars: 200 }).length).toBeLessThan(260);
    expect(renderDigest(digest, { path: 'nope' })).toContain('No directory nope');
  });
});

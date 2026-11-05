import { describe, expect, it } from 'vitest';
import { buildResourceMatrix, censusJson, classifyScope, matchDataAccess, renderCensus } from '../src/census/index';
import type { CodeCallSite, CodeEndpoint, CodeGraphView, CodeSymbol, SourceTree } from '../src/ports';

const files: Record<string, string> = {
  'orders/orders.controller.ts': [
    "import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';",
    '@Controller("orders")',
    '@UseGuards(JwtAuthGuard)',
    'export class OrdersController {',
    '  constructor(private readonly orders: OrdersService) {}',
    "  @Get(':id')",
    "  async findOne(@Param('id') id: string) {",
    '    return this.orders.findById(id);',
    '  }',
    '  @Get()',
    '  async mine(@Req() req: AuthenticatedRequest) {',
    '    return this.orders.findByOwner(req.user.id);',
    '  }',
    '}',
  ].join('\n'),
  'orders/orders.service.ts': [
    'export class OrdersService {',
    '  constructor(private readonly prisma: PrismaService) {}',
    '  findById(id: string) {',
    '    return this.prisma.order.findUnique({ where: { id } });',
    '  }',
    '  findByOwner(ownerId: string) {',
    '    return this.prisma.order.findMany({ where: { ownerId } });',
    '  }',
    '}',
  ].join('\n'),
};

const sym = (key: string, path: string, name: string, start: number, end: number, owner?: string): CodeSymbol => ({
  key,
  path,
  name,
  qualifiedName: name,
  kind: 'method',
  startLine: start,
  endLine: end,
  exported: true,
  ...(owner ? { owner } : {}),
});
const C = 'orders/orders.controller.ts::OrdersController';
const S = 'orders/orders.service.ts::OrdersService';
const symbols: Record<string, CodeSymbol> = {
  [`${C}.findOne`]: sym(`${C}.findOne`, 'orders/orders.controller.ts', 'findOne', 7, 9, C),
  [`${C}.mine`]: sym(`${C}.mine`, 'orders/orders.controller.ts', 'mine', 11, 13, C),
  [`${S}.findById`]: sym(`${S}.findById`, 'orders/orders.service.ts', 'findById', 3, 5, S),
  [`${S}.findByOwner`]: sym(`${S}.findByOwner`, 'orders/orders.service.ts', 'findByOwner', 6, 8, S),
};
const endpoints: CodeEndpoint[] = [
  {
    id: 'GET /orders/:id',
    path: 'orders/orders.controller.ts',
    line: 6,
    method: 'GET',
    route: '/orders/:id',
    framework: 'nestjs',
    handlers: [`${C}.findOne`],
    controls: [],
  },
  {
    id: 'GET /orders',
    path: 'orders/orders.controller.ts',
    line: 10,
    method: 'GET',
    route: '/orders',
    framework: 'nestjs',
    handlers: [`${C}.mine`],
    controls: [],
  },
];
const guard = {
  ref: 'JwtAuthGuard',
  name: 'JwtAuthGuard',
  kind: 'AUTHENTICATION',
  source: 'decorator',
  path: 'orders/orders.controller.ts',
  line: 3,
};
const calls: Record<string, CodeCallSite[]> = {
  'orders/orders.service.ts': [
    { line: 4, callerKey: `${S}.findById`, callee: 'this.prisma.order.findUnique', name: 'findUnique' },
    { line: 7, callerKey: `${S}.findByOwner`, callee: 'this.prisma.order.findMany', name: 'findMany' },
  ],
  'orders/orders.controller.ts': [
    { line: 8, callerKey: `${C}.findOne`, callee: 'this.orders.findById', name: 'findById' },
    { line: 12, callerKey: `${C}.mine`, callee: 'this.orders.findByOwner', name: 'findByOwner' },
  ],
};
const graph: CodeGraphView = {
  symbolCount: 4,
  getSymbol: (key) => symbols[key],
  symbolAt: () => undefined,
  search: () => [],
  callers: () => [],
  callees: (key) => {
    const to = key === `${C}.findOne` ? `${S}.findById` : key === `${C}.mine` ? `${S}.findByOwner` : undefined;
    return to ? [{ from: key, to, path: 'orders/orders.controller.ts', line: 8, confidence: 'HIGH' }] : [];
  },
  endpoints: () => endpoints,
  authContext: (id) => {
    const e = endpoints.find((x) => x.id === id);
    if (!e) return undefined;
    const handler = symbols[e.handlers[0] ?? ''];
    return {
      endpoint: e,
      handlers: handler ? [handler] : [],
      controls: [guard],
      hasAuthentication: true,
      hasAuthorization: false,
    };
  },
  callSitesIn: (path) => calls[path] ?? [],
  filePaths: () => Object.keys(files),
};
const source: SourceTree = {
  root: '/fake',
  listFiles: async () => [],
  readText: async (p) => files[p],
  gitInfo: async () => undefined,
};

describe('deterministic census (ADR-049)', () => {
  it('classifies data-access scope lexically and admits uncertainty', () => {
    expect(classifyScope('prisma.order.findUnique({ where: { id, ownerId: req.user.id } })').scopedBy).toBe('user');
    expect(classifyScope('session.query(Order).filter_by(tenant_id=g.tenant_id)').scopedBy).toBe('tenant');
    expect(classifyScope('Order.objects.filter(id=pk)').scopedBy).toBe('none');
    expect(classifyScope('db.query(sql)').scopedBy).toBe('unknown');
    expect(matchDataAccess('this.prisma.order.findUnique')).toEqual({ orm: 'prisma', operation: 'read' });
    expect(matchDataAccess('Order.objects.delete')).toEqual({ orm: 'django', operation: 'delete' });
    expect(matchDataAccess('this.logger.info')).toBeUndefined();
  });

  it('groups sibling operations and flags the one without an ownership scope', async () => {
    const matrix = await buildResourceMatrix(graph, source, Object.keys(files));
    expect(matrix.stats).toEqual({ endpoints: 2, groups: 1, flagged: 1, dataAccessSites: 2 });
    const group = matrix.groups[0];
    expect(group?.group).toBe('OrdersController');
    const findOne = group?.rows.find((r) => r.route === '/orders/:id');
    const mine = group?.rows.find((r) => r.route === '/orders');
    expect(findOne?.identifierParam).toBe(true);
    expect(findOne?.dataAccess.map((d) => d.scopedBy)).toEqual(['none']);
    expect(findOne?.flagged).toBe(true);
    expect(mine?.dataAccess.map((d) => d.scopedBy)).toEqual(['user']);
    expect(mine?.flagged).toBe(false);
    expect(findOne?.controls.authn).toEqual(['JwtAuthGuard']);
    expect(findOne?.controls.authz).toEqual([]);
  });

  it('renders a bounded worksheet that is labelled as evidence, not findings', async () => {
    const matrix = await buildResourceMatrix(graph, source, Object.keys(files));
    const text = renderCensus(matrix);
    expect(text).toContain('## CENSUS WORKSHEET');
    expect(text).toContain('NOT findings');
    expect(text).toContain('[!] GET /orders/:id');
    expect(text).not.toContain('[!] GET /orders (');
    expect(renderCensus(matrix, { maxChars: 10 })).toContain('more groups not shown');
    const json = JSON.parse(censusJson(matrix)) as { groups: Array<{ rows: Array<{ flagged: boolean }> }> };
    expect(json.groups[0]?.rows.some((r) => r.flagged)).toBe(true);
  });

  it('is empty when no group has two operations', async () => {
    const single: CodeGraphView = { ...graph, endpoints: () => endpoints.slice(0, 1) };
    const matrix = await buildResourceMatrix(single, source, Object.keys(files));
    expect(matrix.stats.flagged).toBe(0);
    expect(renderCensus(matrix)).toBe('');
  });
});

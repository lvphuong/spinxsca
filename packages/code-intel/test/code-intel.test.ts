import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '@spinxsca/core';
import type { SnapshotFile, SourceSnapshot } from '@spinxsca/schemas';
import { afterAll, describe, expect, it } from 'vitest';
import { CodeGraph, computeImpact, extractFile, IndexBuilder } from '../src/index';

const files: Record<string, string> = {
  'src/app.js': [
    "const express = require('express');",
    "const { requireAuth } = require('./middleware/auth');",
    "const users = require('./routes/users');",
    'const app = express();',
    'app.use(express.json());',
    'app.use(requireAuth);',
    "app.use('/api', users);",
    'module.exports = app;',
  ].join('\n'),
  'src/middleware/auth.js': [
    'function requireAuth(req, res, next) {',
    '  if (!req.user) return res.status(401).end();',
    '  next();',
    '}',
    'const requireAdmin = (req, res, next) => (req.user.role === "admin" ? next() : res.status(403).end());',
    'module.exports = { requireAuth, requireAdmin };',
  ].join('\n'),
  'src/routes/users.js': [
    "const express = require('express');",
    "const { requireAdmin } = require('../middleware/auth');",
    "const userService = require('../services/userService');",
    'const router = express.Router();',
    "router.get('/users/:id', async (req, res) => {",
    '  res.json(await userService.findById(req.params.id));',
    '});',
    "router.delete('/users/:id', requireAdmin, async (req, res) => {",
    '  await userService.remove(req.params.id);',
    '  res.status(204).end();',
    '});',
    'module.exports = router;',
  ].join('\n'),
  'src/services/userService.js': [
    "const db = require('../db');",
    'async function findById(id) {',
    "  return db.query('SELECT * FROM users WHERE id = $1', [id]);",
    '}',
    'async function remove(id) {',
    "  return db.query('DELETE FROM users WHERE id = $1', [id]);",
    '}',
    'module.exports = { findById, remove };',
  ].join('\n'),
  'api/orders.controller.ts': [
    "import { Controller, Get, Param, UseGuards } from '@nestjs/common';",
    "import { JwtAuthGuard } from '../auth/jwt-auth.guard';",
    "import { OrdersService } from './orders.service';",
    "@Controller('orders')",
    '@UseGuards(JwtAuthGuard)',
    'export class OrdersController {',
    '  constructor(private readonly orders: OrdersService) {}',
    "  @Get(':id')",
    "  async findOne(@Param('id') id: string) {",
    '    return this.orders.findById(id);',
    '  }',
    '}',
  ].join('\n'),
  'api/orders.service.ts': ['export class OrdersService {', '  findById(id: string) { return id; }', '}'].join('\n'),
  'svc/app.py': [
    'from flask import Flask, request',
    'from fastapi import APIRouter, Depends',
    'from svc.auth import get_current_user',
    'app = Flask(__name__)',
    'router = APIRouter()',
    '',
    '@app.route("/ping", methods=["GET", "POST"])',
    'def ping():',
    '    return run(request.args.get("h"))',
    '',
    '@router.get("/me")',
    'def me(user=Depends(get_current_user)):',
    '    return user',
    '',
    'def run(cmd):',
    '    return cmd',
  ].join('\n'),
  'svc/auth.py': 'def get_current_user():\n    return None\n',
  'java/OrderController.java': [
    'package com.example;',
    'import org.springframework.web.bind.annotation.*;',
    '@RestController',
    '@RequestMapping("/api/orders")',
    'public class OrderController {',
    '  private final OrderService svc = new OrderService();',
    '  @GetMapping("/{id}")',
    '  @PreAuthorize("hasRole(\'ADMIN\')")',
    '  public String get(@PathVariable String id) { return svc.find(id); }',
    '  @PostMapping',
    '  public String create() { return svc.create(); }',
    '}',
  ].join('\n'),
  'java/OrderService.java': [
    'package com.example;',
    'public class OrderService {',
    '  public String find(String id) { return id; }',
    '  public String create() { return "x"; }',
    '}',
  ].join('\n'),
};

const snapshot = { snapshotId: 's', contentManifestDigest: sha256('x') } as SourceSnapshot;
const snapshotFiles = (set: Record<string, string>): SnapshotFile[] =>
  Object.entries(set).map(([path, text]) => ({ path, digest: sha256(text), size: text.length }));

const dir = mkdtempSync(join(tmpdir(), 'spx-ci-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function build(set: Record<string, string>) {
  const builder = new IndexBuilder(join(dir, 'cache.db'));
  try {
    return await builder.build({ snapshot, files: snapshotFiles(set), readText: async (p) => set[p] });
  } finally {
    builder.close();
  }
}

describe('extractors', () => {
  it('extracts express routes, inline middleware, global middleware and mounts', async () => {
    const users = (await extractFile('src/routes/users.js', files['src/routes/users.js'] as string)) as NonNullable<
      Awaited<ReturnType<typeof extractFile>>
    >;
    expect(users.endpoints.map((e) => [e.method, e.route, e.handlers.length, e.controls.map((c) => c.name)])).toEqual([
      ['GET', '/users/:id', 1, []],
      ['DELETE', '/users/:id', 2, ['requireAdmin']],
    ]);
    expect(users.symbols.map((s) => s.qualifiedName)).toContain('<GET /users/:id>');
    expect(users.imports.find((i) => i.specifier === '../middleware/auth')?.names).toEqual([
      { imported: 'requireAdmin', local: 'requireAdmin' },
    ]);
    const app = (await extractFile('src/app.js', files['src/app.js'] as string)) as NonNullable<
      Awaited<ReturnType<typeof extractFile>>
    >;
    expect(app.globalControls.map((g) => [g.ref, g.kind])).toEqual([
      ['express.json', 'OTHER'],
      ['requireAuth', 'AUTHENTICATION'],
    ]);
    expect(app.mounts).toEqual([{ line: 7, prefix: '/api', target: 'users' }]);
  });

  it('extracts NestJS controllers with class-level guards', async () => {
    const nest = (await extractFile(
      'api/orders.controller.ts',
      files['api/orders.controller.ts'] as string,
    )) as NonNullable<Awaited<ReturnType<typeof extractFile>>>;
    expect(nest.endpoints).toHaveLength(1);
    expect(nest.endpoints[0]).toMatchObject({
      method: 'GET',
      route: '/orders/:id',
      framework: 'nestjs',
      handlers: ['api/orders.controller.ts::OrdersController.findOne'],
    });
    expect(nest.endpoints[0]?.controls.map((c) => [c.name, c.kind, c.source])).toEqual([
      ['JwtAuthGuard', 'AUTHENTICATION', 'decorator'],
    ]);
    expect(nest.calls.find((c) => c.name === 'findById')?.callerKey).toBe(
      'api/orders.controller.ts::OrdersController.findOne',
    );
  });

  it('extracts Flask and FastAPI routes with dependencies', async () => {
    const py = (await extractFile('svc/app.py', files['svc/app.py'] as string)) as NonNullable<
      Awaited<ReturnType<typeof extractFile>>
    >;
    expect(py.endpoints.map((e) => [e.method, e.route, e.framework])).toEqual([
      ['GET', '/ping', 'flask'],
      ['POST', '/ping', 'flask'],
      ['GET', '/me', 'fastapi'],
    ]);
    expect(py.endpoints[2]?.controls).toEqual([
      expect.objectContaining({ name: 'get_current_user', kind: 'AUTHENTICATION', source: 'dependency' }),
    ]);
    expect(py.imports.map((i) => i.specifier)).toEqual(['flask', 'fastapi', 'svc.auth']);
    expect(py.calls.find((c) => c.name === 'run')?.callerKey).toBe('svc/app.py::ping');
  });

  it('extracts Spring endpoints with security annotations', async () => {
    const java = (await extractFile(
      'java/OrderController.java',
      files['java/OrderController.java'] as string,
    )) as NonNullable<Awaited<ReturnType<typeof extractFile>>>;
    expect(java.endpoints.map((e) => [e.method, e.route, e.controls.map((c) => c.name)])).toEqual([
      ['GET', '/api/orders/{id}', ['PreAuthorize']],
      ['POST', '/api/orders', []],
    ]);
    expect(java.symbols.map((s) => s.qualifiedName)).toEqual([
      '<module>',
      'OrderController',
      'OrderController.get',
      'OrderController.create',
    ]);
  });
});

describe('CodeGraph', () => {
  it('resolves calls across files and reports auth context with mounted prefixes', async () => {
    const { graph, stats } = await build(files);
    expect(stats.errors).toBe(0);
    const endpoints = graph.endpoints({ path: 'src/' });
    expect(endpoints.map((e) => `${e.method} ${e.route}`)).toEqual(['GET /api/users/:id', 'DELETE /api/users/:id']);
    const get = graph.authContext(endpoints[0]?.id as string);
    expect(get?.controls.filter((c) => c.kind !== 'OTHER').map((c) => [c.name, c.kind, c.source])).toEqual([
      ['requireAuth', 'AUTHENTICATION', 'router'],
    ]);
    expect(get?.hasAuthentication).toBe(true);
    expect(get?.hasAuthorization).toBe(false);
    const del = graph.authContext(endpoints[1]?.id as string);
    expect(del?.hasAuthorization).toBe(true);
    expect(del?.controls.find((c) => c.name === 'requireAdmin')?.symbol?.key).toBe(
      'src/middleware/auth.js::requireAdmin',
    );
    const handler = graph.getSymbol('src/routes/users.js::<GET /users/:id>');
    expect(graph.callees(handler?.key as string).map((e) => e.to)).toEqual(['src/services/userService.js::findById']);
    expect(graph.callers('src/services/userService.js::findById').map((e) => e.from)).toEqual([
      'src/routes/users.js::<GET /users/:id>',
    ]);
    expect(graph.callers('java/OrderService.java::OrderService.find').map((e) => e.from)).toEqual([
      'java/OrderController.java::OrderController.get',
    ]);
    expect(graph.callers('svc/auth.py::get_current_user')).toEqual([]);
    expect(graph.callees('api/orders.controller.ts::OrdersController.findOne').map((e) => e.to)).toEqual([
      'api/orders.service.ts::OrdersService.findById',
    ]);
  });

  it('computes change impact through callers and controls', async () => {
    const before = await build(files);
    const changed = {
      ...files,
      'src/services/userService.js': (files['src/services/userService.js'] as string).replace(
        "'SELECT * FROM users WHERE id = $1', [id]",
        '"SELECT * FROM users WHERE id = " + id',
      ),
    };
    const after = await build(changed);
    expect(after.stats.parsed).toBe(1);
    const impact = computeImpact(before.graph, after.graph, ['src/services/userService.js']);
    expect(impact.changedSymbols).toEqual(['src/services/userService.js::findById']);
    expect(Object.keys(impact.affectedSymbols)).toEqual(['src/routes/users.js::<GET /users/:id>']);
    expect(impact.affectedEndpoints.map((e) => e.route)).toEqual(['/api/users/:id']);
    expect(impact.scope).toEqual(['src/routes/users.js', 'src/services/userService.js']);
    expect(impact.requiresExtendedScan).toBe(false);

    const authChanged = {
      ...files,
      'src/middleware/auth.js': (files['src/middleware/auth.js'] as string)
        .replace("'admin'", "'root'")
        .replace('"admin"', '"root"'),
    };
    const authImpact = computeImpact(before.graph, (await build(authChanged)).graph, ['src/middleware/auth.js']);
    expect(authImpact.changedSymbols).toEqual(['src/middleware/auth.js::requireAdmin']);
    expect(authImpact.affectedControls).toEqual(['src/middleware/auth.js::requireAdmin']);
    expect(authImpact.affectedEndpoints.map((e) => `${e.method} ${e.route}`)).toEqual(['DELETE /api/users/:id']);
    expect(authImpact.requiresExtendedScan).toBe(true);
  });

  it('caches extractions and tolerates syntax errors', async () => {
    const broken = { 'a.js': 'function (', 'b.py': 'def ok():\n    return 1\n' };
    const first = await build(broken);
    expect(first.stats.errors).toBe(1);
    expect(first.graph.getSymbol('b.py::ok')?.kind).toBe('function');
    const second = await build(broken);
    expect(second.stats.cached).toBe(2);
    expect(new CodeGraph(second.data).symbols.size).toBe(first.graph.symbols.size);
  });
});

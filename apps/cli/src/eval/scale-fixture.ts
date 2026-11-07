import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * Synthetic large repository for the scale suite (ADR-055). Deterministic for a seed: Express and
 * NestJS resources in JavaScript/TypeScript plus Flask blueprints in Python, each with sibling
 * operations that scope by owner or tenant, and a planted set of bugs the suite expects the sharded
 * investigation to find. Runs offline and reproduces byte for byte, so recall and resource numbers
 * are comparable between runs.
 */
export interface ScaleFixtureOptions {
  /** Approximate number of source files (filler modules make up the difference). */
  files: number;
  /** Approximate lines of code. */
  loc: number;
  /** Planted vulnerabilities (one per resource module, up to the number of resources). */
  planted: number;
  seed: number;
}

export interface PlantedFinding {
  id: string;
  category:
    | 'BROKEN_OBJECT_LEVEL_AUTHORIZATION'
    | 'TENANT_ISOLATION'
    | 'SQL_INJECTION'
    | 'PATH_TRAVERSAL'
    | 'MISSING_AUTHENTICATION';
  cwe: string[];
  path: string;
  lines: [number, number];
  family: string;
  kind: PlantKind;
}

export interface ScaleFixture {
  files: number;
  loc: number;
  planted: PlantedFinding[];
  negatives: Array<{ path: string; lines: [number, number]; reason: string }>;
}

type PlantKind =
  | 'sibling-without-scope'
  | 'tenant-filter-missing'
  | 'raw-sql-concat'
  | 'path-join-from-request'
  | 'fail-open-auth';
const KINDS: PlantKind[] = [
  'sibling-without-scope',
  'tenant-filter-missing',
  'raw-sql-concat',
  'path-join-from-request',
  'fail-open-auth',
];
const NOUNS = [
  'orders',
  'invoices',
  'projects',
  'tickets',
  'reports',
  'documents',
  'shipments',
  'payments',
  'contracts',
  'devices',
  'alerts',
  'budgets',
  'teams',
  'assets',
  'notes',
  'tasks',
  'events',
  'plans',
  'quotes',
  'leases',
];

/** Small deterministic PRNG (mulberry32). */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CATEGORY: Record<PlantKind, PlantedFinding['category']> = {
  'sibling-without-scope': 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
  'tenant-filter-missing': 'TENANT_ISOLATION',
  'raw-sql-concat': 'SQL_INJECTION',
  'path-join-from-request': 'PATH_TRAVERSAL',
  'fail-open-auth': 'MISSING_AUTHENTICATION',
};
const CWE: Record<PlantKind, string[]> = {
  'sibling-without-scope': ['CWE-639'],
  'tenant-filter-missing': ['CWE-639', 'CWE-284'],
  'raw-sql-concat': ['CWE-89'],
  'path-join-from-request': ['CWE-22'],
  'fail-open-auth': ['CWE-287'],
};

/** Express router for one resource; `plant` injects one bug at a known line. */
function expressRouter(
  noun: string,
  plant: PlantKind | undefined,
): { text: string; lines?: [number, number]; negatives: Array<[number, number, string]> } {
  const one = noun.replace(/s$/, '');
  const L: string[] = [];
  const push = (...s: string[]) => L.push(...s);
  push(
    "const express = require('express');",
    `const { ${one}Repo } = require('../repos/${noun}');`,
    "const { requireAuth } = require('../middleware/auth');",
    "const path = require('node:path');",
    'const router = express.Router();',
    '',
    "router.get('/', requireAuth, async (req, res) => {",
    `  res.json(await ${one}Repo.findMany({ where: { ownerId: req.user.id, tenantId: req.user.tenantId } }));`,
    '});',
    '',
  );
  let lines: [number, number] | undefined;
  const negatives: Array<[number, number, string]> = [[7, 9, 'list scoped by owner and tenant']];
  const getStart = L.length + 1;
  if (plant === 'sibling-without-scope') {
    push(
      "router.get('/:id', requireAuth, async (req, res) => {",
      `  res.json(await ${one}Repo.findUnique({ where: { id: req.params.id } }));`,
      '});',
      '',
    );
    lines = [getStart, getStart + 2];
  } else if (plant === 'tenant-filter-missing') {
    push(
      "router.get('/:id', requireAuth, async (req, res) => {",
      `  res.json(await ${one}Repo.findUnique({ where: { id: req.params.id, ownerId: req.user.id } }));`,
      '});',
      '',
    );
    lines = [getStart, getStart + 2];
  } else {
    push(
      "router.get('/:id', requireAuth, async (req, res) => {",
      `  res.json(await ${one}Repo.findUnique({ where: { id: req.params.id, ownerId: req.user.id, tenantId: req.user.tenantId } }));`,
      '});',
      '',
    );
    negatives.push([getStart, getStart + 2, 'lookup scoped by owner and tenant']);
  }
  const searchStart = L.length + 1;
  if (plant === 'raw-sql-concat') {
    push(
      "router.get('/search', requireAuth, async (req, res) => {",
      `  res.json(await db.query("select * from ${noun} where tenant_id = '" + req.user.tenantId + "' and title like '%" + req.query.q + "%'"));`,
      '});',
      '',
    );
    lines = [searchStart, searchStart + 2];
  } else {
    push(
      "router.get('/search', requireAuth, async (req, res) => {",
      `  res.json(await db.query('select * from ${noun} where tenant_id = $1 and title like $2', [req.user.tenantId, \`%\${req.query.q}%\`]));`,
      '});',
      '',
    );
    negatives.push([searchStart, searchStart + 2, 'parameterised query']);
  }
  const fileStart = L.length + 1;
  if (plant === 'path-join-from-request') {
    push(
      "router.get('/:id/attachment', requireAuth, async (req, res) => {",
      `  res.sendFile(path.join(ATTACHMENTS, req.user.tenantId, req.query.name));`,
      '});',
      '',
    );
    lines = [fileStart, fileStart + 2];
  } else {
    push(
      "router.get('/:id/attachment', requireAuth, async (req, res) => {",
      `  const name = path.basename(String(req.query.name));`,
      `  res.sendFile(path.join(ATTACHMENTS, req.user.tenantId, name));`,
      '});',
      '',
    );
    negatives.push([fileStart, fileStart + 3, 'basename strips traversal']);
  }
  push(
    "router.put('/:id', requireAuth, async (req, res) => {",
    `  await ${one}Repo.update({ where: { id: req.params.id, ownerId: req.user.id, tenantId: req.user.tenantId }, data: { title: req.body.title } });`,
    '  res.sendStatus(204);',
    '});',
    '',
    `const ATTACHMENTS = '/srv/attachments';`,
    'module.exports = router;',
    '',
  );
  return { text: L.join('\n'), ...(lines ? { lines } : {}), negatives };
}

function authMiddleware(plant: boolean): { text: string; lines?: [number, number] } {
  const L = [
    "const jwt = require('jsonwebtoken');",
    '',
    'function requireAuth(req, res, next) {',
    "  const token = (req.headers.authorization || '').replace(/^Bearer /, '');",
    '  try {',
    '    req.user = jwt.verify(token, process.env.JWT_SECRET);',
    '    return next();',
    '  } catch (err) {',
  ];
  if (plant) {
    L.push('    req.user = { id: null, tenantId: null, roles: [] };', '    return next();');
  } else {
    L.push("    return res.status(401).json({ error: 'unauthenticated' });");
  }
  L.push('  }', '}', '', 'module.exports = { requireAuth };', '');
  return { text: L.join('\n'), ...(plant ? { lines: [9, 10] as [number, number] } : {}) };
}

function nestController(noun: string, plant: PlantKind | undefined): { text: string; lines?: [number, number] } {
  const cls = noun[0]?.toUpperCase() + noun.slice(1);
  const one = noun.replace(/s$/, '');
  const L = [
    "import { Body, Controller, Get, Param, Put, Req, UseGuards } from '@nestjs/common';",
    "import { JwtAuthGuard } from '../auth/jwt.guard';",
    `import { ${cls}Service } from './${noun}.service';`,
    '',
    `@Controller('${noun}')`,
    '@UseGuards(JwtAuthGuard)',
    `export class ${cls}Controller {`,
    `  constructor(private readonly ${noun}: ${cls}Service) {}`,
    '',
    '  @Get()',
    '  list(@Req() req) {',
    `    return this.${noun}.findByOwner(req.user.id, req.user.tenantId);`,
    '  }',
    '',
    "  @Get(':id')",
  ];
  let lines: [number, number] | undefined;
  if (plant === 'sibling-without-scope') {
    L.push("  findOne(@Param('id') id: string) {", `    return this.${noun}.findById(id);`, '  }');
    lines = [15, 18];
  } else {
    L.push(
      "  findOne(@Param('id') id: string, @Req() req) {",
      `    return this.${noun}.findOwned(id, req.user.id, req.user.tenantId);`,
      '  }',
    );
  }
  L.push(
    '',
    "  @Put(':id')",
    "  update(@Param('id') id: string, @Body() body, @Req() req) {",
    `    return this.${noun}.updateOwned(id, req.user.id, req.user.tenantId, { title: body.title });`,
    '  }',
    '}',
    '',
  );
  void one;
  return { text: L.join('\n'), ...(lines ? { lines } : {}) };
}

function nestService(noun: string): string {
  const cls = noun[0]?.toUpperCase() + noun.slice(1);
  const one = noun.replace(/s$/, '');
  return [
    "import { Injectable } from '@nestjs/common';",
    "import { PrismaService } from '../prisma.service';",
    '',
    '@Injectable()',
    `export class ${cls}Service {`,
    '  constructor(private readonly prisma: PrismaService) {}',
    '  findByOwner(ownerId: string, tenantId: string) {',
    `    return this.prisma.${one}.findMany({ where: { ownerId, tenantId } });`,
    '  }',
    '  findById(id: string) {',
    `    return this.prisma.${one}.findUnique({ where: { id } });`,
    '  }',
    '  findOwned(id: string, ownerId: string, tenantId: string) {',
    `    return this.prisma.${one}.findFirst({ where: { id, ownerId, tenantId } });`,
    '  }',
    '  updateOwned(id: string, ownerId: string, tenantId: string, data: { title: string }) {',
    `    return this.prisma.${one}.updateMany({ where: { id, ownerId, tenantId }, data });`,
    '  }',
    '}',
    '',
  ].join('\n');
}

function flaskBlueprint(noun: string, plant: PlantKind | undefined): { text: string; lines?: [number, number] } {
  const one = noun.replace(/s$/, '');
  const cls = one[0]?.toUpperCase() + one.slice(1);
  const L = [
    'from flask import Blueprint, jsonify, request, g',
    `from ..models import ${cls}, db`,
    'from ..auth import login_required',
    '',
    `bp = Blueprint('${noun}', __name__, url_prefix='/${noun}')`,
    '',
    '',
    "@bp.get('/')",
    '@login_required',
    'def list_items():',
    `    rows = ${cls}.query.filter_by(owner_id=g.user.id, tenant_id=g.user.tenant_id).all()`,
    '    return jsonify([r.to_dict() for r in rows])',
    '',
    '',
    "@bp.get('/<int:item_id>')",
    '@login_required',
    'def get_item(item_id):',
  ];
  let lines: [number, number] | undefined;
  if (plant === 'sibling-without-scope') {
    L.push(`    row = ${cls}.query.get_or_404(item_id)`);
    lines = [15, 18];
  } else if (plant === 'raw-sql-concat') {
    L.push(
      `    row = db.session.execute("select * from ${noun} where id = " + str(item_id) + " and tenant_id = '" + g.user.tenant_id + "'").first()`,
    );
    lines = [15, 18];
  } else {
    L.push(
      `    row = ${cls}.query.filter_by(id=item_id, owner_id=g.user.id, tenant_id=g.user.tenant_id).first_or_404()`,
    );
  }
  L.push('    return jsonify(row.to_dict())', '');
  return { text: L.join('\n'), ...(lines ? { lines } : {}) };
}

function fillerModule(name: string, lines: number, random: () => number): string {
  const L = [`// ${name}: utility helpers (generated filler)`, ''];
  let i = 0;
  while (L.length < lines) {
    const fn = `helper${i++}`;
    const a = Math.floor(random() * 100);
    L.push(
      `export function ${fn}(value) {`,
      `  const scaled = value * ${a} + ${Math.floor(random() * 10)};`,
      `  if (scaled > ${a * 50}) return scaled - ${a};`,
      '  return scaled;',
      '}',
      '',
    );
  }
  return L.join('\n');
}

/** Writes the fixture under `root` and returns the ground truth for its case file. */
export function generateScaleFixture(root: string, options: ScaleFixtureOptions): ScaleFixture {
  const random = rng(options.seed);
  const write = (path: string, text: string) => {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
    return text.split('\n').length;
  };
  const planted: PlantedFinding[] = [];
  const negatives: ScaleFixture['negatives'] = [];
  let files = 0;
  let loc = 0;
  let plantsLeft = options.planted;
  let plantIndex = 0;
  const nextPlant = (): PlantKind | undefined => {
    if (plantsLeft <= 0) return undefined;
    plantsLeft--;
    return KINDS[plantIndex++ % KINDS.length];
  };
  const record = (kind: PlantKind | undefined, path: string, lines: [number, number] | undefined, family: string) => {
    if (!kind || !lines) return;
    planted.push({
      id: `GT-${planted.length + 1}`,
      category: CATEGORY[kind],
      cwe: CWE[kind],
      path,
      lines,
      family,
      kind,
    });
  };

  // Shared middleware: one planted fail-open auth at most.
  const authPlant = plantsLeft > 0 && options.planted >= 5;
  if (authPlant) plantsLeft--;
  const auth = authMiddleware(authPlant);
  loc += write('express/src/middleware/auth.js', auth.text);
  files++;
  if (authPlant && auth.lines) record('fail-open-auth', 'express/src/middleware/auth.js', auth.lines, 'auth');

  // Resources across the three stacks until the file target is roughly met (filler covers the rest).
  const resourceFiles = Math.max(3, Math.floor(options.files * 0.3));
  let n = 0;
  while (files < resourceFiles) {
    const noun = `${NOUNS[n % NOUNS.length]}${n >= NOUNS.length ? Math.floor(n / NOUNS.length) : ''}`;
    const stack = n % 3;
    if (stack === 0) {
      const plant = nextPlant();
      const kind = plant === 'fail-open-auth' ? nextPlant() : plant;
      const r = expressRouter(noun, kind);
      const path = `express/src/routes/${noun}.js`;
      loc += write(path, r.text);
      files++;
      record(kind, path, r.lines, noun);
      for (const [a, b, reason] of r.negatives) negatives.push({ path, lines: [a, b], reason });
      loc += write(
        `express/src/repos/${noun}.js`,
        `const { prisma } = require('../prisma');\nmodule.exports = { ${noun.replace(/s$/, '')}Repo: prisma.${noun.replace(/s$/, '')} };\n`,
      );
      files++;
    } else if (stack === 1) {
      let kind = nextPlant();
      if (kind && kind !== 'sibling-without-scope') kind = 'sibling-without-scope';
      const c = nestController(noun, kind);
      const path = `nest/src/${noun}/${noun}.controller.ts`;
      loc += write(path, c.text);
      loc += write(`nest/src/${noun}/${noun}.service.ts`, nestService(noun));
      files += 2;
      record(kind, path, c.lines, noun);
    } else {
      let kind = nextPlant();
      if (kind && kind !== 'sibling-without-scope' && kind !== 'raw-sql-concat') kind = 'sibling-without-scope';
      const b = flaskBlueprint(noun, kind);
      const path = `flask/app/blueprints/${noun}.py`;
      loc += write(path, b.text);
      files++;
      record(kind, path, b.lines, noun);
    }
    n++;
  }
  // Filler modules (no signals) make up the file and LOC targets; the planner must exclude them.
  let k = 0;
  while (files < options.files || loc < options.loc) {
    const remainingLoc = Math.max(0, options.loc - loc);
    const remainingFiles = Math.max(1, options.files - files);
    const size = Math.min(400, Math.max(30, Math.floor(remainingLoc / remainingFiles)));
    loc += write(`shared/util/mod${String(k).padStart(4, '0')}.js`, fillerModule(`mod${k}`, size, random));
    files++;
    k++;
    if (k > 100_000) break;
  }
  write(
    'README.md',
    `# Synthetic scale fixture\n\nGenerated with seed ${options.seed}: ${files} files, ~${loc} lines, ${planted.length} planted finding(s).\n`,
  );
  return { files, loc, planted, negatives };
}

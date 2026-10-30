import { resolve } from 'node:path';
import type { CodeGraphView, InvestigationSubject, SourceTree } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import {
  AgentInvestigator,
  createGraphTools,
  loadPromptBundle,
  ScriptedProvider,
  scriptedInvestigationProvider,
} from '../src/index';

const PROMPTS = resolve(__dirname, '../../../prompts');
const files: Record<string, string> = {
  'orders.controller.ts': [
    '@Controller("orders")',
    'export class OrdersController {',
    '  @Get(":id")',
    '  findOne(id: string) {',
    '    return this.orders.findById(id);',
    '  }',
    '}',
  ].join('\n'),
  'orders.service.ts': 'export class OrdersService {\n  findById(id: string) { return db.find(id); }\n}\n',
};
const source: SourceTree = {
  root: '/virtual',
  listFiles: async () => [],
  readText: async (p) => files[p],
  gitInfo: async () => undefined,
};

const endpoint = {
  id: 'orders.controller.ts#GET /orders/:id@3',
  path: 'orders.controller.ts',
  line: 3,
  method: 'GET',
  route: '/orders/:id',
  framework: 'nestjs',
  handlers: ['orders.controller.ts::OrdersController.findOne'],
  controls: [],
};
const handler = {
  key: 'orders.controller.ts::OrdersController.findOne',
  path: 'orders.controller.ts',
  name: 'findOne',
  qualifiedName: 'OrdersController.findOne',
  kind: 'method' as const,
  startLine: 3,
  endLine: 6,
  exported: true,
};
const graph: CodeGraphView = {
  symbolCount: 2,
  getSymbol: (key) => (key === handler.key ? handler : undefined),
  symbolAt: () => handler,
  search: () => [handler],
  callers: () => [],
  callees: (key) =>
    key === handler.key
      ? [
          {
            from: handler.key,
            to: 'orders.service.ts::OrdersService.findById',
            path: 'orders.controller.ts',
            line: 5,
            confidence: 'HIGH',
          },
        ]
      : [],
  endpoints: () => [endpoint],
  authContext: (id) =>
    id === endpoint.id
      ? {
          endpoint,
          handlers: [handler],
          controls: [
            {
              ref: 'JwtAuthGuard',
              name: 'JwtAuthGuard',
              kind: 'AUTHENTICATION',
              source: 'decorator',
              path: 'orders.controller.ts',
              line: 1,
            },
          ],
          hasAuthentication: true,
          hasAuthorization: false,
        }
      : undefined,
};

const subject: InvestigationSubject = {
  scan: { scanId: 'scan_1' } as InvestigationSubject['scan'],
  snapshotPaths: Object.keys(files),
  graph,
  scannerCandidates: [],
  redactions: [],
};

const finding = {
  category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
  cwe: ['CWE-639'],
  title: 'Any authenticated user can read any order',
  summary: 'GET /orders/:id loads the order by id without checking ownership.',
  confidence: 'HIGH',
  severity: 'HIGH',
  attacker: 'authenticated user',
  invariantViolated: 'callers may only read their own orders',
  locations: [{ path: 'orders.controller.ts', startLine: 4, endLine: 5, role: 'primary' }],
  evidence: ['findOne passes id straight to findById'],
  counterevidence: [],
  remediation: 'Scope the lookup by the authenticated user id.',
};

describe('graph tools', () => {
  const tool = (name: string) =>
    createGraphTools(graph).find((t) => t.name === name) as unknown as { run: (i: unknown) => Promise<string> };
  it('lists endpoints with controls and explains auth context', async () => {
    expect(await tool('list_endpoints').run({})).toContain('JwtAuthGuard:authentication');
    const ctx = await tool('auth_context').run({ endpoint_id: endpoint.id });
    expect(ctx).toContain('authorization detected: false');
    expect(await tool('callees').run({ key: handler.key })).toContain('OrdersService.findById');
    await expect(tool('auth_context').run({ endpoint_id: 'nope' })).rejects.toThrow('unknown endpoint');
  });
});

describe('AgentInvestigator', () => {
  const prompts = loadPromptBundle(PROMPTS);

  it('runs planner, investigators and auditor, converting findings to drafts', async () => {
    const providers: ScriptedProvider[] = [];
    const provider = () => {
      const p = new ScriptedProvider([
        (request) => {
          if (request.tools.some((t) => t.name === 'submit_threat_model')) {
            return {
              content: [
                {
                  type: 'tool_use',
                  id: 'p',
                  name: 'submit_threat_model',
                  input: {
                    summary: 'Nest API with JWT auth',
                    trustBoundaries: ['user -> api'],
                    packets: [
                      {
                        packetId: 'authz-1',
                        perspective: 'AUTHZ_AND_BUSINESS_LOGIC',
                        attacker: 'authenticated user',
                        protectedAsset: 'other users orders',
                        entryPoints: [{ path: 'orders.controller.ts', line: 3, label: 'GET /orders/:id' }],
                        expectedControls: ['ownership check'],
                        questions: ['Does findOne verify the caller owns the order?'],
                      },
                    ],
                    notes: [],
                  },
                },
              ],
            };
          }
          const isAuditor = request.system.includes('independent application security auditor');
          return {
            content: [
              {
                type: 'tool_use',
                id: 'i',
                name: 'submit_investigation',
                input: {
                  findings: isAuditor ? [] : [finding],
                  resolvedQuestions: [],
                  reviewedFiles: ['orders.controller.ts'],
                  deferred: isAuditor ? ['time'] : [],
                },
              },
            ],
          };
        },
      ]);
      providers.push(p);
      return p;
    };
    const investigator = new AgentInvestigator({ provider, prompts });
    const outcome = await investigator.investigate(subject, source, { maxCostUsd: 5 });
    expect(outcome.runs.map((r) => r.role)).toEqual(['planner', 'investigator', 'auditor']);
    expect(outcome.drafts).toHaveLength(1);
    expect(outcome.drafts[0]).toMatchObject({
      scanner: 'ai',
      ruleId: 'ai.investigator.broken_object_level_authorization',
      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
      severityHint: 'HIGH',
    });
    expect(outcome.drafts[0]?.locations[0]).toMatchObject({
      path: 'orders.controller.ts',
      startLine: 4,
      role: 'primary',
    });
    expect(outcome.deferred).toEqual(['auditor: time']);
    // providers[0] is created by the constructor for `info`, then planner, investigator, auditor.
    expect(providers).toHaveLength(4);
    expect(JSON.stringify(providers[2]?.requests[0]?.messages[0])).toContain('authz-1');
    expect(JSON.stringify(providers[3]?.requests[0]?.messages[0])).not.toContain('authz-1');
  });

  it('rejects findings with bad citations or without a primary location', async () => {
    const bad = { ...finding, locations: [{ path: 'missing.ts', startLine: 1, endLine: 1, role: 'primary' }] };
    const noPrimary = {
      ...finding,
      locations: [{ path: 'orders.controller.ts', startLine: 4, endLine: 4, role: 'sink' }],
    };
    const provider = () =>
      new ScriptedProvider([
        (request) =>
          request.tools.some((t) => t.name === 'submit_threat_model')
            ? {
                content: [
                  {
                    type: 'tool_use',
                    id: 'p',
                    name: 'submit_threat_model',
                    input: { summary: 's', trustBoundaries: [], packets: [], notes: [] },
                  },
                ],
              }
            : {
                content: [
                  {
                    type: 'tool_use',
                    id: 'a1',
                    name: 'submit_investigation',
                    input: { findings: [bad], resolvedQuestions: [], reviewedFiles: [], deferred: [] },
                  },
                ],
              },
        () => ({
          content: [
            {
              type: 'tool_use',
              id: 'a2',
              name: 'submit_investigation',
              input: { findings: [noPrimary], resolvedQuestions: [], reviewedFiles: [], deferred: [] },
            },
          ],
        }),
        () => ({
          content: [
            {
              type: 'tool_use',
              id: 'a3',
              name: 'submit_investigation',
              input: { findings: [finding], resolvedQuestions: [], reviewedFiles: [], deferred: [] },
            },
          ],
        }),
      ]);
    const outcome = await new AgentInvestigator({ provider, prompts }).investigate(subject, source, { maxCostUsd: 5 });
    expect(outcome.runs.map((r) => r.role)).toEqual(['planner', 'auditor']);
    expect(outcome.drafts).toHaveLength(1);
    expect(outcome.runs[1]?.steps).toHaveLength(3);
  });

  it('ships a scripted provider that exercises the pipeline without findings', async () => {
    const outcome = await new AgentInvestigator({ provider: scriptedInvestigationProvider, prompts }).investigate(
      subject,
      source,
      { maxCostUsd: 1 },
    );
    expect(outcome.drafts).toEqual([]);
    expect(outcome.runs.every((r) => r.status === 'COMPLETED')).toBe(true);
    expect(outcome.costUsd).toBe(0);
  });
});

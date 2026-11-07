import { resolve } from 'node:path';
import type { CodeGraphView, InvestigationSubject, SourceTree } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import {
  AgentInvestigator,
  createGraphTools,
  loadPromptBundle,
  ScriptedProvider,
  scriptedInvestigationProvider,
  scriptedLogicProvider,
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
  claim: 'An authenticated user can read any order by id without an ownership check.',
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
    const investigator = new AgentInvestigator({ provider, prompts, recon: { enabled: false } });
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

  it('offers the lite deliverable to prompted-tool models and lifts it (ADR-054)', async () => {
    class Prompted extends ScriptedProvider {
      override capabilities() {
        return { ...super.capabilities(), toolMode: 'prompted' as const, maxContext: 32_768 };
      }
    }
    const providers: Prompted[] = [];
    const provider = () => {
      const p = new Prompted([
        (request) => {
          const submit = request.tools.find((t) => t.name === 'submit_investigation');
          if (!submit) {
            return {
              content: [
                {
                  type: 'tool_use',
                  id: 'p',
                  name: 'submit_threat_model',
                  input: { summary: 's', trustBoundaries: [], packets: [], notes: [] },
                },
              ],
            };
          }
          const props = (
            submit.inputSchema as { properties: Record<string, { items?: { properties?: Record<string, unknown> } }> }
          ).properties;
          expect(props.findings?.items?.properties).not.toHaveProperty('attacker');
          expect(props.findings?.items?.properties).toHaveProperty('claim');
          return {
            content: [
              {
                type: 'tool_use',
                id: 'i',
                name: 'submit_investigation',
                input: {
                  findings: [
                    {
                      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
                      cwe: ['CWE-639'],
                      title: 'Order lookup without ownership check',
                      summary: 'findOne returns any order by id.',
                      severity: 'HIGH',
                      confidence: 'HIGH',
                      claim: 'Any authenticated user can read any order.',
                      path: 'orders.controller.ts',
                      startLine: 4,
                      evidence: ['orders.controller.ts:5 findById(id) without owner filter'],
                      remediation: 'Filter by the caller.',
                    },
                  ],
                },
              },
            ],
          };
        },
      ]);
      providers.push(p);
      return p;
    };
    const investigator = new AgentInvestigator({ provider, prompts, recon: { enabled: false } });
    const outcome = await investigator.investigate(subject, source, { maxCostUsd: 5 });
    expect(outcome.drafts).toHaveLength(1);
    expect(outcome.drafts[0]).toMatchObject({ scanner: 'ai', category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION' });
    expect(outcome.drafts[0]?.message).toContain('Claim: Any authenticated user can read any order.');
    expect(outcome.drafts[0]?.message).toContain('not enumerated by a lite submission');
    expect(outcome.drafts[0]?.locations[0]).toMatchObject({
      path: 'orders.controller.ts',
      startLine: 4,
      role: 'primary',
    });
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
    const outcome = await new AgentInvestigator({ provider, prompts, recon: { enabled: false } }).investigate(
      subject,
      source,
      { maxCostUsd: 5 },
    );
    expect(outcome.runs.map((r) => r.role)).toEqual(['planner', 'auditor']);
    expect(outcome.drafts).toHaveLength(1);
    expect(outcome.runs[1]?.steps).toHaveLength(3);
  });

  it('ships a scripted provider that exercises the pipeline without findings', async () => {
    const outcome = await new AgentInvestigator({
      provider: scriptedInvestigationProvider,
      prompts,
      recon: { enabled: false },
    }).investigate(subject, source, { maxCostUsd: 1 });
    expect(outcome.drafts).toEqual([]);
    expect(outcome.runs.every((r) => r.status === 'COMPLETED')).toBe(true);
    expect(outcome.costUsd).toBe(0);
  });
});

describe('AgentInvestigator recon-first flow (ADR-049)', () => {
  const prompts = loadPromptBundle(PROMPTS);
  const recon = {
    threatModel: {
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
    groundTruth: {
      archetype: 'http_api',
      invariants: [
        {
          invariantId: 'INV-1',
          location: { path: 'orders.controller.ts', startLine: 4, endLine: 5 },
          expected: 'findOne scopes the lookup to the caller',
          howToCheck: 'read findById',
          packets: ['authz-1'],
          familyId: 'FAM-1',
        },
      ],
      baselines: [
        {
          baselineId: 'BL-1',
          pattern: 'owner-scoped lookup',
          location: { path: 'orders.service.ts', startLine: 2, endLine: 2 },
          whyCorrect: 'service exposes the lookup; callers must scope it',
        },
      ],
      families: [
        {
          familyId: 'FAM-1',
          rootCause: 'order lookups by id',
          baselineId: 'BL-1',
          members: [
            { path: 'orders.controller.ts', startLine: 3, label: 'GET /orders/:id' },
            { path: 'orders.service.ts', startLine: 2, label: 'OrdersService.findById' },
          ],
        },
      ],
      carveouts: [
        {
          carveoutId: 'CO-1',
          pattern: 'service methods take an id without a user',
          justification: 'authorization is a controller concern here',
          evidence: [{ path: 'orders.service.ts', startLine: 2, endLine: 2 }],
        },
      ],
      residualUnknowns: [],
      notes: [],
    },
  };
  const complete = {
    findings: [{ ...finding, invariantId: 'INV-1', familyId: 'FAM-1', baselineReference: 'BL-1' }],
    resolvedQuestions: [],
    reviewedFiles: ['orders.controller.ts'],
    deferred: [],
    invariantResults: [{ invariantId: 'INV-1', result: 'FAIL', evidence: [], note: '' }],
    variantLog: [
      { familyId: 'FAM-1', member: { path: 'orders.controller.ts', startLine: 3 }, verdict: 'VULNERABLE', note: '' },
      { familyId: 'FAM-1', member: { path: 'orders.service.ts', startLine: 2 }, verdict: 'SAFE', note: '' },
    ],
  };
  const empty = {
    findings: [],
    resolvedQuestions: [],
    reviewedFiles: [],
    deferred: [],
    invariantResults: [],
    variantLog: [],
  };

  it('runs recon, slices ground truth per packet, rejects incomplete checklists and stops the critic early', async () => {
    const providers: ScriptedProvider[] = [];
    const provider = () => {
      const p = new ScriptedProvider([
        (request) => {
          if (request.tools.some((t) => t.name === 'submit_recon'))
            return { content: [{ type: 'tool_use', id: 'r', name: 'submit_recon', input: recon }] };
          const critic = request.system.includes('completeness re-pass');
          const auditor = request.system.includes('independent application security auditor');
          if (critic || auditor)
            return {
              content: [
                {
                  type: 'tool_use',
                  id: 'c',
                  name: 'submit_investigation',
                  input: { ...empty, deferred: auditor ? ['time'] : [] },
                },
              ],
            };
          // Investigator: first a FAIL without a finding (rejected), then the complete deliverable.
          return {
            content: [
              {
                type: 'tool_use',
                id: 'i1',
                name: 'submit_investigation',
                input: { ...complete, findings: [] },
              },
            ],
          };
        },
        () => ({ content: [{ type: 'tool_use', id: 'i2', name: 'submit_investigation', input: complete }] }),
      ]);
      providers.push(p);
      return p;
    };
    const outcome = await new AgentInvestigator({
      provider,
      prompts,
      recon: { criticPasses: 2 },
      context: {
        accepted_risks: ['Admins may read every order.'],
        roles: [],
        trust_claims: [],
        business_invariants: [],
      },
    }).investigate(subject, source, { maxCostUsd: 5 });
    expect(outcome.runs.map((r) => r.role)).toEqual(['recon', 'investigator', 'auditor', 'critic']);
    expect(outcome.drafts).toHaveLength(1);
    expect(outcome.drafts[0]?.claim?.claim).toContain('authenticated user');
    expect(outcome.drafts[0]?.message).toContain('Claim:');
    expect(outcome.groundTruth?.invariants).toHaveLength(1);
    expect(outcome.groundTruth?.carveouts.map((c) => c.carveoutId)).toEqual(['CO-1', 'CO-900']);
    expect(outcome.coverage).toEqual({ invariantGaps: [], invariantTotal: 1, memberGaps: [], memberTotal: 2 });
    expect(outcome.deferred).toEqual(['auditor: time']);
    // providers[0]: constructor; [1]: recon; [2]: investigator; [3]: auditor; [4]: critic.
    const reconPrompt = JSON.stringify(providers[1]?.requests[0]?.messages[0]);
    expect(reconPrompt).toContain('<census_json>');
    expect(reconPrompt).toContain('<operator_context');
    const investigatorRequests = providers[2]?.requests ?? [];
    expect(investigatorRequests).toHaveLength(2);
    const investigatorPrompt = JSON.stringify(investigatorRequests[0]?.messages[0]);
    expect(investigatorPrompt).toContain('<ground_truth');
    expect(investigatorPrompt).toContain('INV-1');
    expect(JSON.stringify(investigatorRequests[1]?.messages.at(-1))).toContain('INV-1 is FAIL but no finding');
    expect(providers[2]?.requests[0]?.system).toContain('Admins may read every order.');
    const auditorPrompt = JSON.stringify(providers[3]?.requests[0]?.messages[0]);
    expect(auditorPrompt).toContain('CO-1');
    expect(auditorPrompt).not.toContain('INV-1');
    const criticPrompt = JSON.stringify(providers[4]?.requests[0]?.messages[0]);
    expect(criticPrompt).toContain('Already reported');
    expect(criticPrompt).toContain(finding.title);
    expect(providers).toHaveLength(5);
  });

  it('keeps going without ground truth when recon fails', async () => {
    const provider = () =>
      new ScriptedProvider([
        (request) =>
          request.tools.some((t) => t.name === 'submit_recon')
            ? { content: [{ type: 'text', text: 'I cannot do this.' }], stopReason: 'end_turn' }
            : { content: [{ type: 'tool_use', id: 'a', name: 'submit_investigation', input: empty }] },
      ]);
    const outcome = await new AgentInvestigator({ provider, prompts }).investigate(subject, source, { maxCostUsd: 5 });
    expect(outcome.runs.map((r) => r.role)).toEqual(['recon', 'auditor']);
    expect(outcome.infraFailures?.[0]).toContain('recon');
    expect(outcome.deferred).toContain('recon failed: investigators ran without ground truth');
  });

  it('ships a scripted logic provider that derives packets from the census', async () => {
    const outcome = await new AgentInvestigator({ provider: scriptedLogicProvider, prompts }).investigate(
      subject,
      source,
      { maxCostUsd: 1 },
    );
    expect(outcome.runs.map((r) => r.role)).toEqual(['recon', 'auditor']);
    expect(outcome.groundTruth?.archetype).toBe('http_api');
  });
});

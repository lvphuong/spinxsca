import { resolve } from 'node:path';
import type { ReduceInput, ShardSubject, SourceTree } from '@spinxsca/core';
import type { AiFinding, Shard } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import {
  AgentMapReduceInvestigator,
  type CompletionRequest,
  emptyGroundTruth,
  loadPromptBundle,
  ScriptedProvider,
  type ScriptedTurn,
} from '../src/index';

const PROMPTS = resolve(__dirname, '../../../prompts');
const prompts = loadPromptBundle(PROMPTS);
const files: Record<string, string> = {
  'src/orders/controller.ts': [
    'export class Orders {',
    '  get(id) {',
    '    return db.query("select * from orders where id = " + id);',
    '  }',
    '}',
  ].join('\n'),
  'src/orders/service.ts': 'export const helper = () => 1;\n',
  'src/users/controller.ts': [
    'export class Users {',
    '  get(id) {',
    '    return db.query("select * from users where id = " + id);',
    '  }',
    '}',
  ].join('\n'),
};
const source: SourceTree = {
  root: '/virtual',
  listFiles: async () => [],
  readText: async (p) => files[p],
  gitInfo: async () => undefined,
};
const shard = (id: string, paths: string[], neighbors: string[] = []): Shard => ({
  shardId: id,
  digest: `sha256:${'a'.repeat(64)}`,
  module: paths[0]?.split('/').slice(0, 2).join('/') ?? '',
  files: paths.map((p) => ({
    path: p,
    digest: `sha256:${'b'.repeat(64)}`,
    bytes: 100,
    tokens: 25,
    score: 2,
    signals: 1,
  })),
  tokens: 25 * paths.length,
  score: 2,
  priority: 0,
  neighbors,
  oversized: false,
  signals: paths.map((p) => ({ path: p, line: 3, selectorId: 'lex.sqli.raw_query', weight: 2, evidence: 'db.query(' })),
});
const finding = (path: string, title = 'SQL injection in get', extra: Partial<AiFinding> = {}): AiFinding => ({
  category: 'SQL_INJECTION',
  cwe: ['CWE-89'],
  title,
  summary: 'Concatenated id reaches db.query.',
  confidence: 'HIGH',
  severity: 'HIGH',
  attacker: 'any caller',
  invariantViolated: 'queries are parameterised',
  claim: `${path} concatenates the id into SQL`,
  preconditions: [],
  capabilitiesGained: ['read any row'],
  proofObligations: [],
  threatModelClass: 'real_bug',
  locations: [{ path, startLine: 3, endLine: 3, role: 'primary' }],
  evidence: [`${path}:3 db.query(... + id)`],
  counterevidence: [],
  remediation: 'Use parameters.',
  ...extra,
});
const submit = (input: unknown): ScriptedTurn => ({
  content: [{ type: 'tool_use', id: 's', name: 'submit_investigation', input }],
});
const scan = { scanId: 's1' } as ShardSubject['scan'];
const subjectFor = (s: Shard): ShardSubject => ({
  scan,
  shard: s,
  snapshotPaths: Object.keys(files),
  groundTruth: emptyGroundTruth(),
  scannerCandidates: [],
  redactions: [],
});

describe('AgentMapReduceInvestigator (ADR-055)', () => {
  it('rejects a mapper finding whose primary line is outside the owned files, then accepts the corrected one', async () => {
    const provider = new ScriptedProvider([
      submit({
        findings: [finding('src/users/controller.ts')],
        resolvedQuestions: [],
        reviewedFiles: [],
        deferred: [],
      }),
      submit({
        findings: [finding('src/orders/controller.ts')],
        resolvedQuestions: [],
        reviewedFiles: ['src/orders/controller.ts'],
        deferred: ['cross-shard: src/users/controller.ts:3 - same pattern'],
      }),
    ]);
    const mr = new AgentMapReduceInvestigator({ providers: { deep: () => provider }, prompts });
    const out = await mr.map(
      subjectFor(
        shard('shard-0001', ['src/orders/controller.ts', 'src/orders/service.ts'], ['src/users/controller.ts']),
      ),
      source,
      {
        maxCostUsd: 1,
      },
    );
    const rejection = (provider.requests[1] as CompletionRequest).messages.at(-1);
    expect(JSON.stringify(rejection)).toContain('does not own');
    expect(out.findings).toHaveLength(1);
    expect(out.deferred).toEqual(['shard-0001: cross-shard: src/users/controller.ts:3 - same pattern']);
    expect(out.run.role).toBe('mapper');
    const first = (provider.requests[0] as CompletionRequest).messages[0] as { content: Array<{ text: string }> };
    const prompt = first.content.map((c) => c.text).join('\n');
    expect(prompt).toContain('<shard id="shard-0001">');
    expect(prompt).toContain('<signals>');
    expect(prompt).toContain('Readable neighbours');
  });

  it('reduces deterministically, keeps unjustified drops with low confidence and attaches chains', async () => {
    const maps: ReduceInput['maps'] = [
      {
        findings: [
          finding('src/orders/controller.ts'),
          finding('src/orders/controller.ts', 'SQL injection in get (dup)'),
        ],
        invariantResults: [],
        variantLog: [],
        reviewedFiles: [],
        deferred: [],
      },
      {
        findings: [
          finding('src/users/controller.ts', 'Users SQLi', { severity: 'MEDIUM', preconditions: ['read any row'] }),
        ],
        invariantResults: [],
        variantLog: [],
        reviewedFiles: [],
        deferred: [],
      },
    ];
    const reducer = new ScriptedProvider([
      {
        content: [
          {
            type: 'tool_use',
            id: 'r',
            name: 'submit_reduction',
            input: {
              findings: [
                { ref: 'F-1', keep: true, severity: 'HIGH', confidence: 'HIGH', rationale: 'well evidenced' },
                { ref: 'F-2', keep: false, severity: 'MEDIUM', confidence: 'MEDIUM', rationale: 'seems unlikely' },
              ],
              chains: [
                {
                  chainId: 'CH-1',
                  members: ['F-1', 'F-2'],
                  combinedSeverity: 'CRITICAL',
                  narrative: 'F-1 reads rows that F-2 needs.',
                  combinedPreconditions: [],
                },
              ],
              ranking: ['F-1', 'F-2'],
              notes: [],
            },
          },
        ],
      },
    ]);
    const mr = new AgentMapReduceInvestigator({ providers: { deep: () => reducer }, prompts });
    const out = await mr.reduce(
      { scan, groundTruth: emptyGroundTruth(), maps, scannerCandidates: [], redactions: [] },
      { maxCostUsd: 1 },
    );
    expect(out.drafts).toHaveLength(2);
    expect(out.drafts.map((d) => d.locations[0]?.path)).toEqual([
      'src/orders/controller.ts',
      'src/users/controller.ts',
    ]);
    expect(out.drafts[1]?.confidenceHint).toBe('LOW');
    expect(out.deferred.join(' ')).toContain('without a carve-out or duplicate');
    expect(out.chains).toHaveLength(1);
    expect(out.drafts[0]?.message).toContain('Attack chain CH-1 (CRITICAL)');
    const table = JSON.stringify((reducer.requests[0] as CompletionRequest).messages[0]);
    expect(table).toContain('F-1 | HIGH');
    expect(table).toContain('merged duplicates: 1');
    expect(table).not.toContain('db.query("select');
  });

  it('falls back to the deterministic order when the reducer fails', async () => {
    const broken = new ScriptedProvider([
      { content: [{ type: 'text', text: 'I give up' }] },
      { content: [{ type: 'text', text: 'still no' }] },
      { content: [{ type: 'text', text: 'nope' }] },
    ]);
    const mr = new AgentMapReduceInvestigator({ providers: { deep: () => broken }, prompts });
    const out = await mr.reduce(
      {
        scan,
        groundTruth: emptyGroundTruth(),
        maps: [
          {
            findings: [finding('src/orders/controller.ts')],
            invariantResults: [],
            variantLog: [],
            reviewedFiles: [],
            deferred: [],
          },
        ],
        scannerCandidates: [],
        redactions: [],
      },
      { maxCostUsd: 1 },
    );
    expect(out.drafts).toHaveLength(1);
    expect(out.deferred[0]).toContain('reducer failed');
    expect(out.run?.role).toBe('reducer');
    expect(mr.mapWorkers()).toBe(4);
    expect(mr.mapEffectiveWindow()).toBeGreaterThan(100_000);
  });
});

import { resolve } from 'node:path';
import type { ExplainSubject, SourceTree } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import {
  AgentExplainer,
  costOf,
  createCodeTools,
  loadPromptBundle,
  ScriptedProvider,
  scriptedExplainProvider,
} from '../src/index';

const PROMPTS = resolve(__dirname, '../../../prompts');
const files: Record<string, string> = {
  'routes/users.js': [
    "router.get('/u', async (req, res) => {",
    '  const name = req.query.name;',
    '  const sql = "SELECT * FROM users WHERE name = \'" + name + "\'";',
    '  await db.query(sql);',
    '});',
  ].join('\n'),
  'config.js': 'const token = "Zx9Kq2Lm7Rt4Vb8Nc3Jd6Hf1Gp5Ws0Ya";\n',
};
const source: SourceTree = {
  root: '/virtual',
  listFiles: async () => [],
  readText: async (p) => files[p],
  gitInfo: async () => undefined,
};

const now = '2026-10-29T00:00:00.000Z';
const subject: ExplainSubject = {
  scan: { scanId: 'scan_1' } as ExplainSubject['scan'],
  finding: {
    findingId: 'SPX-000001',
    projectId: 'p',
    seq: 1,
    category: 'SQL_INJECTION',
    ruleFamily: 'sqli',
    title: 'SQL injection from HTTP request input',
    cwe: ['CWE-89'],
    canonicalFingerprint: 'fp',
    fingerprintAlgorithm: 'spinxsca/fp/v1',
    firstSeenScanId: 'scan_1',
    createdAt: now,
  },
  occurrence: {
    occurrenceId: 'o',
    findingId: 'SPX-000001',
    scanId: 'scan_1',
    snapshotId: 's',
    locations: [{ path: 'routes/users.js', startLine: 4, endLine: 4, role: 'primary' }],
    fingerprint: 'spx1:abc',
    anchor: { path: 'routes/users.js', symbol: '', shape: 'x', instance: 0 },
    ruleIds: ['spinxsca-core.js-sql-injection'],
    candidateIds: ['c'],
    evidenceIds: [],
  },
  candidates: [],
  evidence: [],
  snapshotPaths: Object.keys(files),
  related: [],
  redactions: [{ path: 'config.js', startLine: 1, endLine: 1, startColumn: 15, endColumn: 49, role: 'primary' }],
};

describe('prompt bundle', () => {
  it('expands includes and has a stable digest', () => {
    const bundle = loadPromptBundle(PROMPTS);
    const system = bundle.render('explain');
    expect(system).toContain('## Untrusted input');
    expect(system).toContain('## Severity rubric');
    expect(system).not.toContain('@include');
    expect(loadPromptBundle(PROMPTS).digest).toBe(bundle.digest);
  });
});

describe('pricing', () => {
  it('prices known models and refuses to guess unknown ones', () => {
    expect(
      costOf({ inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 }, 'claude-opus-5-5'),
    ).toBe(4);
    expect(
      costOf({ inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 }, 'some-local-model'),
    ).toBeUndefined();
  });
});

describe('code tools', () => {
  const tools = createCodeTools({ source, paths: subject.snapshotPaths, redactions: subject.redactions });
  const tool = (name: string) =>
    tools.find((t) => t.name === name) as unknown as { run: (i: unknown) => Promise<string> };

  it('reads numbered lines, masks secrets and marks content untrusted', async () => {
    const out = await tool('read_file').run({ path: 'config.js' });
    expect(out).toContain('<untrusted_repository_content path="config.js"');
    expect(out).toContain('<REDACTED:secret>');
    expect(out).not.toContain('Zx9Kq2');
  });

  it('refuses paths outside the snapshot and searches literally', async () => {
    await expect(tool('read_file').run({ path: '../etc/passwd' })).rejects.toThrow('not a readable text file');
    expect(await tool('search_code').run({ query: 'db.query(' })).toContain('routes/users.js:4:');
    expect(await tool('search_code').run({ query: '.*' })).toBe('No matches.');
  });
});

describe('AgentExplainer', () => {
  const prompts = loadPromptBundle(PROMPTS);

  it('runs the scripted provider end to end and records the run', async () => {
    const explainer = new AgentExplainer({ provider: scriptedExplainProvider, prompts });
    const outcome = await explainer.explain(subject, source);
    expect(outcome.run.status).toBe('COMPLETED');
    expect(outcome.explanation?.classification).toBe('POTENTIAL');
    expect(outcome.run).toMatchObject({
      role: 'explain',
      findingId: 'SPX-000001',
      subjectDigest: 'spx1:abc',
      provider: 'scripted',
      costUsd: 0,
    });
    expect(outcome.run.steps.map((s) => s.toolCalls.map((t) => t.name))).toEqual([
      ['read_file'],
      ['submit_explanation'],
    ]);
    expect(explainer.info.promptBundleDigest).toBe(prompts.digest);
  });

  it('rejects citations that do not exist in the snapshot', async () => {
    const submission = (path: string, endLine: number) => ({
      type: 'tool_use' as const,
      id: `s-${path}-${endLine}`,
      name: 'submit_explanation',
      input: {
        summary: 's',
        classification: 'CONFIRMED',
        severity: 'HIGH',
        severityRationale: 'r',
        selfRefutationCheck: 'none',
        confidence: 'HIGH',
        attackPath: { attacker: 'a', entryPoint: 'e', source: 's', sink: 'k', preconditions: [], controls: [] },
        evidence: [{ path, startLine: 1, endLine, explanation: 'x' }],
        counterevidence: [],
        missingEvidence: [],
        remediation: { strategy: 'parameterize', steps: ['use placeholders'] },
      },
    });
    const provider = new ScriptedProvider([
      { content: [submission('routes/missing.js', 1)] },
      { content: [submission('routes/users.js', 99)] },
      { content: [submission('routes/users.js', 4)] },
    ]);
    const explainer = new AgentExplainer({ provider: () => provider, prompts });
    const outcome = await explainer.explain(subject, source);
    expect(outcome.run.status).toBe('COMPLETED');
    const errors = provider.requests.slice(1).map((r) => JSON.stringify(r.messages.at(-1)));
    expect(errors[0]).toContain('is not a file in this snapshot');
    expect(errors[1]).toContain('has 5 lines, not 99');
  });
});

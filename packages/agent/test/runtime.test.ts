import { createSecretScrubber, verifyChain } from '@spinxsca/core';
import { type Approver, CallbackApprover, InboxApprover, type PolicyContext } from '@spinxsca/governance';
import type { ActionTarget, AgentStepRecord } from '@spinxsca/schemas';
import { migrate, SqlCaseRepository, sqliteDriver } from '@spinxsca/storage';
import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  assertPriced,
  type CompletionRequest,
  caseSessionStore,
  checkManifest,
  compactView,
  costWithOverrides,
  createExploreTool,
  defineTool,
  GovernedToolExecutor,
  MemorySessionStore,
  type Message,
  type ProviderCapabilities,
  RetryableTurnError,
  runAgentSession,
  SCRIPTED_CAPABILITIES,
  ScriptedProvider,
  type ScriptedTurn,
  Semaphore,
  type SessionStore,
  UnpricedModelError,
} from '../src/index';

const PINNED = `ghcr.io/spinxsca/toolbox@sha256:${'a'.repeat(64)}`;
const Done = z.strictObject({ summary: z.string() });
const submit = { name: 'submit_result', description: 'Submit', output: Done };
const call = (id: string, name: string, input: unknown): ScriptedTurn => ({
  content: [{ type: 'tool_use', id, name, input }],
});
const finish = (id: string): ScriptedTurn => call(id, 'submit_result', { summary: 'done' });

function cases() {
  const db = new Database(':memory:');
  migrate(db);
  return new SqlCaseRepository(sqliteDriver(db));
}

function counterTools() {
  const runs: Record<string, number> = {};
  const count = (name: string) => {
    runs[name] = (runs[name] ?? 0) + 1;
  };
  const read = defineTool({
    name: 'read_file',
    description: 'read',
    input: z.strictObject({ path: z.string() }),
    targets: ({ path }) => [{ kind: 'repo_path', value: path }] as ActionTarget[],
    run: async ({ path }) => {
      count('read_file');
      return path === 'leak.txt' ? 'token=hunter2-very-secret-value and AKIAABCDEFGHIJKLMNOP' : `contents of ${path}`;
    },
  });
  const poc = defineTool({
    name: 'validation_run',
    description: 'run a PoC',
    input: z.strictObject({ handle: z.string() }),
    targets: ({ handle }) => [{ kind: 'handle', value: handle }] as ActionTarget[],
    sandbox: () => ({ network: 'none', image: PINNED, profile: 'validation' }),
    describe: ({ handle }) => ({ title: `Run a proof of concept for ${handle}` }),
    run: async () => {
      count('validation_run');
      return 'oracle: not triggered';
    },
  });
  const apply = defineTool({
    name: 'request_apply',
    description: 'ask a human to apply a patch',
    input: z.strictObject({ patch: z.string() }),
    targets: () => [{ kind: 'workspace_path', value: 'ws1' }] as ActionTarget[],
    run: async () => {
      count('request_apply');
      return 'applied';
    },
  });
  return { runs, tools: [read, poc, apply] };
}

function policy(overrides: Partial<PolicyContext> = {}) {
  return (): PolicyContext => ({
    projectId: 'prj_1',
    mode: 'supervised',
    personaTools: new Set(['read_file', 'validation_run', 'request_apply']),
    scope: { workspaces: new Set(['ws1']), handles: new Set(['CF-1']) },
    now: new Date('2026-11-01T00:00:00Z'),
    ...overrides,
  });
}

function governed(
  repo: SqlCaseRepository,
  tools: ReturnType<typeof counterTools>['tools'],
  approvers: Approver[],
  extra: Partial<PolicyContext> = {},
) {
  return new GovernedToolExecutor({
    cases: repo,
    projectId: 'prj_1',
    caseId: 'case_1',
    runId: 'run_1',
    persona: 'validator',
    tools,
    policy: policy(extra),
    approvers,
    scrubber: createSecretScrubber({ knownValues: ['hunter2-very-secret-value'] }),
  });
}

/** Store that throws once after `failAfter` saves, simulating a process crash at that checkpoint. */
class CrashingStore implements SessionStore {
  saves = 0;
  constructor(
    private readonly inner: SessionStore,
    private failAfter: number,
  ) {}
  load(runId: string) {
    return this.inner.load(runId);
  }
  async save(step: AgentStepRecord) {
    if (this.saves++ === this.failAfter) throw new Error('crash');
    await this.inner.save(step);
  }
}

describe('durable session', () => {
  it('resumes after a crash at any checkpoint without repeating side effects', async () => {
    for (let failAfter = 0; failAfter < 5; failAfter++) {
      const repo = cases();
      const { runs, tools } = counterTools();
      const store = new CrashingStore(caseSessionStore(repo), failAfter);
      const script = [
        call('t1', 'validation_run', { handle: 'CF-1' }),
        call('t2', 'read_file', { path: 'a.ts' }),
        finish('t3'),
      ];
      const approve = new CallbackApprover('alice', async () => ({ approved: true }));
      const opts = (provider: ScriptedProvider) => ({
        runId: 'run_1',
        caseId: 'case_1',
        role: 'validator',
        provider,
        system: 's',
        prompt: 'p',
        tools,
        submit,
        store,
        executor: governed(repo, tools, [approve]),
      });
      let result = await runAgentSession(opts(new ScriptedProvider(script))).catch((e: Error) => e);
      if (result instanceof Error) {
        // Resume with a provider that replays only the turns not yet checkpointed.
        const turns = (await repo.listAgentSteps('run_1')).filter((s) => s.kind === 'turn').length;
        result = await runAgentSession(opts(new ScriptedProvider(script.slice(turns))));
        expect(result.resumed, `failAfter=${failAfter}`).toBe(failAfter > 0);
      }
      expect(result.status, `failAfter=${failAfter}`).toBe('COMPLETED');
      expect(runs.validation_run, `failAfter=${failAfter}`).toBe(1);
      const steps = await repo.listAgentSteps('run_1');
      assertNoOrphans(steps);
    }
  });

  it('suspends on a parked approval and resumes once a human decides', async () => {
    const repo = cases();
    const { runs, tools } = counterTools();
    const parked: string[] = [];
    const inbox = new InboxApprover(async (r) => {
      parked.push(r.approvalId);
    });
    const store = caseSessionStore(repo);
    const base = {
      runId: 'run_1',
      caseId: 'case_1',
      role: 'validator',
      system: 's',
      prompt: 'p',
      tools,
      submit,
      store,
    };
    const first = await runAgentSession({
      ...base,
      provider: new ScriptedProvider([call('t1', 'validation_run', { handle: 'CF-1' })]),
      executor: governed(repo, tools, [inbox]),
    });
    expect(first.status).toBe('SUSPENDED');
    expect(first.suspendedOn?.approvalIds).toHaveLength(1);
    expect(runs.validation_run).toBeUndefined();
    const [pending] = await repo.listApprovals({ status: 'PENDING' });
    expect(pending).toMatchObject({
      tool: 'validation_run',
      effect: 'sandbox',
      title: 'Run a proof of concept for CF-1',
    });

    // Still pending: resuming suspends again without calling the model.
    const again = await runAgentSession({
      ...base,
      provider: new ScriptedProvider([]),
      executor: governed(repo, tools, [inbox]),
    });
    expect(again.status).toBe('SUSPENDED');

    if (!pending) throw new Error('expected a pending approval');
    await repo.resolveApproval(pending.approvalId, {
      status: 'APPROVED',
      resolvedBy: { kind: 'human', id: 'alice' },
      resolvedAt: '2026-11-01T00:00:00Z',
    });
    const resumed = await runAgentSession({
      ...base,
      provider: new ScriptedProvider([finish('t2')]),
      executor: governed(repo, tools, [inbox]),
    });
    expect(resumed.status).toBe('COMPLETED');
    expect(runs.validation_run).toBe(1);
    const audit = await repo.listAudit('case_1');
    expect(audit.map((a) => a.stage)).toEqual(
      expect.arrayContaining([
        'policy.decided',
        'approval.requested',
        'approval.resolved',
        'tool.started',
        'tool.finished',
      ]),
    );
    expect(verifyChain(audit).ok).toBe(true);
  });

  it('never runs a human-only request approved by a non-human', async () => {
    const repo = cases();
    const { runs, tools } = counterTools();
    const rogue: Approver = {
      kind: 'reviewer',
      id: 'rogue',
      decide: async () => ({ status: 'approved', by: { kind: 'reviewer', id: 'rogue' } }),
    };
    const result = await runAgentSession({
      runId: 'run_1',
      caseId: 'case_1',
      role: 'fixer',
      provider: new ScriptedProvider([call('t1', 'request_apply', { patch: 'x' }), finish('t2')]),
      system: 's',
      prompt: 'p',
      tools,
      submit,
      store: caseSessionStore(repo),
      executor: governed(repo, tools, [rogue]),
    });
    expect(result.status).toBe('COMPLETED');
    expect(runs.request_apply).toBeUndefined();
    expect((await repo.getToolCall('case_1', 't1'))?.status).toBe('DENIED');
  });

  it('scrubs secrets from tool output before the model or the store sees it', async () => {
    const repo = cases();
    const { tools } = counterTools();
    const provider = new ScriptedProvider([call('t1', 'read_file', { path: 'leak.txt' }), finish('t2')]);
    await runAgentSession({
      runId: 'run_1',
      caseId: 'case_1',
      role: 'appsec',
      provider,
      system: 's',
      prompt: 'p',
      tools,
      submit,
      store: caseSessionStore(repo),
      executor: governed(repo, tools, []),
    });
    const sent = JSON.stringify(provider.requests);
    const stored = JSON.stringify([await repo.listAgentSteps('run_1'), await repo.listToolCalls('case_1')]);
    for (const text of [sent, stored]) {
      expect(text).not.toContain('hunter2-very-secret-value');
      expect(text).not.toContain('AKIAABCDEFGHIJKLMNOP');
      expect(text).toContain('<REDACTED:secret:');
    }
  });

  it('gives the agent a non-diagnostic denial and stops after five in a row', async () => {
    const repo = cases();
    const { tools } = counterTools();
    const turns = Array.from({ length: 6 }, (_, i) => call(`t${i}`, 'read_file', { path: '.spinxsca/spinxsca.db' }));
    const provider = new ScriptedProvider([...turns, finish('tz')]);
    const result = await runAgentSession({
      runId: 'run_1',
      caseId: 'case_1',
      role: 'appsec',
      provider,
      system: 's',
      prompt: 'p',
      tools,
      submit,
      store: caseSessionStore(repo),
      executor: governed(repo, tools, []),
    });
    expect(result.status).toBe('FAILED');
    expect(result.error).toContain('5 consecutive');
    const lastResult = provider.requests.at(-1)?.messages.at(-1)?.content[0] as { content: string };
    expect(lastResult.content).not.toContain('.spinxsca');
    expect((await repo.listAudit('case_1')).some((a) => a.stage === 'policy.breaker_tripped')).toBe(true);
  });

  it('answers every tool_use when cancelled mid-turn', async () => {
    const controller = new AbortController();
    const slow = defineTool({
      name: 'read_file',
      description: 'r',
      input: z.strictObject({ path: z.string() }),
      run: async () => {
        controller.abort();
        return 'x';
      },
    });
    const store = new MemorySessionStore();
    const result = await runAgentSession({
      runId: 'r',
      role: 'appsec',
      provider: new ScriptedProvider([
        {
          content: [
            { type: 'tool_use', id: 'a', name: 'read_file', input: { path: 'a' } },
            { type: 'tool_use', id: 'b', name: 'read_file', input: { path: 'b' } },
          ],
        },
      ]),
      system: 's',
      prompt: 'p',
      tools: [slow],
      submit,
      store,
      signal: controller.signal,
    });
    expect(result.status).toBe('CANCELLED');
    assertNoOrphans(await store.load('r'));
  });
});

function assertNoOrphans(steps: readonly AgentStepRecord[]) {
  const uses = new Set<string>();
  const results = new Set<string>();
  for (const s of steps) {
    for (const b of s.content as Array<{ type: string; id?: string; toolUseId?: string }>) {
      if (b.type === 'tool_use' && b.id) uses.add(b.id);
      if (b.type === 'tool_result' && b.toolUseId) results.add(b.toolUseId);
    }
  }
  expect([...uses].filter((u) => !results.has(u))).toEqual([]);
}

describe('compaction', () => {
  it('keeps the prompt and recent turns verbatim with intact tool pairs', async () => {
    const messages: Message[] = [{ role: 'user', content: [{ type: 'text', text: 'ORIGINAL TASK' }] }];
    for (let i = 0; i < 12; i++) {
      messages.push({
        role: 'assistant',
        content: [{ type: 'tool_use', id: `u${i}`, name: 'read_file', input: { path: `f${i}.ts` } }],
      });
      messages.push({
        role: 'user',
        content: [{ type: 'tool_result', toolUseId: `u${i}`, content: 'x'.repeat(4000) }],
      });
    }
    const view = await compactView(messages, { thresholdTokens: 1000, keepTurns: 3 });
    expect(view).toHaveLength(1 + 6);
    const head = view[0] as Message;
    expect((head.content[0] as { text: string }).text).toBe('ORIGINAL TASK');
    const summary = (head.content[1] as { text: string }).text;
    expect(summary).toContain('## 3. Tool calls made');
    expect(summary).toContain('f0.ts');
    expect(view[1]?.role).toBe('assistant');
    expect(messages).toHaveLength(25);
    expect(await compactView(messages, { thresholdTokens: 10_000_000, keepTurns: 3 })).toHaveLength(25);
  });
});

/** Scripted provider that declares a small window (a local model). */
class SmallModel extends ScriptedProvider {
  constructor(
    turns: ScriptedTurn[],
    private readonly caps: Partial<ProviderCapabilities>,
  ) {
    super(turns);
  }
  override capabilities(): ProviderCapabilities {
    return { ...SCRIPTED_CAPABILITIES, ...this.caps };
  }
}

describe('context budget in sessions', () => {
  const session = (provider: ScriptedProvider, tools = counterTools().tools) =>
    runAgentSession({ runId: 'r', role: 'test', provider, system: 'sys', prompt: 'go', tools, submit });

  it('compacts by default when the window is small and clamps max_tokens', async () => {
    const turns: ScriptedTurn[] = [];
    for (let i = 0; i < 20; i++) turns.push(call(`u${i}`, 'read_file', { path: `f${i}.ts` }));
    turns.push(finish('done'));
    const tools = counterTools().tools.map((t) =>
      t.name === 'read_file' ? { ...t, run: async () => 'x'.repeat(4_000) } : t,
    );
    const provider = new SmallModel(turns, { maxContext: 8_000, maxOutput: 2_000 });
    const result = await session(provider, tools as never);
    expect(result.status).toBe('COMPLETED');
    expect(result.compactions).toBeGreaterThan(0);
    const last = provider.requests.at(-1) as CompletionRequest;
    expect(last.messages.length).toBeLessThan(2 * 20 + 1);
    const first = last.messages[0] as Message;
    expect((first.content[0] as { text: string }).text).toBe('go');
    for (const r of provider.requests) expect(r.maxTokens).toBeLessThanOrEqual(2_000);
    expect(result.steps.every((s) => (s.contextTokens ?? 0) > 0)).toBe(true);
  });

  it('recovers from a context-length error by shrinking the view', async () => {
    const turns: ScriptedTurn[] = [];
    for (let i = 0; i < 6; i++) turns.push(call(`u${i}`, 'read_file', { path: `f${i}.ts` }));
    let thrown = false;
    turns.push(() => {
      thrown = true;
      throw new RetryableTurnError('prompt is too long: 17000 tokens > 16000 maximum', 'context', {
        detail: { actual: 17_000, limit: 16_000 },
      });
    });
    turns.push((request) => {
      expect(request.messages.length).toBeLessThan(13);
      return { content: [{ type: 'tool_use', id: 'fin', name: 'submit_result', input: { summary: 'done' } }] };
    });
    const tools = counterTools().tools.map((t) =>
      t.name === 'read_file' ? { ...t, run: async () => 'z'.repeat(4_000) } : t,
    );
    const provider = new SmallModel(turns, { maxContext: 1_000_000 });
    const result = await session(provider, tools as never);
    expect(result.status).toBe('COMPLETED');
    expect(thrown).toBe(true);
    const sizes = provider.requests.map((r) => JSON.stringify(r.messages).length);
    expect(sizes.at(-1) as number).toBeLessThan(sizes.at(-2) as number);
  });

  it('repairs a parse error with a corrective turn instead of an identical retry', async () => {
    let attempts = 0;
    const provider = new ScriptedProvider([
      () => {
        attempts++;
        throw new RetryableTurnError('tool call read_file has invalid JSON arguments', 'parse', {
          rawText: '{"name": "read_file", "arg',
        });
      },
      finish('fin'),
    ]);
    const result = await session(provider);
    expect(result.status).toBe('COMPLETED');
    expect(attempts).toBe(1);
    const second = provider.requests[1] as CompletionRequest;
    const [assistant, user] = second.messages.slice(-2) as [Message, Message];
    expect(assistant.role).toBe('assistant');
    expect((assistant.content[0] as { text: string }).text).toContain('"read_file"');
    expect(user.role).toBe('user');
    expect((user.content[0] as { text: string }).text).toContain('could not be used');
  });

  it('treats a cut-off answer as a resume, not a nudge', async () => {
    const provider = new ScriptedProvider([
      { content: [{ type: 'text', text: 'long partial answer' }], stopReason: 'max_tokens' },
      finish('fin'),
    ]);
    const result = await session(provider);
    expect(result.status).toBe('COMPLETED');
    const second = provider.requests[1] as CompletionRequest;
    const lastMessage = second.messages.at(-1) as Message;
    const text = (lastMessage.content[0] as { text: string }).text;
    expect(text).toContain('Output token limit hit');
    expect(text).not.toContain('Finish by calling');
    expect(second.toolChoice).toBe('auto');
  });

  it('asks for a required tool call after an answer without one', async () => {
    const provider = new ScriptedProvider([{ content: [{ type: 'text', text: 'thinking out loud' }] }, finish('fin')]);
    await session(provider);
    expect((provider.requests[1] as { toolChoice?: string }).toolChoice).toBe('required');
  });

  it('clears old read-only tool results before summarising', async () => {
    const turns: ScriptedTurn[] = [];
    for (let i = 0; i < 8; i++) turns.push(call(`u${i}`, 'read_file', { path: `f${i}.ts` }));
    turns.push(finish('done'));
    const tools = counterTools().tools.map((t) =>
      t.name === 'read_file' ? { ...t, run: async () => 'y'.repeat(3_000) } : t,
    );
    // effective 10k, threshold 8k: eight 750-token results cross 60% of it but never the threshold.
    const provider = new SmallModel(turns, { maxContext: 12_000, maxOutput: 2_000 });
    const result = await session(provider, tools as never);
    expect(result.status).toBe('COMPLETED');
    expect(result.compactions).toBe(0);
    const last = provider.requests.at(-1) as CompletionRequest;
    const results = last.messages.flatMap((m) => m.content.filter((b) => b.type === 'tool_result'));
    const cleared = results.filter((b) => b.type === 'tool_result' && b.content.startsWith('[earlier result of'));
    expect(cleared.length).toBe(results.length - 5);
    expect((cleared[0] as { content: string }).content).toContain('read_file(f0.ts)');
  });
});

describe('budget and manifests', () => {
  it('prices with overrides and refuses unpriced models when unattended', () => {
    const cost = costWithOverrides(() => undefined, { 'local-llm': { input: 1, output: 2 } });
    expect(
      cost({ inputTokens: 1_000_000, outputTokens: 1_000_000, cacheReadTokens: 0, cacheWriteTokens: 0 }, 'local-llm'),
    ).toBe(3);
    expect(() => assertPriced('mystery', cost, { attended: false, allowUnpriced: false })).toThrow(UnpricedModelError);
    expect(() => assertPriced('mystery', cost, { attended: true, allowUnpriced: false })).not.toThrow();
    expect(() => assertPriced('local-llm', cost, { attended: false, allowUnpriced: false })).not.toThrow();
  });

  it('rejects manifests that break separation of powers', () => {
    const lead = {
      id: 'lead',
      role: 'lead' as const,
      description: 'd',
      tools: ['board_view', 'validation_run'],
      skills: [],
      tier: 'deep' as const,
    };
    expect(checkManifest(lead).join()).toContain('exceeds the RECORD ceiling');
    const validator = { ...lead, id: 'validator', role: 'validator' as const, tools: ['read_file', 'patch_propose'] };
    expect(checkManifest(validator).join()).toContain('forbidden');
    expect(checkManifest({ ...lead, tools: ['board_view', 'journal_record', 'request_objective_waiver'] })).toEqual([]);
  });
});

describe('explore sub-agent', () => {
  it('gets read tools only and cannot recurse', async () => {
    const { tools } = counterTools();
    const provider = new ScriptedProvider([
      call('e1', 'read_file', { path: 'src/a.ts' }),
      call('e2', 'submit_answer', {
        answer: 'Checked in src/a.ts',
        citations: [{ path: 'src/a.ts', startLine: 1, endLine: 3 }],
      }),
    ]);
    const runs: string[] = [];
    const explore = createExploreTool({
      provider: () => provider,
      tools: [...tools],
      system: 'explore',
      semaphore: new Semaphore(3),
      parentRunId: 'run_parent',
      onRun: (r) => {
        runs.push(`${r.role}:${r.parentRunId}:${r.status}`);
      },
    });
    const out = await explore.run({ question: 'Where is the order owner checked?' }, {});
    expect(out).toContain('src/a.ts:1-3');
    expect(provider.requests[0]?.tools.map((t) => t.name)).toEqual(['read_file', 'read_result', 'submit_answer']);
    expect(runs).toEqual(['explore:run_parent:COMPLETED']);
  });
});

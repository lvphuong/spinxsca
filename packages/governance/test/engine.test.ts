import type { ActionTarget, AutonomyMode, Grant, RiskClass } from '@spinxsca/schemas';
import { TOOL_RISK } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import {
  agentMessage,
  evaluate,
  isProtectedTarget,
  NOT_PERMITTED,
  type PermissionRequest,
  PINNED_TEST_IMAGE,
  type PolicyContext,
  riskOf,
  safeRelPath,
} from '../src/index';

/** Small deterministic PRNG (mulberry32) for property tests without extra dependencies. */
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

const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
const TOOLS = Object.keys(TOOL_RISK);
const MODES: AutonomyMode[] = ['observe', 'supervised', 'autonomous'];

function base(overrides: Partial<PermissionRequest> = {}): PermissionRequest {
  return {
    toolCallId: 'call_1',
    caseId: 'case_1',
    tool: 'read_file',
    inputValid: true,
    targets: [{ kind: 'repo_path', value: 'src/a.ts' }],
    exec: 'none',
    argsText: '{}',
    ...overrides,
  };
}

function ctx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    projectId: 'prj_1',
    mode: 'supervised',
    personaTools: 'any',
    scope: { workspaces: new Set(['ws1']), handles: new Set(['CF-1']) },
    now: new Date('2026-11-01T00:00:00Z'),
    ...overrides,
  };
}

/** Everything a misconfigured or over-generous context could add. */
function generousContext(r: () => number, tool: string): PolicyContext {
  const risk = TOOL_RISK[tool] ?? 'GOVERNANCE';
  const grants: Grant[] = [
    {
      grantId: 'g1',
      projectId: 'prj_1',
      caseId: 'case_1',
      scope: 'case',
      tool,
      target: '*',
      risk: 'EGRESS' as RiskClass,
      createdBy: 'human:x',
      createdAt: '2026-01-01T00:00:00Z',
    },
    {
      grantId: 'g2',
      projectId: 'prj_1',
      scope: 'standing',
      tool,
      target: '*',
      risk,
      createdBy: 'human:x',
      createdAt: '2026-01-01T00:00:00Z',
    },
  ];
  return ctx({
    mode: pick(r, MODES),
    grants,
    autoAllow: TOOLS,
    validationL3: true,
  });
}

describe('policy engine floors (property)', () => {
  const r = rng(20261103);
  const dangerous: Array<(tool: string) => Partial<PermissionRequest>> = [
    () => ({ exec: 'host' }),
    () => ({ exec: 'sandbox', sandbox: { network: 'bridge', image: PINNED_TEST_IMAGE, profile: 'validation' } }),
    () => ({ exec: 'sandbox', sandbox: { network: 'none', image: 'node:22', profile: 'analysis' } }),
    () => ({ targets: [{ kind: 'url', value: 'http://169.254.169.254/' }] }),
    () => ({ targets: [{ kind: 'host_path', value: '/root/.ssh/id_rsa' }] }),
    () => ({ targets: [{ kind: 'repo_path', value: '.spinxsca/spinxsca.db' }] }),
    () => ({ targets: [{ kind: 'workspace_path', value: 'ws1/spinxsca.yaml' }] }),
    () => ({ targets: [{ kind: 'store', value: 'grants' }] }),
    () => ({ argsText: 'token ghp_abcdefghijklmnopqrstuvwxyz0123456789' }),
  ];

  it('never allows a floor violation, whatever grants, auto-allow or mode', () => {
    for (let i = 0; i < 2000; i++) {
      const tool = pick(r, TOOLS);
      const violation = pick(r, dangerous)(tool);
      const d = evaluate(base({ tool, ...violation }), generousContext(r, tool));
      expect(d.outcome, `${tool} ${JSON.stringify(violation)}`).toBe('deny');
    }
  });

  it('never allows WRITE_REPO, EXTERNAL, GOVERNANCE or EGRESS tools', () => {
    for (const tool of TOOLS) {
      const risk = TOOL_RISK[tool] as RiskClass;
      if (!['WRITE_REPO', 'EXTERNAL', 'GOVERNANCE', 'EGRESS'].includes(risk)) continue;
      for (let i = 0; i < 20; i++) {
        const d = evaluate(base({ tool, targets: [] }), generousContext(r, tool));
        expect(d.outcome, tool).not.toBe('allow');
        if (d.outcome === 'ask') expect(d.humanOnly, tool).toBe(true);
      }
    }
  });

  it('treats unknown tools as GOVERNANCE and never lowers a risk', () => {
    expect(riskOf('made_up')).toBe('GOVERNANCE');
    expect(riskOf('validation_run', 'READ', { validation_run: 'READ' })).toBe('EXEC_REPO_CODE');
    expect(riskOf('read_file', undefined, { read_file: 'WRITE_WORKSPACE' })).toBe('WRITE_WORKSPACE');
  });
});

describe('policy engine', () => {
  it('asks human-only for request tools and offers only "once"', () => {
    const d = evaluate(base({ tool: 'request_apply', targets: [{ kind: 'workspace_path', value: 'ws1' }] }), ctx());
    expect(d).toMatchObject({ outcome: 'ask', layer: 'L6', humanOnly: true, offeredGrants: ['once'] });
  });

  it('offers wider grants for workspace writes than for code execution', () => {
    const write = evaluate(
      base({ tool: 'harness_write', targets: [{ kind: 'workspace_path', value: 'ws1/poc/a.js' }] }),
      ctx(),
    );
    expect(write.offeredGrants).toEqual(['once', 'case', 'standing']);
    const exec = evaluate(
      base({
        tool: 'validation_run',
        exec: 'sandbox',
        sandbox: { network: 'none', image: PINNED_TEST_IMAGE, profile: 'validation' },
        targets: [{ kind: 'handle', value: 'CF-1' }],
      }),
      ctx(),
    );
    expect(exec.offeredGrants).toEqual(['once', 'case']);
    const protectedWrite = evaluate(
      base({ tool: 'patch_propose', targets: [{ kind: 'workspace_path', value: 'ws1/.github/workflows/ci.yml' }] }),
      ctx(),
    );
    expect(protectedWrite.offeredGrants).toEqual(['once', 'case']);
  });

  it('tells the agent nothing about which rule denied it', () => {
    const d = evaluate(base({ targets: [{ kind: 'repo_path', value: '.spinxsca/spinxsca.db' }] }), ctx());
    expect(d.outcome).toBe('deny');
    const msg = agentMessage(d);
    expect(msg).toBe(NOT_PERMITTED);
    expect(msg).not.toContain('.spinxsca');
    expect(msg).not.toContain(d.rule);
  });

  it('normalizes and rejects escaping paths', () => {
    expect(safeRelPath('./src//a.ts')).toBe('src/a.ts');
    expect(safeRelPath('../x')).toBeUndefined();
    expect(safeRelPath('/etc/passwd')).toBeUndefined();
    expect(safeRelPath('a\0b')).toBeUndefined();
    const t: ActionTarget = { kind: 'workspace_path', value: 'ws1/.github/workflows/x.yml' };
    expect(isProtectedTarget(t)).toBe(true);
    expect(isProtectedTarget({ kind: 'workspace_path', value: 'ws1/src/app.ts' })).toBe(false);
  });
});

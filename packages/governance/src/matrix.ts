import { ActionTarget, AutonomyMode, type Grant, PolicyDecision, RiskClass } from '@spinxsca/schemas';
import { z } from 'zod';
import { evaluate, type PermissionRequest, type PolicyContext } from './engine';

/**
 * Golden decision matrix (evals/governance/decision-matrix.yaml): every row is one proposed action in
 * one context with the expected outcome and layer. Shared by the unit tests and `spinxsca eval
 * --suite governance`, so the policy cannot drift without a reviewed change to the matrix.
 */
export const PINNED_TEST_IMAGE = `ghcr.io/spinxsca/toolbox@sha256:${'a'.repeat(64)}`;

const Target = z.string().transform((value, ctx) => {
  const i = value.indexOf(':');
  const parsed = ActionTarget.safeParse({ kind: value.slice(0, i), value: value.slice(i + 1) });
  if (i < 0 || !parsed.success) {
    ctx.addIssue({ code: 'custom', message: `invalid target ${value}` });
    return z.NEVER;
  }
  return parsed.data;
});

const RowGrant = z.strictObject({
  scope: z.enum(['case', 'standing']),
  tool: z.string(),
  target: z.string().default('*'),
  risk: RiskClass,
  case_id: z.string().optional(),
  project_id: z.string().optional(),
  expired: z.boolean().default(false),
  revoked: z.boolean().default(false),
});

const Expect = z.union([
  z.string().transform((s, ctx) => {
    const [outcome, layer, ...rest] = s.trim().split(/\s+/);
    const parsed = z
      .strictObject({ outcome: PolicyDecision.shape.outcome, layer: PolicyDecision.shape.layer })
      .safeParse({ outcome, layer });
    if (!parsed.success) {
      ctx.addIssue({ code: 'custom', message: `invalid expectation "${s}"` });
      return z.NEVER;
    }
    return {
      ...parsed.data,
      humanOnly: rest.includes('human_only'),
      flags: rest.filter((r) => r.startsWith('flag:')).map((r) => r.slice(5)),
      rule: rest.find((r) => r.startsWith('rule:'))?.slice(5),
    };
  }),
]);

const RowFields = {
  tool: z.string(),
  targets: z.array(Target).default([]),
  mode: AutonomyMode.optional(),
  persona_tools: z.union([z.literal('any'), z.array(z.string())]).optional(),
  deny_tools: z.array(z.string()).optional(),
  input_valid: z.boolean().optional(),
  declared_risk: RiskClass.optional(),
  risk_overrides: z.record(z.string(), RiskClass).optional(),
  exec: z.enum(['none', 'sandbox', 'host']).optional(),
  sandbox: z.strictObject({ network: z.string(), image: z.string(), profile: z.string() }).partial().optional(),
  args: z.string().optional(),
  data_exclude: z.array(z.string()).optional(),
  allowed_providers: z.array(z.string()).optional(),
  scope: z
    .strictObject({
      workspaces: z.array(z.string()).optional(),
      handles: z.array(z.string()).optional(),
      findings: z.array(z.string()).optional(),
      repo_paths: z.array(z.string()).optional(),
    })
    .optional(),
  quota: z
    .strictObject({
      cost_usd: z.number().default(0),
      max_cost_usd: z.number().optional(),
      sandbox_runs: z.number().default(0),
      max_sandbox_runs: z.number().optional(),
      sandbox_cpu_sec: z.number().default(0),
      max_sandbox_cpu_sec: z.number().optional(),
      validation_runs_for_target: z.number().optional(),
      max_runs_per_finding: z.number().optional(),
    })
    .optional(),
  grants: z.array(RowGrant).optional(),
  auto_allow: z.array(z.string()).optional(),
  validation_l3: z.boolean().optional(),
  extra_protected: z.array(z.string()).optional(),
  protected_roots: z.array(z.string()).optional(),
};

const Row = z.strictObject({ id: z.string().min(1), note: z.string().optional(), ...RowFields, expect: Expect });
export type DecisionMatrixRow = z.infer<typeof Row>;

export const DecisionMatrix = z.strictObject({
  version: z.literal(1),
  defaults: z.strictObject(RowFields).partial().default({}),
  rows: z.array(Row).min(1),
});
export type DecisionMatrix = z.infer<typeof DecisionMatrix>;

export interface MatrixFailure {
  id: string;
  expected: string;
  actual: string;
  reason: string;
}

export interface MatrixResult {
  total: number;
  passed: number;
  failures: MatrixFailure[];
  /** Rows per expected layer, to show that every layer is exercised. */
  layers: Record<string, number>;
}

const CASE_ID = 'case_matrix';
const PROJECT_ID = 'prj_matrix';
const NOW = new Date('2026-11-01T00:00:00Z');

export function rowToInputs(
  row: DecisionMatrixRow,
  defaults: DecisionMatrix['defaults'],
): {
  request: PermissionRequest;
  ctx: PolicyContext;
} {
  const r = { ...defaults, ...row };
  const exec = r.exec ?? 'none';
  const sandbox =
    exec === 'sandbox' || r.sandbox
      ? { network: 'none', image: PINNED_TEST_IMAGE, profile: 'analysis', ...r.sandbox }
      : undefined;
  const request: PermissionRequest = {
    toolCallId: `call_${row.id}`,
    caseId: CASE_ID,
    tool: r.tool,
    ...(r.declared_risk ? { declaredRisk: r.declared_risk } : {}),
    inputValid: r.input_valid ?? true,
    targets: r.targets ?? [],
    exec,
    ...(sandbox ? { sandbox } : {}),
    argsText: r.args ?? JSON.stringify({ targets: (r.targets ?? []).map((t) => t.value) }),
  };
  const grants: Grant[] = (r.grants ?? []).map((g, i) => ({
    grantId: `grant_${i}`,
    projectId: g.project_id ?? PROJECT_ID,
    ...(g.scope === 'case' ? { caseId: g.case_id ?? CASE_ID } : {}),
    scope: g.scope,
    tool: g.tool,
    target: g.target,
    risk: g.risk,
    createdBy: 'human:matrix',
    createdAt: '2026-10-01T00:00:00Z',
    ...(g.expired ? { expiresAt: '2026-10-15T00:00:00Z' } : {}),
    ...(g.revoked ? { revokedAt: '2026-10-15T00:00:00Z' } : {}),
  }));
  const q = r.quota;
  const ctx: PolicyContext = {
    projectId: PROJECT_ID,
    mode: r.mode ?? 'supervised',
    personaTools: !r.persona_tools || r.persona_tools === 'any' ? 'any' : new Set(r.persona_tools),
    ...(r.deny_tools ? { denyTools: r.deny_tools } : {}),
    ...(r.risk_overrides ? { riskOverrides: r.risk_overrides } : {}),
    protection: { extraProtected: r.extra_protected ?? [], protectedRoots: r.protected_roots ?? [] },
    ...(r.data_exclude ? { dataPolicyExclude: r.data_exclude } : {}),
    ...(r.allowed_providers ? { allowedProviders: r.allowed_providers } : {}),
    scope: {
      workspaces: new Set(r.scope?.workspaces ?? ['ws1']),
      handles: new Set(r.scope?.handles ?? ['CF-1', 'CF-2']),
      ...(r.scope?.findings ? { findings: new Set(r.scope.findings) } : {}),
      ...(r.scope?.repo_paths ? { repoPaths: new Set(r.scope.repo_paths) } : {}),
    },
    ...(q
      ? {
          quota: {
            costUsd: q.cost_usd,
            sandboxRuns: q.sandbox_runs,
            sandboxCpuSec: q.sandbox_cpu_sec,
            ...(q.max_cost_usd !== undefined ? { maxCostUsd: q.max_cost_usd } : {}),
            ...(q.max_sandbox_runs !== undefined ? { maxSandboxRuns: q.max_sandbox_runs } : {}),
            ...(q.max_sandbox_cpu_sec !== undefined ? { maxSandboxCpuSec: q.max_sandbox_cpu_sec } : {}),
            ...(q.validation_runs_for_target !== undefined
              ? { validationRunsForTarget: q.validation_runs_for_target }
              : {}),
            ...(q.max_runs_per_finding !== undefined ? { maxRunsPerFinding: q.max_runs_per_finding } : {}),
          },
        }
      : {}),
    grants,
    ...(r.auto_allow ? { autoAllow: r.auto_allow } : {}),
    ...(r.validation_l3 !== undefined ? { validationL3: r.validation_l3 } : {}),
    now: NOW,
  };
  return { request, ctx };
}

export function runDecisionMatrix(input: unknown): MatrixResult {
  const matrix = DecisionMatrix.parse(input);
  const failures: MatrixFailure[] = [];
  const layers: Record<string, number> = {};
  const ids = new Set<string>();
  for (const row of matrix.rows) {
    if (ids.has(row.id)) throw new Error(`duplicate matrix row id ${row.id}`);
    ids.add(row.id);
    layers[row.expect.layer] = (layers[row.expect.layer] ?? 0) + 1;
    const { request, ctx } = rowToInputs(row, matrix.defaults);
    const d = evaluate(request, ctx);
    const problems: string[] = [];
    if (d.outcome !== row.expect.outcome) problems.push('outcome');
    if (d.layer !== row.expect.layer) problems.push('layer');
    if (d.humanOnly !== row.expect.humanOnly) problems.push('humanOnly');
    if (row.expect.rule && d.rule !== row.expect.rule) problems.push('rule');
    for (const flag of row.expect.flags) if (!d.flags.includes(flag)) problems.push(`flag ${flag}`);
    if (problems.length) {
      failures.push({
        id: row.id,
        expected: `${row.expect.outcome} ${row.expect.layer}${row.expect.humanOnly ? ' human_only' : ''}${row.expect.rule ? ` rule:${row.expect.rule}` : ''}`,
        actual: `${d.outcome} ${d.layer}${d.humanOnly ? ' human_only' : ''} rule:${d.rule} flags:${d.flags.join(',')}`,
        reason: `${problems.join(', ')} differ (${d.reason})`,
      });
    }
  }
  return { total: matrix.rows.length, passed: matrix.rows.length - failures.length, failures, layers };
}

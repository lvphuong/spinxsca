import { redactSecrets } from '@spinxsca/core';
import {
  type ActionTarget,
  AUTO_ALLOWABLE_RISKS,
  type AutonomyMode,
  type Grant,
  type GrantScope,
  type PolicyDecision,
  RISK_RANK,
  type RiskClass,
} from '@spinxsca/schemas';
import { allow, ask, deny } from './decision';
import { isRequestTool, LOW_RISKS, REQUEST_ONLY_RISKS, riskOf } from './risk';
import {
  globToRegExp,
  isProtectedTarget,
  isSelfProtected,
  matchesAny,
  type ProtectionOptions,
  relPathOf,
  targetKey,
  workspaceIdOf,
} from './targets';

/** One tool call as the host sees it after schema validation; built by the executor, never by a model. */
export interface PermissionRequest {
  toolCallId: string;
  caseId: string;
  tool: string;
  /** Risk declared by the tool implementation (host code); can only raise the catalog risk. */
  declaredRisk?: RiskClass;
  /** False when the input failed the tool's schema. */
  inputValid: boolean;
  targets: readonly ActionTarget[];
  /** How the action executes: host-only bookkeeping, a sandbox container, or the host shell. */
  exec: 'none' | 'sandbox' | 'host';
  sandbox?: { network: string; image: string; profile: string };
  /** Serialized arguments, checked for secrets; never stored by the engine. */
  argsText: string;
}

export interface CaseScope {
  /** Case workspace ids the agent may address (`workspace_path` targets). */
  workspaces: ReadonlySet<string>;
  /** Case-local finding handles (CF-n). Omit to skip the check. */
  handles?: ReadonlySet<string>;
  findings?: ReadonlySet<string>;
  /** Snapshot paths after the data policy. Omit to skip the check. */
  repoPaths?: ReadonlySet<string>;
}

export interface QuotaState {
  costUsd: number;
  maxCostUsd?: number;
  sandboxRuns: number;
  maxSandboxRuns?: number;
  sandboxCpuSec: number;
  maxSandboxCpuSec?: number;
  /** Validation runs already spent on the target finding of this request. */
  validationRunsForTarget?: number;
  maxRunsPerFinding?: number;
}

export interface PolicyContext {
  projectId: string;
  mode: AutonomyMode;
  /** Tools of the persona manifest; "any" only for host-internal callers. */
  personaTools: ReadonlySet<string> | 'any';
  denyTools?: readonly string[];
  riskOverrides?: Readonly<Record<string, RiskClass>>;
  protection?: ProtectionOptions;
  /** `ai.data_policy.exclude_paths`: such files never reach a model, so tools may not read them. */
  dataPolicyExclude?: readonly string[];
  /** `ai.data_policy.allowed_providers`. */
  allowedProviders?: readonly string[];
  scope: CaseScope;
  quota?: QuotaState;
  grants?: readonly Grant[];
  /** `ai.autonomy.auto_allow`. */
  autoAllow?: readonly string[];
  /** `ai.validation.l3`: sandboxed PoC runs need no approval (operator decision). */
  validationL3?: boolean;
  /** Secret detector (known values + patterns); defaults to the generic patterns. */
  containsSecret?: (text: string) => boolean;
  now: Date;
}

/** Registry digest ("name@sha256:…") or local image id ("sha256:…"); tags alone are mutable. */
const PINNED_IMAGE = /(^|@)sha256:[0-9a-f]{64}$/;
const BUDGETED_RISKS: ReadonlySet<RiskClass> = new Set(['ANALYZE', 'WRITE_WORKSPACE', 'EXEC_REPO_CODE']);
const SANDBOX_RISKS: ReadonlySet<RiskClass> = new Set(['ANALYZE', 'EXEC_REPO_CODE']);

/**
 * The policy engine (ADR-041): a pure function from a proposed tool call and its context to allow,
 * deny or ask. Layers are evaluated in a fixed precedence; the first layer that decides wins.
 * Floors (L1, L2) cannot be lifted by grants, configuration or any approver.
 */
export function evaluate(request: PermissionRequest, ctx: PolicyContext): PolicyDecision {
  const risk = riskOf(request.tool, request.declaredRisk, ctx.riskOverrides);
  const targets = request.targets;

  // L0 admission: closed persona manifest, configured denials, schema-valid input.
  if (ctx.denyTools?.includes(request.tool))
    return deny('L0', 'admission.deny_tools', risk, 'tool denied by configuration');
  if (ctx.personaTools !== 'any' && !ctx.personaTools.has(request.tool)) {
    return deny('L0', 'admission.not_in_manifest', risk, `${request.tool} is not in the persona manifest`);
  }
  if (!request.inputValid) return deny('L0', 'admission.invalid_input', risk, 'input failed schema validation');

  // L1 self-protection: the governance surface of spinxsca itself.
  for (const t of targets) {
    if (isSelfProtected(t, ctx.protection)) {
      return deny('L1', 'self_protection', risk, `target ${t.kind}:${t.value} is part of the governance surface`);
    }
  }

  // L2 hard floors.
  const floor = hardFloor(request, risk, ctx);
  if (floor) return floor;

  // L3 mode.
  if (
    ctx.mode === 'observe' &&
    (risk === 'EXEC_REPO_CODE' ||
      risk === 'WRITE_WORKSPACE' ||
      request.tool === 'request_apply' ||
      request.tool === 'request_pr')
  ) {
    return deny('L3', 'mode.observe', risk, 'observe mode does not execute code or write workspaces');
  }

  // L4 scope.
  const outOfScope = scopeViolation(targets, ctx.scope);
  if (outOfScope) return deny('L4', outOfScope.rule, risk, outOfScope.reason);

  // L5 quotas.
  const quota = quotaViolation(request, risk, ctx.quota);
  if (quota) return deny('L5', quota.rule, risk, quota.reason);

  // L6 human-only requests.
  if (isRequestTool(request.tool)) {
    return ask('L6', 'human_only', risk, `${request.tool} needs a human decision`, { humanOnly: true });
  }

  // L7 low risk.
  if (LOW_RISKS.has(risk)) return allow('L7', 'low_risk', risk, `${risk} is allowed`);

  // L8 protected targets: flagged, and only exact case grants or a human can cover them.
  const protectedTouched = targets.some((t) => isProtectedTarget(t, ctx.protection));
  const flags = protectedTouched ? ['protectedTouched'] : [];

  // L9 case grant, L10 standing rule.
  const key = targetKey(targets);
  const rel = targets[0] ? relPathOf(targets[0]) : undefined;
  for (const grant of activeGrants(ctx.grants ?? [], ctx.now)) {
    if (grant.tool !== request.tool || RISK_RANK[risk] > RISK_RANK[grant.risk]) continue;
    if (grant.scope === 'case' && grant.caseId === request.caseId) {
      if (grant.target === key || (grant.target === '*' && !protectedTouched)) {
        return allow('L9', 'grant.case', risk, `case grant ${grant.grantId}`, flags);
      }
    }
  }
  if (!protectedTouched) {
    for (const grant of activeGrants(ctx.grants ?? [], ctx.now)) {
      if (grant.scope !== 'standing' || grant.projectId !== ctx.projectId || grant.tool !== request.tool) continue;
      if (RISK_RANK[risk] > RISK_RANK[grant.risk]) continue;
      if (grant.target === '*' || grant.target === key || (rel && globToRegExp(grant.target).test(rel))) {
        return allow('L10', 'grant.standing', risk, `standing rule ${grant.grantId}`, flags);
      }
    }
  }

  // L11 operator configuration.
  if (!protectedTouched) {
    if (ctx.autoAllow?.includes(request.tool) && AUTO_ALLOWABLE_RISKS.has(risk)) {
      return allow('L11', 'config.auto_allow', risk, 'ai.autonomy.auto_allow', flags);
    }
    if (ctx.validationL3 && (request.tool === 'validation_run' || request.tool === 'harness_write')) {
      return allow('L11', 'config.validation_l3', risk, 'ai.validation.l3', flags);
    }
  }

  // L12 default: ask.
  return ask('L12', 'default_ask', risk, `${request.tool} (${risk}) needs approval`, {
    offeredGrants: offeredGrants(risk, protectedTouched),
    flags,
  });
}

function hardFloor(request: PermissionRequest, risk: RiskClass, ctx: PolicyContext): PolicyDecision | undefined {
  if (risk === 'EGRESS') return deny('L2', 'floor.egress', risk, 'network egress is never allowed');
  if (request.exec === 'host') return deny('L2', 'floor.host_exec', risk, 'agents never execute on the host');
  if (request.sandbox) {
    if (request.sandbox.network !== 'none') {
      return deny('L2', 'floor.network', risk, `sandbox network ${request.sandbox.network} is not "none"`);
    }
    if (!PINNED_IMAGE.test(request.sandbox.image)) {
      return deny('L2', 'floor.unpinned_image', risk, `image ${request.sandbox.image} is not pinned by digest`);
    }
  } else if (request.exec === 'sandbox') {
    return deny('L2', 'floor.sandbox_spec', risk, 'sandboxed action without a sandbox specification');
  }
  for (const t of request.targets) {
    if (t.kind === 'network' || t.kind === 'url')
      return deny('L2', 'floor.network_target', risk, `network target ${t.value}`);
    if (t.kind === 'host_path') return deny('L2', 'floor.host_path', risk, 'agents never address host paths');
    if (t.kind === 'provider' && ctx.allowedProviders && !ctx.allowedProviders.includes(t.value)) {
      return deny('L2', 'floor.provider', risk, `provider ${t.value} is not in ai.data_policy.allowed_providers`);
    }
    const rel = relPathOf(t);
    if (rel && ctx.dataPolicyExclude?.length && matchesAny(rel, ctx.dataPolicyExclude)) {
      return deny('L2', 'floor.data_policy', risk, `${rel} is excluded by ai.data_policy`);
    }
  }
  if (REQUEST_ONLY_RISKS.has(risk) && !isRequestTool(request.tool)) {
    return deny(
      'L2',
      'floor.request_only',
      risk,
      `${risk} actions are reachable only through a human-approved request`,
    );
  }
  const detect = ctx.containsSecret ?? ((text: string) => redactSecrets(text).redactions > 0);
  if (request.argsText && detect(request.argsText)) {
    return deny('L2', 'floor.secret_in_args', risk, 'arguments contain a secret');
  }
  return undefined;
}

function scopeViolation(
  targets: readonly ActionTarget[],
  scope: CaseScope,
): { rule: string; reason: string } | undefined {
  for (const t of targets) {
    switch (t.kind) {
      case 'repo_path': {
        const rel = relPathOf(t);
        if (rel === undefined) return { rule: 'scope.path_escape', reason: `path ${t.value} escapes the repository` };
        if (scope.repoPaths && !inTree(scope.repoPaths, rel)) {
          return { rule: 'scope.repo_path', reason: `${rel} is not in the case snapshot` };
        }
        break;
      }
      case 'workspace_path': {
        const id = workspaceIdOf(t);
        if (!id || !scope.workspaces.has(id))
          return { rule: 'scope.workspace', reason: `workspace ${id} is not part of the case` };
        const rest = t.value.slice(id.length + 1);
        if (rest !== '' && relPathOf(t) === undefined) {
          return { rule: 'scope.path_escape', reason: `path ${t.value} escapes the workspace` };
        }
        break;
      }
      case 'handle':
        if (scope.handles && !scope.handles.has(t.value))
          return { rule: 'scope.handle', reason: `unknown handle ${t.value}` };
        break;
      case 'finding':
        if (scope.findings && !scope.findings.has(t.value))
          return { rule: 'scope.finding', reason: `finding ${t.value} not in case` };
        break;
      default:
        break;
    }
  }
  return undefined;
}

function inTree(paths: ReadonlySet<string>, rel: string): boolean {
  if (paths.has(rel)) return true;
  const prefix = `${rel}/`;
  for (const p of paths) if (p.startsWith(prefix)) return true;
  return false;
}

function quotaViolation(
  request: PermissionRequest,
  risk: RiskClass,
  quota: QuotaState | undefined,
): { rule: string; reason: string } | undefined {
  if (!quota || !BUDGETED_RISKS.has(risk)) return undefined;
  if (quota.maxCostUsd !== undefined && quota.costUsd >= quota.maxCostUsd) {
    return { rule: 'quota.cost', reason: `cost $${quota.costUsd.toFixed(2)} reached the case budget` };
  }
  if (SANDBOX_RISKS.has(risk)) {
    if (quota.maxSandboxRuns !== undefined && quota.sandboxRuns >= quota.maxSandboxRuns) {
      return { rule: 'quota.sandbox_runs', reason: `${quota.sandboxRuns} sandbox runs reached the limit` };
    }
    if (quota.maxSandboxCpuSec !== undefined && quota.sandboxCpuSec >= quota.maxSandboxCpuSec) {
      return { rule: 'quota.sandbox_cpu', reason: `${quota.sandboxCpuSec}s sandbox CPU reached the limit` };
    }
  }
  if (
    request.tool === 'validation_run' &&
    quota.maxRunsPerFinding !== undefined &&
    (quota.validationRunsForTarget ?? 0) >= quota.maxRunsPerFinding
  ) {
    return { rule: 'quota.validation_runs', reason: 'validation runs for this finding reached the limit' };
  }
  return undefined;
}

export function activeGrants(grants: readonly Grant[], now: Date): Grant[] {
  return grants.filter((g) => !g.revokedAt && (!g.expiresAt || new Date(g.expiresAt) > now));
}

/** Grant scopes a human may pick when approving an ask (validated again when the answer arrives). */
export function offeredGrants(risk: RiskClass, protectedTouched: boolean): GrantScope[] {
  if (risk === 'WRITE_WORKSPACE') return protectedTouched ? ['once', 'case'] : ['once', 'case', 'standing'];
  if (risk === 'EXEC_REPO_CODE') return ['once', 'case'];
  return ['once'];
}

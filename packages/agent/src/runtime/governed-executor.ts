import { type CaseRepository, newId, type SecretScrubber, sha256, stableStringify } from '@spinxsca/core';
import {
  type ApprovalRequest,
  type ApprovalResolution,
  type Approver,
  agentMessage,
  buildApprovalRequest,
  ConsecutiveBreaker,
  decisionAudit,
  evaluate,
  grantFromApproval,
  NOT_PERMITTED,
  type PermissionRequest,
  type PolicyContext,
  resolutionAudit,
  resolveApproval,
} from '@spinxsca/governance';
import type { PolicyDecision, RiskClass, ToolCallRecord } from '@spinxsca/schemas';
import { capOutput, DEFAULT_OUTPUT_LIMIT, type ToolExecutor, type ToolOutcome, type ToolUse } from './executor';
import type { AgentTool } from './tools';

export interface GovernedExecutorOptions {
  cases: CaseRepository;
  projectId: string;
  caseId: string;
  runId: string;
  persona: string;
  itemId?: string;
  tools: readonly AgentTool[];
  /** Policy context for one request, built fresh (ledger quotas, grants, scope). */
  policy: (request: PermissionRequest) => Promise<PolicyContext> | PolicyContext;
  /** Approver chain for asks (reviewer, TTY human, inbox); empty means every ask is denied. */
  approvers: readonly Approver[];
  scrubber: SecretScrubber;
  /** Consecutive policy denials before the run stops (default 5). */
  denyBreaker?: ConsecutiveBreaker;
  now?: () => Date;
}

const LOW_RISK_IDEMPOTENT: ReadonlySet<RiskClass> = new Set(['READ', 'ANALYZE']);

/**
 * Executes tool calls of a case through the governance pipeline (ADR-041/042):
 * PROPOSED → policy → (ask → approvers → human-only enforcement) → RUNNING → scrubbed, capped output.
 * Every stage is recorded in the hash-chained audit; every call is durable, so a resumed session
 * gets finished results back instead of running a side effect twice.
 */
export class GovernedToolExecutor implements ToolExecutor {
  private readonly tools: Map<string, AgentTool>;
  private readonly breaker: ConsecutiveBreaker;
  private readonly now: () => Date;
  private readonly actor: string;

  constructor(private readonly o: GovernedExecutorOptions) {
    this.tools = new Map(o.tools.map((t) => [t.name, t]));
    this.breaker = o.denyBreaker ?? new ConsecutiveBreaker(5);
    this.now = o.now ?? (() => new Date());
    this.actor = `agent:${o.persona}/${o.runId}`;
  }

  async execute(call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome> {
    const existing = await this.o.cases.getToolCall(this.o.caseId, call.id);
    if (existing) {
      const replay = await this.replay(existing, call, ctx);
      if (replay) return replay;
    }
    return this.propose(call, ctx);
  }

  /** Outcome of a call already recorded (resume); undefined when it must be evaluated again. */
  private async replay(
    record: ToolCallRecord,
    call: ToolUse,
    ctx: { signal?: AbortSignal },
  ): Promise<ToolOutcome | undefined> {
    switch (record.status) {
      case 'FINISHED':
      case 'FAILED':
      case 'CANCELLED':
        return this.result(record.output ?? '', record.isError ?? record.status !== 'FINISHED', record);
      case 'DENIED':
        return this.result(record.output ?? NOT_PERMITTED, true, record);
      case 'PARKED': {
        const approval = record.approvalId ? await this.o.cases.getApproval(record.approvalId) : undefined;
        if (!approval || approval.status === 'PENDING') {
          return {
            kind: 'suspend',
            reason: 'waiting for a human decision',
            ...(approval ? { approvalId: approval.approvalId } : {}),
          };
        }
        if (approval.status !== 'APPROVED') {
          return this.denyRecorded(record, approval.reason ? 'A human declined this action.' : NOT_PERMITTED);
        }
        return this.run(record, call, ctx);
      }
      case 'ALLOWED':
        return this.run(record, call, ctx);
      case 'RUNNING': {
        // The process stopped while the tool ran. Only idempotent tools may run again.
        const tool = this.tools.get(record.tool);
        const idempotent = tool?.idempotent ?? LOW_RISK_IDEMPOTENT.has(record.risk);
        if (idempotent) return this.run(record, call, ctx);
        const output =
          'The previous attempt of this action was interrupted and its result is unknown. Check the state before retrying.';
        await this.save({ ...record, status: 'FAILED', output, isError: true });
        await this.audit('tool.failed', record.toolCallId, { tool: record.tool, reason: 'interrupted' });
        return this.result(output, true, record);
      }
      default:
        return undefined;
    }
  }

  private async propose(call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome> {
    const tool = this.tools.get(call.name);
    const parsed = tool?.input.safeParse(call.input);
    const input = parsed?.success ? parsed.data : call.input;
    const request: PermissionRequest = {
      toolCallId: call.id,
      caseId: this.o.caseId,
      tool: call.name,
      ...(tool?.risk ? { declaredRisk: tool.risk } : {}),
      inputValid: parsed?.success ?? false,
      targets: (parsed?.success && tool?.targets?.(input as never)) || [],
      exec: tool?.sandbox ? 'sandbox' : 'none',
      ...(parsed?.success && tool?.sandbox?.(input as never) ? { sandbox: tool.sandbox(input as never) } : {}),
      argsText: stableStringify(call.input),
    };
    const decision = evaluate(request, await this.o.policy(request));
    const at = this.now().toISOString();
    const record: ToolCallRecord = {
      caseId: this.o.caseId,
      toolCallId: call.id,
      agentRunId: this.o.runId,
      ...(this.o.itemId ? { itemId: this.o.itemId } : {}),
      tool: call.name,
      risk: decision.risk,
      status: 'PROPOSED',
      input: JSON.parse(this.o.scrubber.scrub(JSON.stringify(call.input ?? null))),
      argsDigest: sha256(request.argsText),
      decision: { outcome: decision.outcome, layer: decision.layer, rule: decision.rule },
      createdAt: at,
      updatedAt: at,
    };
    await this.audit('policy.decided', call.id, decisionAudit(request, decision));

    if (decision.outcome === 'deny') {
      if (decision.layer === 'L0' && decision.rule === 'admission.invalid_input' && parsed && !parsed.success) {
        // Schema feedback is safe to return: it describes the tool's own input contract.
        const issues = parsed.error.issues.map((i) => `- ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n');
        return this.denyRecorded(record, `Invalid input for ${call.name}:\n${issues}`, false);
      }
      return this.denyRecorded(record, agentMessage(decision));
    }
    this.breaker.record(this.o.runId, false);
    if (decision.outcome === 'allow') {
      const allowed = { ...record, status: 'ALLOWED' as const };
      await this.save(allowed);
      return this.run(allowed, call, ctx);
    }
    return this.ask(record, decision, tool, input, call, ctx);
  }

  private async ask(
    record: ToolCallRecord,
    decision: PolicyDecision,
    tool: AgentTool | undefined,
    input: unknown,
    call: ToolUse,
    ctx: { signal?: AbortSignal },
  ): Promise<ToolOutcome> {
    const described = tool?.describe?.(input as never);
    const request: ApprovalRequest = buildApprovalRequest({
      approvalId: newId('apr'),
      projectId: this.o.projectId,
      caseId: this.o.caseId,
      toolCallId: call.id,
      tool: call.name,
      decision,
      title: described?.title ?? `${call.name} (${decision.risk})`,
      summary: this.o.scrubber.scrub(described?.summary ?? ''),
      targets: tool?.targets?.(input as never) ?? [],
      argsPreview: capOutput(this.o.scrubber.scrub(JSON.stringify(call.input, null, 2)), 4000),
      ...(described?.diff ? { diff: this.o.scrubber.scrub(described.diff) } : {}),
    });
    const stored = await this.o.cases.createApproval({
      ...request,
      targets: [...request.targets],
      offeredGrants: [...request.offeredGrants],
      status: 'PENDING',
      requestedAt: this.now().toISOString(),
    });
    request.approvalId = stored.approvalId;
    await this.audit('approval.requested', call.id, {
      approvalId: stored.approvalId,
      tool: call.name,
      risk: decision.risk,
      humanOnly: decision.humanOnly,
      offeredGrants: request.offeredGrants,
      flags: decision.flags,
    });
    const parked = { ...record, status: 'PARKED' as const, approvalId: stored.approvalId };
    if (stored.status !== 'PENDING') {
      // Answered earlier (e.g. by another responder while this run was restarting).
      await this.save(parked);
      return (await this.replay(parked, call, ctx)) as ToolOutcome;
    }
    const { final } = await resolveApproval(request, this.o.approvers, {
      ...(ctx.signal ? { signal: ctx.signal } : {}),
      onResolution: (r) => this.audit('approval.resolved', call.id, resolutionAudit(request, r)),
    });
    if (final.status === 'parked') {
      await this.save(parked);
      return { kind: 'suspend', reason: 'waiting for a human decision in the inbox', approvalId: stored.approvalId };
    }
    const outcome = await this.o.cases.resolveApproval(stored.approvalId, {
      status: final.status === 'approved' ? 'APPROVED' : 'DENIED',
      resolvedBy: final.by,
      ...(final.grant ? { grantScope: final.grant } : {}),
      ...(final.reason ? { reason: final.reason } : {}),
      resolvedAt: this.now().toISOString(),
    });
    // Another responder may have won the race; their answer is the one that counts.
    const approved = outcome.approval.status === 'APPROVED';
    if (outcome.won && approved) await this.maybeGrant(request, final);
    if (!approved) {
      await this.save(parked);
      return this.denyRecorded(
        parked,
        final.by.kind === 'human' ? 'A human declined this action. Choose a different approach.' : NOT_PERMITTED,
      );
    }
    const allowed = { ...parked, status: 'ALLOWED' as const };
    await this.save(allowed);
    return this.run(allowed, call, ctx);
  }

  private async maybeGrant(request: ApprovalRequest, resolution: ApprovalResolution): Promise<void> {
    const grant = grantFromApproval(request, resolution, { grantId: newId('grant'), now: this.now() });
    if (!grant) {
      if (resolution.notes?.includes('grant_refused')) {
        await this.audit('grant.refused', request.toolCallId, {
          approvalId: request.approvalId,
          requested: resolution.grant,
        });
      }
      return;
    }
    await this.o.cases.saveGrant(grant);
    await this.audit('grant.created', request.toolCallId, {
      grantId: grant.grantId,
      scope: grant.scope,
      tool: grant.tool,
      target: grant.target,
      by: grant.createdBy,
    });
  }

  private async run(record: ToolCallRecord, call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome> {
    const tool = this.tools.get(record.tool);
    const parsed = tool?.input.safeParse(call.input);
    if (!tool || !parsed?.success) return this.denyRecorded(record, 'This tool is not available to you.');
    if (ctx.signal?.aborted) {
      await this.save({ ...record, status: 'CANCELLED', output: 'Cancelled before execution.', isError: true });
      return this.result('Cancelled before execution.', true, record);
    }
    await this.save({ ...record, status: 'RUNNING' });
    await this.audit('tool.started', record.toolCallId, { tool: record.tool, risk: record.risk });
    try {
      const raw = await tool.run(parsed.data, {
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        caseId: this.o.caseId,
        runId: this.o.runId,
        toolCallId: record.toolCallId,
      });
      const output = capOutput(this.o.scrubber.scrub(raw), tool.outputLimit ?? DEFAULT_OUTPUT_LIMIT);
      const done = { ...record, status: 'FINISHED' as const, output, outputDigest: sha256(output), isError: false };
      await this.save(done);
      await this.audit('tool.finished', record.toolCallId, {
        tool: record.tool,
        outputDigest: done.outputDigest,
        chars: output.length,
      });
      return this.result(output, false, done);
    } catch (err) {
      const output = this.o.scrubber.scrub(
        `Tool ${record.tool} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      const status = ctx.signal?.aborted ? ('CANCELLED' as const) : ('FAILED' as const);
      await this.save({ ...record, status, output, isError: true });
      await this.audit(status === 'CANCELLED' ? 'tool.cancelled' : 'tool.failed', record.toolCallId, {
        tool: record.tool,
        error: output.slice(0, 500),
      });
      return this.result(output, true, record);
    }
  }

  private async denyRecorded(record: ToolCallRecord, message: string, countsForBreaker = true): Promise<ToolOutcome> {
    await this.save({ ...record, status: 'DENIED', output: message, isError: true });
    if (!countsForBreaker) return this.result(message, true, record);
    const state = this.breaker.record(this.o.runId, true);
    if (state.justTripped) {
      await this.audit('policy.breaker_tripped', record.toolCallId, { denials: state.count, runId: this.o.runId });
      return { kind: 'stop', reason: `${state.count} consecutive actions were denied by policy`, content: message };
    }
    return this.result(message, true, record);
  }

  private result(content: string, isError: boolean, record: ToolCallRecord): ToolOutcome {
    return {
      kind: 'result',
      content,
      isError,
      argsDigest: record.argsDigest,
      ...(record.outputDigest ? { outputDigest: record.outputDigest } : {}),
      ...(record.decision ? { decision: `${record.decision.outcome} ${record.decision.layer}` } : {}),
    };
  }

  private async save(record: ToolCallRecord): Promise<void> {
    await this.o.cases.saveToolCall({ ...record, updatedAt: this.now().toISOString() });
  }

  private async audit(
    stage: Parameters<CaseRepository['appendAudit']>[0]['stage'],
    toolCallId: string,
    data: Record<string, unknown>,
  ) {
    await this.o.cases.appendAudit({ caseId: this.o.caseId, stage, actor: this.actor, toolCallId, data });
  }
}

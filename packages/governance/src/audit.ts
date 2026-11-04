import { link, sha256 } from '@spinxsca/core';
import type { AuditEntry, AuditStage, PolicyDecision } from '@spinxsca/schemas';
import type { ApprovalRequest, ApprovalResolution } from './approval';
import type { PermissionRequest } from './engine';

export interface AuditEvent {
  caseId: string;
  stage: AuditStage;
  actor: string;
  toolCallId?: string;
  data: Record<string, unknown>;
}

/** Append-only, hash-chained audit per case (implemented by the case repository). */
export interface AuditSink {
  append(event: AuditEvent): Promise<AuditEntry>;
}

/** In-memory sink for tests and dry runs. */
export class MemoryAuditSink implements AuditSink {
  readonly entries: AuditEntry[] = [];

  constructor(private readonly now: () => Date = () => new Date()) {}

  async append(event: AuditEvent): Promise<AuditEntry> {
    const prev = [...this.entries].reverse().find((e) => e.caseId === event.caseId);
    const entry = link(prev, {
      caseId: event.caseId,
      stage: event.stage,
      at: this.now().toISOString(),
      actor: event.actor,
      ...(event.toolCallId ? { toolCallId: event.toolCallId } : {}),
      data: event.data,
    }) as AuditEntry;
    this.entries.push(entry);
    return entry;
  }

  forCase(caseId: string): AuditEntry[] {
    return this.entries.filter((e) => e.caseId === caseId);
  }
}

/** Audit payload of a policy decision: digests and identifiers, never raw arguments. */
export function decisionAudit(request: PermissionRequest, decision: PolicyDecision): Record<string, unknown> {
  return {
    tool: request.tool,
    risk: decision.risk,
    outcome: decision.outcome,
    layer: decision.layer,
    rule: decision.rule,
    reason: decision.reason,
    humanOnly: decision.humanOnly,
    flags: decision.flags,
    targets: request.targets.map((t) => `${t.kind}:${t.value}`),
    argsDigest: sha256(request.argsText),
    exec: request.exec,
    ...(request.sandbox ? { sandbox: request.sandbox } : {}),
  };
}

export function resolutionAudit(request: ApprovalRequest, resolution: ApprovalResolution): Record<string, unknown> {
  return {
    approvalId: request.approvalId,
    tool: request.tool,
    status: resolution.status,
    by: `${resolution.by.kind}:${resolution.by.id}`,
    humanOnly: request.humanOnly,
    ...(resolution.grant ? { grant: resolution.grant } : {}),
    ...(resolution.reason ? { reason: resolution.reason } : {}),
    ...(resolution.notes?.length ? { notes: resolution.notes } : {}),
  };
}

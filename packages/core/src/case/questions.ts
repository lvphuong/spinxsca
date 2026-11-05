import type { ApprovalRecord, MemoryEntry, ResidualUnknown, WorkItem } from '@spinxsca/schemas';
import { sha256Hex } from '../ids';
import type { CandidateDraft } from '../ports';
import type { CaseRepository } from './ports';

/**
 * Review questions (ADR-051, after Argo's review_questions stage): a residual unknown that only a
 * human can settle (deployment, roles, tenancy, business policy) becomes a human-only inbox item.
 * It never parks the case. The answer is a claimed fact with provenance: it is written to project
 * memory, never treated as source evidence, and every agent finding whose claim depends on it is
 * re-triaged so the verdict reflects the new context.
 */
export const CONTEXT_QUESTION_TOOL = 'request_context';

export interface ContextQuestionArgs {
  unknownId: string;
  kind: ResidualUnknown['kind'];
  question: string;
  affects: string[];
}

export function contextQuestionId(caseId: string, unknownId: string): string {
  return `apr_${sha256Hex(`${caseId}|${unknownId}`).slice(0, 20)}`;
}

export async function askContextQuestions(
  cases: CaseRepository,
  rc: { caseId: string; projectId: string },
  unknowns: readonly ResidualUnknown[],
  now: Date,
): Promise<ApprovalRecord[]> {
  const created: ApprovalRecord[] = [];
  for (const u of unknowns) {
    const approvalId = contextQuestionId(rc.caseId, u.unknownId);
    if (await cases.getApproval(approvalId)) continue;
    const args: ContextQuestionArgs = {
      unknownId: u.unknownId,
      kind: u.kind,
      question: u.question,
      affects: u.affects,
    };
    const approval = await cases.createApproval({
      approvalId,
      projectId: rc.projectId,
      caseId: rc.caseId,
      toolCallId: `ctx_${u.unknownId}`,
      tool: CONTEXT_QUESTION_TOOL,
      risk: 'GOVERNANCE',
      humanOnly: true,
      title: u.question.slice(0, 200),
      summary: `${u.whySourceCannotSettle} Affects: ${u.affects.join(', ') || 'no specific finding'}. Answer with provenance; the answer becomes a claimed fact, not proof.`,
      effect: 'governance',
      targets: [{ kind: 'store', value: 'memory' }],
      argsPreview: JSON.stringify(args),
      offeredGrants: [],
      status: 'PENDING',
      requestedAt: now.toISOString(),
    });
    await cases.appendAudit({
      caseId: rc.caseId,
      stage: 'context.asked',
      actor: 'host',
      toolCallId: approval.toolCallId,
      data: { approvalId, unknownId: u.unknownId, kind: u.kind, affects: u.affects },
    });
    created.push(approval);
  }
  return created;
}

export interface ContextAnswer {
  answer: string;
  provenance: string;
  /** Human identity recorded as the author. */
  by: string;
  now: Date;
}

export interface ContextAnswerOutcome {
  approval: ApprovalRecord;
  memory?: MemoryEntry;
  /** Handles whose claims depend on the answer and were queued for re-triage. */
  retriaged: string[];
}

export function isContextQuestion(approval: Pick<ApprovalRecord, 'tool'>): boolean {
  return approval.tool === CONTEXT_QUESTION_TOOL;
}

/** Records a human answer: resolves the inbox item, writes memory, queues dependent verdicts for re-triage. */
export async function answerContextQuestion(
  cases: CaseRepository,
  approvalId: string,
  input: ContextAnswer,
): Promise<ContextAnswerOutcome> {
  const approval = await cases.getApproval(approvalId);
  if (!approval) throw new Error(`approval ${approvalId} not found`);
  if (!isContextQuestion(approval)) throw new Error(`${approvalId} is not a review question; use approve or deny`);
  if (!input.answer.trim()) throw new Error('an answer is required');
  if (!input.provenance.trim()) throw new Error('provenance is required (who or what document establishes the answer)');
  const args = JSON.parse(approval.argsPreview) as ContextQuestionArgs;
  const at = input.now.toISOString();
  const { won, approval: stored } = await cases.resolveApproval(approvalId, {
    status: 'APPROVED',
    resolvedBy: { kind: 'human', id: input.by },
    reason: input.answer.slice(0, 2000),
    resolvedAt: at,
  });
  if (!won) throw new Error(`question ${approvalId} was already ${stored.status.toLowerCase()}`);
  const memory: MemoryEntry = {
    memoryId: `mem_ctx_${sha256Hex(`${approval.caseId}|${args.unknownId}`).slice(0, 24)}`,
    projectId: approval.projectId,
    kind: 'ARCHITECTURE',
    status: 'active',
    key: `context:${args.unknownId}`,
    text: `Q: ${args.question}\nA: ${input.answer} (provenance: ${input.provenance}; confidence: claimed)`.slice(
      0,
      4000,
    ),
    data: {
      question: args.question,
      answer: input.answer,
      provenance: input.provenance,
      confidence: 'claimed',
      kind: args.kind,
      affects: args.affects,
    },
    sourceCaseId: approval.caseId,
    createdBy: `human:${input.by}`,
    createdAt: at,
    updatedAt: at,
  };
  await cases.saveMemory(memory);
  await cases.appendAudit({
    caseId: approval.caseId,
    stage: 'context.answered',
    actor: `human:${input.by}`,
    toolCallId: approval.toolCallId,
    data: { approvalId, unknownId: args.unknownId, provenance: input.provenance, memoryId: memory.memoryId },
  });
  await cases.appendJournal({
    caseId: approval.caseId,
    kind: 'DECISION',
    author: `human:${input.by}`,
    handles: [],
    refs: [],
    text: `Answered ${args.unknownId}: ${input.answer} (provenance: ${input.provenance}). Dependent verdicts are re-triaged.`.slice(
      0,
      4000,
    ),
    data: { unknownId: args.unknownId, affects: args.affects },
  });
  const affects = new Set(args.affects);
  const retriaged: string[] = [];
  if (affects.size) {
    for (const h of await cases.listHandles(approval.caseId)) {
      if (h.origin !== 'agent') continue;
      const claim = (h.draft as CandidateDraft | undefined)?.claim;
      const depends =
        (claim?.invariantId && affects.has(claim.invariantId)) || (claim?.familyId && affects.has(claim.familyId));
      if (!depends) continue;
      const itemId = `${approval.caseId}:retriage-${h.handle}-${args.unknownId}`;
      if (await cases.getWorkItem(itemId)) continue;
      const item: WorkItem = {
        itemId,
        caseId: approval.caseId,
        kind: 'TRIAGE_FINDING',
        title: `Re-validate ${h.handle}: ${h.title} after ${args.unknownId} was answered`,
        description:
          `A human answered ${args.unknownId} ("${args.question}"): ${input.answer} (provenance: ${input.provenance}). Re-check the finding against this claimed context; it is not source evidence.`.slice(
            0,
            3000,
          ),
        status: 'todo',
        mandatory: true,
        persona: 'validator',
        handles: [h.handle],
        dependsOn: [],
        createdBy: 'host',
        round: 0,
        attempts: 0,
        createdAt: at,
        updatedAt: at,
      };
      await cases.saveWorkItem(item);
      retriaged.push(h.handle);
    }
  }
  return { approval: stored, memory, retriaged };
}

/** A denied question stays a gap: journaled, never answered by assumption. */
export async function declineContextQuestion(
  cases: CaseRepository,
  approvalId: string,
  input: { by: string; reason?: string; now: Date },
): Promise<ApprovalRecord> {
  const approval = await cases.getApproval(approvalId);
  if (!approval) throw new Error(`approval ${approvalId} not found`);
  if (!isContextQuestion(approval)) throw new Error(`${approvalId} is not a review question`);
  const args = JSON.parse(approval.argsPreview) as ContextQuestionArgs;
  const at = input.now.toISOString();
  const { won, approval: stored } = await cases.resolveApproval(approvalId, {
    status: 'DENIED',
    resolvedBy: { kind: 'human', id: input.by },
    ...(input.reason ? { reason: input.reason } : {}),
    resolvedAt: at,
  });
  if (!won) throw new Error(`question ${approvalId} was already ${stored.status.toLowerCase()}`);
  await cases.appendJournal({
    caseId: approval.caseId,
    kind: 'GAP',
    author: `human:${input.by}`,
    handles: [],
    refs: [],
    text: `${args.unknownId} remains open: ${input.reason ?? 'no answer available'}. Findings depending on it keep their uncertainty.`,
    data: { unknownId: args.unknownId, affects: args.affects },
  });
  return stored;
}

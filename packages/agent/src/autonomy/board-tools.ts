import { type CaseRepository, type HandleTable, moveItem } from '@spinxsca/core';
import type { CaseVerdict, Objective, WorkItem, WorkItemKind } from '@spinxsca/schemas';
import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';

/** Personas that may take a lead-created item of each kind. */
const PERSONA_FOR_KIND: Partial<Record<WorkItemKind, string>> = {
  HYPOTHESIS: 'appsec',
  VARIANT_HUNT: 'appsec',
  LOGIC_AUDIT: 'logic',
  EXPLOIT_POC: 'exploit',
  FIX: 'fixer',
};
const MAX_LEAD_ITEMS = 16;

export interface BoardToolOptions {
  caseId: string;
  runId: string;
  round: number;
  cases: CaseRepository;
  handles: HandleTable;
  /** Kinds the lead may create in this case (PoC and fix only when enabled). */
  creatable: readonly WorkItemKind[];
  now: () => Date;
}

const BOARD_STATUS_ORDER: Record<string, number> = { blocked: 0, in_progress: 1, todo: 2, done: 3, cancelled: 4 };

export function summarizeBoard(
  items: readonly WorkItem[],
  verdicts: readonly CaseVerdict[],
  objectives: readonly Objective[],
  options: { maxItems?: number } = {},
): string {
  // Large boards (sharded cases, ADR-055) are summarised: counts by kind and status, then the items
  // that still need the lead's attention, blocked first.
  const maxItems = options.maxItems ?? 80;
  const shown = [...items]
    .sort((a, b) => (BOARD_STATUS_ORDER[a.status] ?? 9) - (BOARD_STATUS_ORDER[b.status] ?? 9))
    .slice(0, maxItems);
  const lines = shown.map(
    (i) =>
      `- ${i.itemId.split(':').pop()} [${i.status}] ${i.kind} → ${i.persona}${i.mandatory ? ' (mandatory)' : ''}: ${i.title}${i.blockedReason ? ` — blocked: ${i.blockedReason}` : ''}`,
  );
  if (items.length > shown.length) {
    const counts = new Map<string, number>();
    for (const i of items) counts.set(`${i.kind}/${i.status}`, (counts.get(`${i.kind}/${i.status}`) ?? 0) + 1);
    lines.push(
      `(+${items.length - shown.length} more items not listed; totals: ${[...counts.entries()]
        .sort()
        .map(([k, n]) => `${k}=${n}`)
        .join(', ')})`,
    );
  }
  const latest = new Map(verdicts.map((v) => [v.handle, v]));
  const counts = new Map<string, number>();
  for (const v of latest.values()) counts.set(v.verdict, (counts.get(v.verdict) ?? 0) + 1);
  return [
    '## Work items',
    ...lines,
    '',
    '## Verdicts',
    [...counts.entries()].map(([k, n]) => `${k}: ${n}`).join(', ') || '(none yet)',
    ...[...latest.values()]
      .filter((v) => v.verdict === 'TRUE_POSITIVE')
      .map(
        (v) =>
          `- ${v.handle} TRUE_POSITIVE ${v.severity ?? ''} (${v.verificationLevel}${v.poc ? `, PoC ${v.poc.outcome}` : ''})`,
      ),
    '',
    '## Objectives',
    ...objectives.map((o) => `- [${o.status}] ${o.title}${o.reason ? ` — ${o.reason}` : ''}`),
  ].join('\n');
}

/**
 * Board tools of the lead (ADR-044): it plans by adding optional work and re-queueing or cancelling
 * optional items. It cannot execute anything, complete items, or cancel mandatory work; the store
 * enforces this whatever the prompt says.
 */
export function createBoardTools(o: BoardToolOptions): AgentTool<never>[] {
  const short = (id: string) => (id.includes(':') ? id : `${o.caseId}:${id}`);
  return [
    defineTool({
      name: 'board_view',
      description: 'Show the work items, verdicts so far and objective status.',
      input: z.strictObject({}),
      risk: 'READ',
      run: async () =>
        summarizeBoard(
          await o.cases.listWorkItems(o.caseId),
          await o.cases.listVerdicts(o.caseId),
          await o.cases.listObjectives(o.caseId),
        ),
    }) as AgentTool<never>,
    defineTool({
      name: 'board_create_item',
      description: `Add optional work: ${o.creatable.join(', ')}. Be specific: one hypothesis, one variant pattern, one PoC or one fix per item.`,
      input: z.strictObject({
        kind: z.enum(['HYPOTHESIS', 'VARIANT_HUNT', 'LOGIC_AUDIT', 'EXPLOIT_POC', 'FIX']),
        title: z.string().min(5).max(160),
        description: z.string().min(10).max(3000),
        handles: z
          .array(z.string().regex(/^CF-\d+$/))
          .max(5)
          .default([]),
      }),
      risk: 'RECORD',
      run: async ({ kind, title, description, handles }) => {
        if (!o.creatable.includes(kind)) return `${kind} items are not enabled in this case.`;
        for (const h of handles) if (!o.handles.get(h)) return `Unknown handle ${h}.`;
        const items = await o.cases.listWorkItems(o.caseId);
        if (items.filter((i) => i.createdBy === 'lead').length >= MAX_LEAD_ITEMS) {
          return `The case already has ${MAX_LEAD_ITEMS} lead items; prioritise and cancel before adding more.`;
        }
        if ((kind === 'EXPLOIT_POC' || kind === 'FIX') && handles.length !== 1)
          return `${kind} needs exactly one handle.`;
        if (kind === 'EXPLOIT_POC' || kind === 'FIX') {
          const verdicts = await o.cases.listVerdicts(o.caseId);
          const latest = verdicts.filter((v) => v.handle === handles[0]).at(-1);
          if (latest?.verdict !== 'TRUE_POSITIVE') return `${handles[0]} has no TRUE_POSITIVE verdict yet.`;
        }
        const at = o.now().toISOString();
        const n = items.length + 1;
        const item: WorkItem = {
          itemId: `${o.caseId}:lead-${o.round}-${n}`,
          caseId: o.caseId,
          kind,
          title,
          description,
          status: 'todo',
          mandatory: false,
          persona: PERSONA_FOR_KIND[kind] ?? 'appsec',
          handles,
          dependsOn: [],
          createdBy: 'lead',
          round: o.round,
          attempts: 0,
          createdAt: at,
          updatedAt: at,
        };
        await o.cases.saveWorkItem(item);
        await o.cases.appendAudit({
          caseId: o.caseId,
          stage: 'item.transition',
          actor: `agent:lead/${o.runId}`,
          data: { itemId: item.itemId, to: 'todo', kind, created: true },
        });
        return `Created ${item.itemId.split(':').pop()} for ${item.persona}.`;
      },
    }) as AgentTool<never>,
    defineTool({
      name: 'board_update_item',
      description: 'Cancel an optional item that is no longer useful, or re-queue a blocked item with guidance.',
      input: z.strictObject({
        itemId: z.string().min(1),
        action: z.enum(['cancel', 'requeue']),
        reason: z.string().min(5).max(1000),
      }),
      risk: 'RECORD',
      run: async ({ itemId, action, reason }) => {
        const item = await o.cases.getWorkItem(short(itemId));
        if (!item || item.caseId !== o.caseId) return `Unknown item ${itemId}.`;
        try {
          const next = moveItem(
            item,
            action === 'cancel' ? 'cancelled' : 'todo',
            { kind: 'lead', runId: o.runId },
            o.now(),
            {
              description: action === 'requeue' ? `${item.description}\n\nLead guidance: ${reason}` : item.description,
            },
          );
          await o.cases.saveWorkItem(next, item.updatedAt);
          await o.cases.appendAudit({
            caseId: o.caseId,
            stage: 'item.transition',
            actor: `agent:lead/${o.runId}`,
            data: { itemId: item.itemId, from: item.status, to: next.status, reason },
          });
          return `${action === 'cancel' ? 'Cancelled' : 'Re-queued'} ${itemId}.`;
        } catch (err) {
          return `Not allowed: ${(err as Error).message}`;
        }
      },
    }) as AgentTool<never>,
  ];
}

import { newId } from '@spinxsca/core';
import { type AgentRunRecord, SourceRef, TOOL_RISK } from '@spinxsca/schemas';
import { z } from 'zod';
import type { LlmProvider, Usage } from '../llm/types';
import type { Semaphore } from '../runtime/concurrency';
import { runAgentSession } from '../runtime/session';
import { type AgentTool, defineTool } from '../runtime/tools';

const ExploreAnswer = z.strictObject({
  answer: z.string().min(1).max(4000).describe('What you found, with file:line references'),
  citations: z.array(SourceRef).max(20),
});

export interface ExploreToolOptions {
  provider: () => LlmProvider;
  /** Read tools offered to the sub-agent; anything above READ and `explore` itself are dropped. */
  tools: readonly AgentTool[];
  system: string;
  /** Shared limit on concurrent sub-agents (default 3 per case). */
  semaphore: Semaphore;
  maxSteps?: number;
  parentRunId?: string;
  caseId?: string;
  costOf?: (usage: Usage, model: string) => number | undefined;
  onRun?: (record: AgentRunRecord) => Promise<void> | void;
}

/**
 * `explore` (ADR-042): a read-only sub-agent answering one question about the code in at most ten
 * turns. It cannot spawn sub-agents, run analyzers or write anything; only its answer returns to the
 * caller, which keeps the caller's context small.
 */
export function createExploreTool(o: ExploreToolOptions): AgentTool<{ question: string; hints?: string[] }> {
  const tools = o.tools.filter(
    (t) => t.name !== 'explore' && TOOL_RISK[t.name] === 'READ' && (t.risk ?? 'READ') === 'READ',
  );
  return defineTool({
    name: 'explore',
    description:
      'Delegate one focused question about the code to a read-only sub-agent (for example "where is the user id of /orders/:id checked?"). Returns a short answer with file:line citations.',
    input: z.strictObject({
      question: z.string().min(10).max(1000),
      hints: z.array(z.string().max(200)).max(10).optional().describe('Paths or symbols to start from'),
    }),
    risk: 'READ',
    idempotent: true,
    run: async ({ question, hints }, ctx) =>
      o.semaphore.use(async () => {
        const runId = newId('run');
        const startedAt = new Date().toISOString();
        const provider = o.provider();
        const result = await runAgentSession({
          runId,
          ...(o.caseId ? { caseId: o.caseId } : {}),
          role: 'explore',
          provider,
          system: o.system,
          prompt: `Question: ${question}${hints?.length ? `\nStart from: ${hints.join(', ')}` : ''}`,
          tools,
          submit: { name: 'submit_answer', description: 'Submit the answer with citations.', output: ExploreAnswer },
          budget: { maxSteps: o.maxSteps ?? 10, maxToolCalls: 30, maxOutputTokens: 8000 },
          effort: 'low',
          ...(ctx.signal ? { signal: ctx.signal } : {}),
          ...(o.costOf ? { costOf: o.costOf } : {}),
        });
        await o.onRun?.({
          agentRunId: runId,
          role: 'explore',
          ...(o.caseId ? { caseId: o.caseId } : {}),
          personaId: 'explore',
          ...(o.parentRunId ? { parentRunId: o.parentRunId } : {}),
          provider: provider.id,
          model: provider.model,
          modelsUsed: result.models,
          promptBundleDigest: `sha256:${'0'.repeat(64)}`,
          status: result.status === 'SUSPENDED' ? 'FAILED' : result.status,
          usage: result.usage,
          ...(result.costUsd !== undefined ? { costUsd: result.costUsd } : {}),
          ...(result.output ? { output: result.output } : {}),
          ...(result.error ? { error: result.error } : {}),
          steps: result.steps.map((s) => ({
            index: s.index,
            stopReason: s.stopReason,
            model: s.model,
            toolCalls: s.toolCalls,
          })),
          startedAt,
          completedAt: new Date().toISOString(),
        });
        if (result.status !== 'COMPLETED' || !result.output) {
          return `Exploration ended without an answer (${result.status.toLowerCase()}${result.error ? `: ${result.error}` : ''}).`;
        }
        const refs = result.output.citations.map((c) => `- ${c.path}:${c.startLine}-${c.endLine}`).join('\n');
        return `${result.output.answer}${refs ? `\n\nCitations:\n${refs}` : ''}`;
      }),
  });
}

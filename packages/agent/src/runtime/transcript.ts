import type { CaseRepository } from '@spinxsca/core';
import type { AgentStepRecord } from '@spinxsca/schemas';
import type { ContentBlock, Message } from '../llm/types';

/**
 * Durable transcript checkpoints (ADR-042): the prompt, every model turn and every batch of tool
 * results is saved before the session moves on, so a crashed or parked run resumes exactly where it
 * stopped and never loses a tool_use without its tool_result.
 */
export interface SessionStore {
  load(runId: string): Promise<AgentStepRecord[]>;
  save(step: AgentStepRecord): Promise<void>;
}

export class MemorySessionStore implements SessionStore {
  readonly steps = new Map<string, AgentStepRecord[]>();

  async load(runId: string): Promise<AgentStepRecord[]> {
    return [...(this.steps.get(runId) ?? [])];
  }

  async save(step: AgentStepRecord): Promise<void> {
    const list = (this.steps.get(step.agentRunId) ?? []).filter((s) => s.index !== step.index);
    list.push(step);
    list.sort((a, b) => a.index - b.index);
    this.steps.set(step.agentRunId, list);
  }
}

export function caseSessionStore(cases: Pick<CaseRepository, 'listAgentSteps' | 'saveAgentStep'>): SessionStore {
  return {
    load: (runId) => cases.listAgentSteps(runId),
    save: (step) => cases.saveAgentStep(step),
  };
}

/** Rebuilds provider messages from checkpoints (prompt and results are user turns). */
export function messagesFrom(steps: readonly AgentStepRecord[]): Message[] {
  return steps.map((s) => ({
    role: s.kind === 'turn' ? ('assistant' as const) : ('user' as const),
    content: s.content as ContentBlock[],
  }));
}

import type { Effort, LlmProvider, Message, Usage } from '../llm/types';
import type { AgentTool, SubmitTool } from './tools';

export interface AgentBudget {
  maxSteps: number;
  maxToolCalls: number;
  /** Input + output tokens across all turns. */
  maxTotalTokens: number;
  /** Per-response output cap. */
  maxOutputTokens: number;
}

export const DEFAULT_BUDGET: AgentBudget = {
  maxSteps: 30,
  maxToolCalls: 60,
  maxTotalTokens: 400_000,
  // Ceiling only: the session clamps it to what the model's window and profile allow (ADR-053).
  maxOutputTokens: 32_000,
};

export interface AgentRunOptions<O> {
  role: string;
  provider: LlmProvider;
  system: string;
  prompt: string;
  tools: AgentTool<never>[] | AgentTool[];
  submit: SubmitTool<O>;
  budget?: Partial<AgentBudget>;
  effort?: Effort;
  signal?: AbortSignal;
  scanId?: string;
  onStep?: (step: AgentStep) => void;
  /** Stops the run once the accumulated cost exceeds this amount (needs `costOf`). */
  maxCostUsd?: number;
  costOf?: (usage: Usage, model: string) => number | undefined;
  /** Model-written compaction summary (ADR-056). */
  summarizer?: (dropped: readonly Message[]) => Promise<string>;
}

export interface AgentStep {
  index: number;
  stopReason: string;
  model: string;
  usage: Usage;
  toolCalls: Array<{ name: string; ok: boolean }>;
  fallbacks: Array<{ from: string; to: string }>;
  /** Estimated input tokens of the request that produced this step. */
  contextTokens?: number;
}

export type AgentStatus = 'COMPLETED' | 'BUDGET_EXHAUSTED' | 'REFUSED' | 'FAILED' | 'CANCELLED';

export interface AgentRunResult<O> {
  status: AgentStatus;
  output?: O;
  steps: AgentStep[];
  usage: Usage;
  /** Priced cost of the run, when the models are in the price table. */
  costUsd?: number;
  /** Every model that produced output during the run (audit of fallbacks). */
  models: string[];
  error?: string;
  refusal?: { category?: string; explanation?: string };
  /** Times the outbound view was summarised (ADR-053). */
  compactions?: number;
}

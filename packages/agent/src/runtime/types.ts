import type { Effort, LlmProvider, Usage } from '../llm/types';
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
}

export interface AgentStep {
  index: number;
  stopReason: string;
  model: string;
  usage: Usage;
  toolCalls: Array<{ name: string; ok: boolean }>;
  fallbacks: Array<{ from: string; to: string }>;
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
}

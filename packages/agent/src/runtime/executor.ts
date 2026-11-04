import type { ContentBlock } from '../llm/types';
import { type AgentTool, formatIssues } from './tools';

export type ToolUse = Extract<ContentBlock, { type: 'tool_use' }>;

/** What executing one tool call produced. */
export type ToolOutcome =
  | {
      kind: 'result';
      content: string;
      isError?: boolean;
      /** Policy outcome for the audit trail of the run ("allow L7", "deny L2", ...). */
      decision?: string;
      argsDigest?: string;
      outputDigest?: string;
    }
  /** The call waits for a human (inbox); the session suspends and resumes later. */
  | { kind: 'suspend'; reason: string; approvalId?: string }
  /** A breaker tripped: the session ends after recording this result. */
  | { kind: 'stop'; reason: string; content: string };

export interface ToolExecutor {
  execute(call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome>;
}

export const DEFAULT_OUTPUT_LIMIT = 20_000;

export function capOutput(text: string, limit = DEFAULT_OUTPUT_LIMIT): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n[output truncated: ${text.length - limit} more characters]`;
}

/** Ungoverned executor used by the fixed-pipeline roles (explain, investigate): validate and run. */
export class PlainToolExecutor implements ToolExecutor {
  private readonly tools: Map<string, AgentTool>;

  constructor(tools: readonly AgentTool[]) {
    this.tools = new Map(tools.map((t) => [t.name, t]));
  }

  async execute(call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome> {
    const tool = this.tools.get(call.name);
    if (!tool) return { kind: 'result', content: `Unknown tool ${call.name}.`, isError: true };
    const parsed = tool.input.safeParse(call.input);
    if (!parsed.success) {
      return {
        kind: 'result',
        content: `Invalid input for ${call.name}:\n${formatIssues(parsed.error)}`,
        isError: true,
      };
    }
    try {
      return {
        kind: 'result',
        content: await tool.run(parsed.data, { ...(ctx.signal ? { signal: ctx.signal } : {}) }),
      };
    } catch (err) {
      return {
        kind: 'result',
        content: `Tool ${call.name} failed: ${err instanceof Error ? err.message : String(err)}`,
        isError: true,
      };
    }
  }
}

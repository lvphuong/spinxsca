import { runAgentSession } from './session';
import type { AgentRunOptions, AgentRunResult } from './types';

export * from './types';

/**
 * Minimal tool-use loop (docs/architecture/03 section 8): append-only history, all tool results of a
 * turn returned in one user message, schema-validated inputs, explicit stop-reason handling and hard
 * budgets. The run ends only when the submit tool receives a valid deliverable. A thin wrapper over
 * the durable session without checkpoints or governance (ADR-042), used by the fixed-pipeline roles.
 */
export async function runAgent<O>(options: AgentRunOptions<O>): Promise<AgentRunResult<O>> {
  const {
    resumed: _resumed,
    suspendedOn: _suspended,
    ...result
  } = await runAgentSession({
    ...options,
    runId: 'ephemeral',
    tools: options.tools as never,
  });
  return { ...result, status: result.status === 'SUSPENDED' ? 'FAILED' : result.status };
}

import type { Activity, ActivityContext, ActivityOutput } from '../activity';
import { digestOf } from '../ids';

/**
 * Activity of an agent-requested analyzer run (ADR-043). Keyed by the request, so a resumed case
 * reuses the result instead of running it again; kind PROBE keeps it out of the coverage oracle,
 * so a probe can never make a finding RESOLVED.
 */
export function probeActivity<I, O>(
  name: string,
  keyOf: (input: I) => unknown,
  run: (input: I, ctx: ActivityContext) => Promise<ActivityOutput<O>>,
): Activity<I, O> {
  return {
    name,
    kind: 'PROBE',
    idempotencyKey: (input) => `probe:${name}:${digestOf(keyOf(input))}`,
    run,
  };
}

import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runGovernanceSuite } from '../src/eval/governance-runner';

const SUITE = join(import.meta.dirname, '../../../evals/governance');

describe('governance evaluation suite', () => {
  it('passes the decision matrix without a judge', async () => {
    const result = await runGovernanceSuite({ suiteDir: SUITE });
    expect(result.matrix.failures).toEqual([]);
    expect(result.reviewer).toBeUndefined();
    expect(result.passed).toBe(true);
  });

  it('fails when a reviewer approves dangerous or injected actions', async () => {
    const yes = { id: 'always-yes', judge: async () => '{"verdict":"approve","reason":"looks fine"}' };
    const result = await runGovernanceSuite({ suiteDir: SUITE, judge: yes });
    expect(result.reviewer?.falseAllows.length).toBeGreaterThan(5);
    expect(result.passed).toBe(false);
    const careful = { id: 'never-sure', judge: async () => '{"verdict":"unsure","reason":"not clearly in scope"}' };
    const safe = await runGovernanceSuite({ suiteDir: SUITE, judge: careful });
    expect(safe.reviewer).toMatchObject({ falseAllows: [], benignApproved: 0 });
    expect(safe.passed).toBe(true);
  });
});

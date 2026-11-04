import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { DecisionMatrix, runDecisionMatrix } from '../src/index';

const MATRIX = join(import.meta.dirname, '../../../evals/governance/decision-matrix.yaml');

describe('golden decision matrix', () => {
  const doc = parse(readFileSync(MATRIX, 'utf8'));

  it('has at least 120 rows covering every deciding layer', () => {
    const matrix = DecisionMatrix.parse(doc);
    expect(matrix.rows.length).toBeGreaterThanOrEqual(120);
    const layers = new Set(matrix.rows.map((r) => r.expect.layer));
    for (const layer of ['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L9', 'L10', 'L11', 'L12']) {
      expect(layers.has(layer as never), layer).toBe(true);
    }
  });

  it('matches the policy engine on every row', () => {
    const result = runDecisionMatrix(doc);
    expect(result.failures).toEqual([]);
    expect(result.passed).toBe(result.total);
  });
});

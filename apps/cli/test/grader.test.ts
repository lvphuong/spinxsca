import type { EvalCase } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import { gradeCase, type ReportedFinding } from '../src/eval/grader';

const evalCase: EvalCase = {
  id: 'c',
  title: 't',
  languages: ['javascript'],
  source: 'src',
  findings: [
    {
      id: 'GT-1',
      category: 'SQL_INJECTION',
      cwe: ['CWE-89'],
      path: 'a.js',
      lines: [8, 10],
      detectable_by: ['sast'],
      min_phase: 0,
    },
    {
      id: 'GT-2',
      category: 'XSS',
      cwe: ['CWE-79'],
      path: 'b.jsx',
      lines: [5, 5],
      detectable_by: ['sast'],
      min_phase: 0,
    },
    {
      id: 'GT-3',
      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
      cwe: ['CWE-639'],
      path: 'c.ts',
      lines: [1, 5],
      detectable_by: ['ai'],
      min_phase: 2,
    },
  ],
  negatives: [{ path: 'a.js', lines: [15, 18], reason: 'parameterized' }],
};

const finding = (
  id: string,
  path: string,
  line: number,
  category = 'SQL_INJECTION',
  cwe = ['CWE-89'],
): ReportedFinding => ({
  findingId: id,
  category,
  cwe,
  path,
  startLine: line,
  endLine: line,
});

describe('gradeCase', () => {
  it('counts true positives within the line tolerance and reports misses', () => {
    const grade = gradeCase(evalCase, [finding('F1', 'a.js', 11)], 0);
    expect(grade.truePositives.map((t) => t.truth.id)).toEqual(['GT-1']);
    expect(grade.falseNegatives.map((t) => t.id)).toEqual(['GT-2']);
    expect(grade.pending.map((t) => t.id)).toEqual(['GT-3']);
  });

  it('flags findings in negative regions and wrong categories as false positives', () => {
    const grade = gradeCase(
      evalCase,
      [finding('F1', 'a.js', 16), finding('F2', 'b.jsx', 5, 'SQL_INJECTION', ['CWE-89'])],
      0,
    );
    expect(grade.falsePositives.map((f) => [f.finding.findingId, f.negative])).toEqual([
      ['F1', 'parameterized'],
      ['F2', undefined],
    ]);
  });

  it('never double counts and ignores findings matching pending ground truth', () => {
    const grade = gradeCase(
      evalCase,
      [
        finding('F1', 'a.js', 9),
        finding('F2', 'a.js', 10),
        finding('F3', 'c.ts', 3, 'BROKEN_OBJECT_LEVEL_AUTHORIZATION', ['CWE-639']),
      ],
      0,
    );
    expect(grade.truePositives).toHaveLength(1);
    expect(grade.falsePositives.map((f) => f.finding.findingId)).toEqual(['F2']);
  });
});

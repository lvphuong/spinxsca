import type { ScanReportModel } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import { renderPrComment } from '../src/index';

describe('renderPrComment', () => {
  const entry = (id: string, state: string, severity: string) =>
    ({
      finding: { findingId: id, title: 'SQL injection | x', category: 'SQL_INJECTION' },
      assessment: { reconciliationState: state, severity, classification: 'POTENTIAL', verificationLevel: 'L1_STATIC' },
      occurrence: { locations: [{ path: 'a.js', startLine: 3 }] },
      candidates: [],
      evidence: [],
    }) as unknown as ScanReportModel['present'][number];
  const model = {
    scan: { scanId: 'scan_1', mode: 'INCREMENTAL', baselineScanId: 'scan_0', summary: { completeness: 'PARTIAL' } },
    present: [entry('SPX-000002', 'NEW', 'HIGH'), entry('SPX-000001', 'EXISTING', 'LOW')],
    suppressed: [],
    resolved: [entry('SPX-000003', 'RESOLVED', 'HIGH')],
    notReevaluated: [],
    aiRuns: [],
  } as unknown as ScanReportModel;

  it('summarises new findings, resolved ids and partial coverage', () => {
    const text = renderPrComment(model, { policyPassed: false });
    expect(text.startsWith('<!-- spinxsca -->')).toBe(true);
    expect(text).toContain('**1 new**, 1 existing, 1 resolved');
    expect(text).toContain('| HIGH | `SPX-000002` SQL injection \\| x | `a.js:3` |');
    expect(text).not.toContain('SPX-000001`');
    expect(text).toContain('Resolved: `SPX-000003`');
    expect(text).toContain('Coverage is partial');
    expect(text).toContain('policy failed');
  });
});

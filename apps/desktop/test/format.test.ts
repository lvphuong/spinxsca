import { describe, expect, it } from 'vitest';
import { ApiClient } from '../src/api/client';
import type { JobEntry, ReviewCase } from '../src/api/types';
import { failedReviewJob, findingRows, humanize, matchesFilter, preparingJobs, relativeTime } from '../src/lib/format';

const job = (o: Partial<JobEntry>): JobEntry => ({
  jobId: 'j1',
  kind: 'REVIEW',
  payload: {},
  status: 'QUEUED',
  attempts: 0,
  maxAttempts: 3,
  createdAt: '2026-11-05T10:00:00.000Z',
  updatedAt: '2026-11-05T10:00:00.000Z',
  ...o,
});
const reviewCase = (createdAt: string): ReviewCase => ({
  caseId: `case_${createdAt}`,
  scanId: 's',
  goal: '',
  mode: 'supervised',
  attended: false,
  status: 'RUNNING',
  round: 1,
  createdAt,
});

describe('labels', () => {
  it('humanizes enum values and keeps security acronyms upper case', () => {
    expect(humanize('WRITE_WORKSPACE')).toBe('Write workspace');
    expect(humanize('SQL_INJECTION')).toBe('SQL injection');
    expect(humanize('vulnerable_code_not_in_execute_path')).toBe('Vulnerable code not in execute path');
  });

  it('describes recent times relatively', () => {
    const now = Date.parse('2026-11-05T12:00:00Z');
    expect(relativeTime('2026-11-05T11:59:40Z', now)).toBe('just now');
    expect(relativeTime('2026-11-05T11:35:00Z', now)).toBe('25 min ago');
    expect(relativeTime('2026-11-05T09:00:00Z', now)).toBe('3 h ago');
    expect(relativeTime('2026-11-03T12:00:00Z', now)).toBe('2 d ago');
  });
});

describe('findings', () => {
  it('orders by severity, then confirmed before open before dismissed', () => {
    const handle = (h: string, severity: string) => ({
      handle: h,
      title: h,
      category: 'X',
      severity,
      path: 'a.js',
      startLine: 1,
    });
    const verdict = (h: string, v: string, severity?: string) => ({
      handle: h,
      verdict: v,
      verificationLevel: 'L2_CONTEXT',
      rationale: '',
      ...(severity ? { severity } : {}),
    });
    const rows = findingRows(
      [handle('CF-1', 'LOW'), handle('CF-2', 'HIGH'), handle('CF-3', 'HIGH'), handle('CF-10', 'MEDIUM')],
      [
        verdict('CF-2', 'FALSE_POSITIVE'),
        verdict('CF-3', 'TRUE_POSITIVE'),
        verdict('CF-1', 'TRUE_POSITIVE', 'CRITICAL'),
      ],
    );
    expect(rows.map((r) => r.handle.handle)).toEqual(['CF-1', 'CF-3', 'CF-2', 'CF-10']);
    expect(rows[0]?.severity).toBe('CRITICAL');
    expect(rows.filter((r) => matchesFilter(r, 'open')).map((r) => r.handle.handle)).toEqual(['CF-10']);
  });
});

describe('review jobs', () => {
  it('shows a review as preparing until its case exists', () => {
    const queued = job({ status: 'RUNNING' });
    expect(preparingJobs([queued], [])).toHaveLength(1);
    expect(preparingJobs([queued], [reviewCase('2026-11-05T09:00:00.000Z')])).toHaveLength(1);
    expect(preparingJobs([queued], [reviewCase('2026-11-05T10:03:00.000Z')])).toHaveLength(0);
  });

  it('reports the last review job only when it failed before creating a case', () => {
    const failed = job({
      jobId: 'j2',
      status: 'FAILED',
      error: 'autonomous review needs AI configured on this server',
    });
    expect(failedReviewJob([failed], [])?.error).toContain('needs AI');
    expect(failedReviewJob([failed], [reviewCase('2026-11-05T10:01:00.000Z')])).toBeUndefined();
    const newer = job({ jobId: 'j3', status: 'SUCCEEDED', createdAt: '2026-11-05T11:00:00.000Z' });
    expect(failedReviewJob([failed, newer], [])).toBeUndefined();
  });
});

describe('API client', () => {
  it('reads the project list the server returns as a bare array', async () => {
    const project = { projectId: 'p1', name: 'shop-api', source: { kind: 'local', path: '/x' }, defaultBranch: 'main' };
    const client = new ApiClient({ baseUrl: 'http://127.0.0.1:5000', token: 't' }, async () =>
      Response.json([project]),
    );
    expect((await client.projects()).map((p) => p.name)).toEqual(['shop-api']);
    const legacy = new ApiClient({ baseUrl: 'http://127.0.0.1:5000', token: 't' }, async () =>
      Response.json({ projects: [project] }),
    );
    expect(await legacy.projects()).toHaveLength(1);
  });
});

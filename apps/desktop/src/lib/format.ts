import type { CaseHandle, CaseVerdict, JobEntry, ReviewCase } from '../api/types';

/** Semantic colour of a status; the stylesheet maps each tone to a foreground and a soft fill. */
export type Tone = 'neutral' | 'info' | 'ok' | 'warn' | 'danger';

export interface Label {
  label: string;
  tone: Tone;
}

const ACRONYMS = new Set('sql xss xxe ssrf csrf rce idor jwt api iac poc cve tls os'.split(' '));

/** WRITE_WORKSPACE → "Write workspace", SQL_INJECTION → "SQL injection". */
export function humanize(value: string): string {
  const words = value
    .replace(/[_.-]+/g, ' ')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => (ACRONYMS.has(w) ? w.toUpperCase() : w));
  if (!words.length) return value;
  const [head = '', ...rest] = words;
  return [head.charAt(0).toUpperCase() + head.slice(1), ...rest].join(' ');
}

const lookup = (table: Record<string, Label>, value: string | undefined, fallback: Tone = 'neutral'): Label =>
  (value ? table[value] : undefined) ?? { label: value ? humanize(value) : 'Unknown', tone: fallback };

const CASE_STATUS: Record<string, Label> = {
  RUNNING: { label: 'Running', tone: 'info' },
  PARKED: { label: 'Waiting for you', tone: 'warn' },
  PAUSED: { label: 'Paused', tone: 'warn' },
  CONVERGED: { label: 'Completed', tone: 'ok' },
  STAGNATED: { label: 'Stalled', tone: 'warn' },
  BUDGET_EXHAUSTED: { label: 'Budget reached', tone: 'warn' },
  CANCELLED: { label: 'Cancelled', tone: 'neutral' },
  FAILED: { label: 'Failed', tone: 'danger' },
};
export const caseStatus = (status: string) => lookup(CASE_STATUS, status);

const VERDICT: Record<string, Label> = {
  TRUE_POSITIVE: { label: 'Confirmed', tone: 'danger' },
  FALSE_POSITIVE: { label: 'False positive', tone: 'ok' },
  BLOCKED: { label: 'Blocked', tone: 'warn' },
  UNREVIEWED: { label: 'Unreviewed', tone: 'neutral' },
};
export const verdictLabel = (verdict: string | undefined) => lookup(VERDICT, verdict ?? 'UNREVIEWED');

const OBJECTIVE: Record<string, Label> = {
  MET: { label: 'Met', tone: 'ok' },
  NOT_MET: { label: 'Not met', tone: 'danger' },
  OPEN: { label: 'Open', tone: 'neutral' },
  WAIVED: { label: 'Waived', tone: 'neutral' },
};
export const objectiveStatus = (status: string) => lookup(OBJECTIVE, status);

const CHECK: Record<string, Label> = {
  RAN: { label: 'Ran', tone: 'ok' },
  DEGRADED: { label: 'Degraded', tone: 'warn' },
  NOT_RUN: { label: 'Not run', tone: 'neutral' },
};
export const checkOutcome = (outcome: string) => lookup(CHECK, outcome);

const POC: Record<string, Label> = {
  CONFIRMED: { label: 'PoC confirmed', tone: 'danger' },
  NOT_CONFIRMED: { label: 'PoC not confirmed', tone: 'neutral' },
  INVALID_HARNESS: { label: 'PoC harness invalid', tone: 'warn' },
  BLOCKED: { label: 'PoC blocked', tone: 'warn' },
  ERROR: { label: 'PoC error', tone: 'warn' },
};
export const pocOutcome = (outcome: string) => lookup(POC, outcome);

const APPLICABILITY: Record<string, Label> = {
  AFFECTED: { label: 'Affected', tone: 'danger' },
  NOT_AFFECTED: { label: 'Not affected', tone: 'ok' },
  UNDER_INVESTIGATION: { label: 'Under investigation', tone: 'warn' },
};
export const applicability = (status: string) => lookup(APPLICABILITY, status);

const REACHABILITY: Record<string, string> = {
  CALLED_FROM_ENTRYPOINT: 'Reachable from an entry point',
  CALLED: 'Called by the code',
  IMPORTED_ONLY: 'Imported, never called',
  NOT_IMPORTED: 'Not imported',
  UNKNOWN_TRANSITIVE: 'Transitive, reachability unknown',
};
export const reachability = (level: string) => REACHABILITY[level] ?? humanize(level);

const VERIFICATION: Record<string, string> = {
  L1_STATIC: 'L1 · static analysis',
  L2_CONTEXT: 'L2 · code context',
  L3_CONTROLLED: 'L3 · proof of concept',
};
export const verificationLevel = (level: string) => VERIFICATION[level] ?? humanize(level);

const RISK: Record<string, Label> = {
  READ: { label: 'Reads', tone: 'neutral' },
  RECORD: { label: 'Records', tone: 'neutral' },
  ANALYZE: { label: 'Analyzes', tone: 'neutral' },
  WRITE_WORKSPACE: { label: 'Writes a workspace copy', tone: 'neutral' },
  EXEC_REPO_CODE: { label: 'Runs repository code', tone: 'warn' },
  WRITE_REPO: { label: 'Writes the repository', tone: 'danger' },
  EXTERNAL: { label: 'External system', tone: 'danger' },
  GOVERNANCE: { label: 'Governance', tone: 'warn' },
};
export const riskLabel = (risk: string) => lookup(RISK, risk);

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export const severityRank = (severity: string | undefined) => {
  const i = SEVERITIES.indexOf((severity ?? '').toUpperCase() as (typeof SEVERITIES)[number]);
  return i < 0 ? SEVERITIES.length : i;
};

const VERDICT_RANK: Record<string, number> = { TRUE_POSITIVE: 0, BLOCKED: 1, UNREVIEWED: 2, FALSE_POSITIVE: 3 };

export interface FindingRow {
  handle: CaseHandle;
  verdict?: CaseVerdict;
  severity: string;
}

/** Findings of a case joined with their latest verdict, most severe and most actionable first. */
export function findingRows(handles: CaseHandle[], verdicts: CaseVerdict[]): FindingRow[] {
  const byHandle = new Map(verdicts.map((v) => [v.handle, v]));
  return handles
    .map((h) => {
      const verdict = byHandle.get(h.handle);
      return { handle: h, ...(verdict ? { verdict } : {}), severity: verdict?.severity ?? h.severity };
    })
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        (VERDICT_RANK[a.verdict?.verdict ?? 'UNREVIEWED'] ?? 9) -
          (VERDICT_RANK[b.verdict?.verdict ?? 'UNREVIEWED'] ?? 9) ||
        a.handle.handle.localeCompare(b.handle.handle, undefined, { numeric: true }),
    );
}

export type FindingFilter = 'all' | 'confirmed' | 'open' | 'dismissed';

export function matchesFilter(row: FindingRow, filter: FindingFilter): boolean {
  const v = row.verdict?.verdict ?? 'UNREVIEWED';
  if (filter === 'confirmed') return v === 'TRUE_POSITIVE';
  if (filter === 'open') return v === 'UNREVIEWED' || v === 'BLOCKED';
  if (filter === 'dismissed') return v === 'FALSE_POSITIVE';
  return true;
}

/** "just now", "5 min ago", "3 h ago", "2 d ago", then a short date. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const seconds = Math.round((now - then) / 1000);
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days} d ago`;
  return new Date(then).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export const clockTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString(undefined, { hour12: false });
};

export const usd = (value: number) => `$${value.toFixed(2)}`;

export const caseTitle = (c: Pick<ReviewCase, 'goal'>) => c.goal.trim() || 'Full security review';

/**
 * Review jobs that have not produced a case yet: the scan runs before the review case exists, which
 * takes minutes. A case created after a job was queued is taken as that job's case.
 */
export function preparingJobs(jobs: JobEntry[], cases: ReviewCase[]): JobEntry[] {
  return jobs
    .filter((j) => j.kind === 'REVIEW' && (j.status === 'QUEUED' || j.status === 'RUNNING'))
    .filter((j) => !cases.some((c) => c.createdAt >= j.createdAt));
}

/** The most recent review job, when it failed before creating a case. */
export function failedReviewJob(jobs: JobEntry[], cases: ReviewCase[]): JobEntry | undefined {
  const last = jobs.filter((j) => j.kind === 'REVIEW').sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  if (last?.status !== 'FAILED') return undefined;
  return cases.some((c) => c.createdAt >= last.createdAt) ? undefined : last;
}

/** Case statuses a review can still be paused, resumed or stopped from. */
export const ACTIVE_CASE_STATUSES: ReadonlySet<string> = new Set(['RUNNING', 'PARKED', 'PAUSED']);

/** The queued or running job that resumes a case (after Resume or an answered approval). */
export function resumeJobFor(jobs: JobEntry[], caseId: string): JobEntry | undefined {
  return jobs.find(
    (j) => j.kind === 'CASE_RESUME' && j.payload.caseId === caseId && (j.status === 'QUEUED' || j.status === 'RUNNING'),
  );
}

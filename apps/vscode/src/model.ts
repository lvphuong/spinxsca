/** Editor-independent model: findings from the CLI or the server become diagnostics. */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Level = 'error' | 'warning' | 'information' | 'hint';

export interface Location {
  path: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

export interface DiagnosticSpec {
  path: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  level: Level;
  severity: Severity;
  findingId: string;
  message: string;
  state: string;
}

const RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export function levelOf(severity: Severity): Level {
  return severity === 'CRITICAL' || severity === 'HIGH'
    ? 'error'
    : severity === 'MEDIUM'
      ? 'warning'
      : severity === 'LOW'
        ? 'information'
        : 'hint';
}

export function atLeast(severity: Severity, minimum: string): boolean {
  return RANK[severity] >= RANK[minimum.toUpperCase() as Severity];
}

/** Entry of `spinxsca findings list --json`. */
export interface CliFinding {
  finding: { findingId: string; title: string; category: string; cwe: string[] };
  assessment: {
    severity: Severity;
    reconciliationState: string;
    classification: string;
    changeCauses?: string[];
    intel?: { kev?: { dateAdded: string }; epss?: { score: number } };
  };
  location: Location | null;
  disposition: { kind: string } | null;
}

const OPEN = new Set(['NEW', 'EXISTING', 'REOPENED', 'NEEDS_RECONCILIATION']);

function message(title: string, category: string, cwe: string[], extra: string[]): string {
  return [`${title} (${category}${cwe.length ? `, ${cwe.join(', ')}` : ''})`, ...extra].join(' · ');
}

export function diagnosticsFromCli(entries: readonly CliFinding[], minSeverity = 'low'): DiagnosticSpec[] {
  const out: DiagnosticSpec[] = [];
  for (const e of entries) {
    if (!e.location || e.disposition || !OPEN.has(e.assessment.reconciliationState)) continue;
    if (e.assessment.classification === 'UNLIKELY' || !atLeast(e.assessment.severity, minSeverity)) continue;
    const extra: string[] = [];
    if (e.assessment.intel?.kev) extra.push(`CISA KEV since ${e.assessment.intel.kev.dateAdded}`);
    if (e.assessment.intel?.epss) extra.push(`EPSS ${e.assessment.intel.epss.score.toFixed(2)}`);
    if (e.assessment.reconciliationState !== 'EXISTING')
      extra.push(e.assessment.reconciliationState.toLowerCase().replace(/_/g, ' '));
    out.push({
      path: e.location.path,
      startLine: e.location.startLine,
      endLine: e.location.endLine,
      ...(e.location.startColumn ? { startColumn: e.location.startColumn } : {}),
      ...(e.location.endColumn ? { endColumn: e.location.endColumn } : {}),
      level: levelOf(e.assessment.severity),
      severity: e.assessment.severity,
      findingId: e.finding.findingId,
      message: message(e.finding.title, e.finding.category, e.finding.cwe, extra),
      state: e.assessment.reconciliationState,
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path) || a.startLine - b.startLine);
}

/** Row of `GET /v1/projects/:id/findings?branch=` from a spinxsca server. */
export interface ServerFinding {
  findingId: string;
  title: string;
  category: string;
  cwe: string[];
  branch: {
    state: 'OPEN' | 'FIXED' | 'NOT_REEVALUATED' | 'SUPPRESSED';
    severity: Severity;
    kev?: boolean;
    epss?: number;
    location?: Location;
  };
}

export function diagnosticsFromServer(rows: readonly ServerFinding[], minSeverity = 'low'): DiagnosticSpec[] {
  const out: DiagnosticSpec[] = [];
  for (const r of rows) {
    const cell = r.branch;
    if (
      !cell.location ||
      (cell.state !== 'OPEN' && cell.state !== 'NOT_REEVALUATED') ||
      !atLeast(cell.severity, minSeverity)
    )
      continue;
    const extra = [
      ...(cell.kev ? ['CISA KEV'] : []),
      ...(cell.epss !== undefined ? [`EPSS ${cell.epss.toFixed(2)}`] : []),
      ...(cell.state === 'NOT_REEVALUATED' ? ['not re-evaluated by the last scan'] : []),
    ];
    out.push({
      path: cell.location.path,
      startLine: cell.location.startLine,
      endLine: cell.location.endLine,
      level: levelOf(cell.severity),
      severity: cell.severity,
      findingId: r.findingId,
      message: message(r.title, r.category, r.cwe, extra),
      state: cell.state,
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path) || a.startLine - b.startLine);
}

export function summary(specs: readonly DiagnosticSpec[]): string {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<Severity, number>;
  for (const s of specs) counts[s.severity]++;
  const parts = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)
    .filter((k) => counts[k])
    .map((k) => `${counts[k]} ${k.toLowerCase()}`);
  return parts.length ? parts.join(', ') : 'no open findings';
}

/** The spinxsca finding id at a line, if any (code actions). */
export function findingsAt(specs: readonly DiagnosticSpec[], path: string, line: number): DiagnosticSpec[] {
  return specs.filter((s) => s.path === path && s.startLine <= line && s.endLine >= line);
}

import type { ScanReportModel } from '@spinxsca/core';

/** Machine-readable report: every record with its schema shape (docs/architecture/05 section 5). */
export function renderJson(model: ScanReportModel): string {
  const entry = (e: ScanReportModel['present'][number]) => ({
    finding: e.finding,
    assessment: e.assessment,
    occurrence: e.occurrence ?? null,
    candidates: e.candidates,
    evidence: e.evidence,
    disposition: e.disposition ?? null,
    explanation: e.explanation?.output ?? null,
  });
  return `${JSON.stringify(
    {
      schema: 'spinxsca/report/v1',
      project: model.project,
      scan: model.scan,
      snapshot: model.snapshot,
      tasks: model.tasks,
      findings: model.present.map(entry),
      suppressed: model.suppressed.map(entry),
      aiRuns: model.aiRuns.map((r) => ({ ...r, output: undefined })),
      resolved: model.resolved.map(entry),
      notReevaluated: model.notReevaluated.map(entry),
    },
    null,
    2,
  )}\n`;
}

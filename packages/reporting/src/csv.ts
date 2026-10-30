import type { ScanReportModel } from '@spinxsca/core';

const HEADER = [
  'finding_id',
  'state',
  'severity',
  'classification',
  'verification',
  'category',
  'cwe',
  'path',
  'line',
  'title',
  'package',
  'advisories',
  'disposition',
];

/** Flat export for spreadsheets and ticket imports. */
export function renderCsv(model: ScanReportModel): string {
  const rows = [...model.present, ...model.suppressed, ...model.notReevaluated, ...model.resolved].map((e) => {
    const loc = e.occurrence?.locations[0];
    const candidate = e.candidates[0];
    return [
      e.finding.findingId,
      e.assessment.reconciliationState,
      e.assessment.severity,
      e.assessment.classification,
      e.assessment.verificationLevel,
      e.finding.category,
      e.finding.cwe.join(' '),
      loc?.path ?? '',
      loc ? String(loc.startLine) : '',
      e.finding.title,
      candidate?.package?.purl ?? '',
      (candidate?.vulnerabilityIds ?? []).join(' '),
      e.disposition ? `${e.disposition.kind}: ${e.disposition.reason}` : '',
    ];
  });
  return `${[HEADER, ...rows].map((r) => r.map(cell).join(',')).join('\n')}\n`;
}

function cell(value: string): string {
  // Neutralise spreadsheet formulas and quote every field.
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${safe.replace(/"/g, '""')}"`;
}

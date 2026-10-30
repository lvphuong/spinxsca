export { renderCsv } from './csv';
export { renderJson } from './json';
export { describeIntel, renderMarkdown } from './markdown';
export { renderPrComment } from './pr-comment';
export { renderSarif } from './sarif';

export const REPORT_FORMATS = ['sarif', 'md', 'json'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];
export const REPORT_FILENAMES: Record<ReportFormat, string> = {
  sarif: 'report.sarif',
  md: 'report.md',
  json: 'report.json',
};

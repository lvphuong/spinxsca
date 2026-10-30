import { ENGINE_VERSION, FINGERPRINT_ALGORITHM, type ReportEntry, type ScanReportModel } from '@spinxsca/core';
import type { ReconciliationState, Severity } from '@spinxsca/schemas';

/** GitHub code scanning reads `security-severity` (0-10) to bucket results. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  CRITICAL: '9.5',
  HIGH: '8.0',
  MEDIUM: '5.0',
  LOW: '2.0',
  INFO: '0.0',
};
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
  INFO: 'note',
};
const BASELINE_STATE: Partial<Record<ReconciliationState, 'new' | 'unchanged' | 'updated'>> = {
  NEW: 'new',
  REOPENED: 'new',
  NEEDS_RECONCILIATION: 'updated',
  EXISTING: 'unchanged',
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: string };
  properties: Record<string, unknown>;
}

/** SARIF 2.1.0 for code scanning integrations (ADR-014). Only findings present in the scan are results. */
export function renderSarif(model: ScanReportModel): string {
  const rules = new Map<string, SarifRule>();
  const results = [...model.present, ...model.suppressed].map((entry) => {
    const ruleId = entry.occurrence?.ruleIds[0] ?? entry.finding.ruleFamily;
    const candidate = entry.candidates.find((c) => c.ruleId === ruleId) ?? entry.candidates[0];
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: entry.finding.title,
        shortDescription: { text: entry.finding.title },
        fullDescription: { text: candidate?.message || entry.finding.title },
        help: { text: candidate?.message || entry.finding.title },
        defaultConfiguration: { level: LEVEL[entry.assessment.severity] },
        properties: {
          tags: ['security', entry.finding.category, ...entry.finding.cwe],
          precision: entry.assessment.confidence.toLowerCase(),
          'security-severity': SECURITY_SEVERITY[entry.assessment.severity],
        },
      });
    }
    const primary = entry.occurrence?.locations[0];
    return {
      ruleId,
      level: LEVEL[entry.assessment.severity],
      message: { text: `${entry.finding.title} [${entry.finding.findingId}]. ${candidate?.message ?? ''}`.trim() },
      locations: primary
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: primary.path, uriBaseId: '%SRCROOT%' },
                region: {
                  startLine: primary.startLine,
                  endLine: primary.endLine,
                  ...(primary.startColumn ? { startColumn: primary.startColumn } : {}),
                  ...(primary.endColumn ? { endColumn: primary.endColumn } : {}),
                },
              },
            },
          ]
        : [],
      partialFingerprints: entry.occurrence ? { [FINGERPRINT_ALGORITHM]: entry.occurrence.fingerprint } : {},
      ...(BASELINE_STATE[entry.assessment.reconciliationState]
        ? { baselineState: BASELINE_STATE[entry.assessment.reconciliationState] }
        : {}),
      ...(entry.disposition
        ? {
            suppressions: [
              {
                kind: 'external',
                status: 'accepted',
                justification: `${entry.disposition.kind}: ${entry.disposition.reason}`,
              },
            ],
          }
        : {}),
      properties: resultProperties(entry),
    };
  });

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'spinxsca',
            fullName: 'Spinx SecureCode AI',
            version: ENGINE_VERSION,
            rules: [...rules.values()].sort((a, b) => a.id.localeCompare(b.id)),
          },
        },
        automationDetails: { id: `spinxsca/${model.scan.mode.toLowerCase()}/${model.scan.scanId}` },
        results,
        properties: {
          scanId: model.scan.scanId,
          status: model.scan.status,
          snapshotId: model.snapshot.snapshotId,
          snapshotKind: model.snapshot.kind,
          commitSha: model.snapshot.commitSha ?? null,
          manifestDigest: model.scan.manifestDigest,
          baselineScanId: model.scan.baselineScanId ?? null,
          completeness: model.scan.summary?.completeness ?? null,
        },
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function resultProperties(entry: ReportEntry): Record<string, unknown> {
  return {
    findingId: entry.finding.findingId,
    category: entry.finding.category,
    cwe: entry.finding.cwe,
    severity: entry.assessment.severity,
    confidence: entry.assessment.confidence,
    classification: entry.assessment.classification,
    verificationLevel: entry.assessment.verificationLevel,
    reconciliationState: entry.assessment.reconciliationState,
    firstSeenScanId: entry.finding.firstSeenScanId,
    ...(entry.candidates[0]?.package ? { package: entry.candidates[0].package.purl } : {}),
    ...(entry.candidates[0]?.vulnerabilityIds ? { vulnerabilityIds: entry.candidates[0].vulnerabilityIds } : {}),
    ...(entry.assessment.intel
      ? {
          cves: entry.assessment.intel.cves,
          ...(entry.assessment.intel.kev ? { kev: true, kevDateAdded: entry.assessment.intel.kev.dateAdded } : {}),
          ...(entry.assessment.intel.epss
            ? { epss: entry.assessment.intel.epss.score, epssPercentile: entry.assessment.intel.epss.percentile }
            : {}),
          ...(entry.assessment.intel.cvss
            ? { cvss: entry.assessment.intel.cvss.baseScore, cvssVector: entry.assessment.intel.cvss.vector }
            : {}),
        }
      : {}),
  };
}

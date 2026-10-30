import type { CandidateDraft } from '@spinxsca/core';
import { normalizeRelPath } from '@spinxsca/core';
import { Category, type Confidence, categoryFromCwes, normalizeCwe, type Severity } from '@spinxsca/schemas';

/** Subset of `semgrep --json` output used by the adapter. */
export interface SemgrepJson {
  version?: string;
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    extra: {
      message?: string;
      severity?: string;
      fingerprint?: string;
      metadata?: Record<string, unknown>;
    };
  }>;
  errors: Array<{ level?: string; type?: unknown; message?: string; path?: string }>;
  paths: { scanned: string[] };
}

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: 'CRITICAL',
  ERROR: 'HIGH',
  HIGH: 'HIGH',
  WARNING: 'MEDIUM',
  MEDIUM: 'MEDIUM',
  INFO: 'LOW',
  LOW: 'LOW',
  INVENTORY: 'INFO',
  EXPERIMENT: 'INFO',
};

const UNAVAILABLE = 'requires login';

export function normalizeSemgrepResults(
  json: SemgrepJson,
  options: { bundleOf: (ruleId: string) => string | undefined; allowedPaths: ReadonlySet<string> },
): CandidateDraft[] {
  const drafts: CandidateDraft[] = [];
  for (const result of json.results) {
    const path = normalizeRelPath(result.path.replace(/^\/src\/?/, ''));
    if (!options.allowedPaths.has(path)) continue;
    const metadata = result.extra.metadata ?? {};
    const spinx = (metadata.spinxsca ?? {}) as Record<string, unknown>;
    const cwe = [
      ...new Set(
        toArray(metadata.cwe)
          .map(normalizeCwe)
          .filter((c): c is string => c !== undefined),
      ),
    ];
    const declared = Category.safeParse(spinx.category);
    const category = declared.success ? declared.data : categoryFromCwes(cwe);
    const bundle = options.bundleOf(result.check_id);
    const ruleId = bundle ? `${bundle}.${result.check_id}` : result.check_id;
    const severityOverride =
      typeof spinx.severity === 'string' ? SEVERITY_MAP[spinx.severity.toUpperCase()] : undefined;
    drafts.push({
      scanner: 'semgrep',
      ruleId,
      ruleFamily: typeof spinx.family === 'string' ? spinx.family : category.toLowerCase(),
      category,
      cwe,
      title: typeof spinx.title === 'string' ? spinx.title : humanize(result.check_id),
      message: (result.extra.message ?? '').trim(),
      severityHint: severityOverride ?? SEVERITY_MAP[(result.extra.severity ?? '').toUpperCase()] ?? 'MEDIUM',
      confidenceHint: toConfidence(metadata.confidence),
      locations: [
        {
          path,
          startLine: result.start.line,
          endLine: Math.max(result.end.line, result.start.line),
          startColumn: Math.max(1, result.start.col),
          endColumn: Math.max(1, result.end.col),
          role: 'primary',
        },
      ],
      ...(result.extra.fingerprint && result.extra.fingerprint !== UNAVAILABLE
        ? { scannerFingerprint: result.extra.fingerprint }
        : {}),
    });
  }
  return drafts;
}

function toArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return typeof value === 'string' ? [value] : [];
}

function toConfidence(value: unknown): Confidence {
  const upper = typeof value === 'string' ? value.toUpperCase() : '';
  return upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW' ? upper : 'MEDIUM';
}

function humanize(checkId: string): string {
  const last = checkId.split('.').at(-1) ?? checkId;
  const words = last.replace(/[-_]+/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

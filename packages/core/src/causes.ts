import type { AnalysisManifest, ChangeCause } from '@spinxsca/schemas';
import { digestOf } from './ids';

/** File names whose changes are dependency changes rather than code changes. */
const DEPENDENCY_FILES =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|package\.json|requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|pom\.xml|gradle\.lockfile|build\.gradle(\.kts)?|go\.mod|go\.sum|Cargo\.lock|Gemfile\.lock|composer\.lock|packages\.lock\.json)$/;

export function isDependencyManifest(path: string): boolean {
  return DEPENDENCY_FILES.test(path);
}

export interface CauseSubject {
  path: string;
  ruleIds: readonly string[];
  scanners: readonly string[];
  vulnerabilityIds: readonly string[];
}

export type CauseAttributor = (subject: CauseSubject) => ChangeCause[];

/**
 * Explains, per finding, why it appeared or disappeared relative to the baseline
 * (docs/thiet-ke.md section 39): code or dependency change, new or updated advisory, rule or scanner
 * change, or a change of scope. Several causes can apply at once.
 */
export function buildCauseAttributor(input: {
  baseline?: AnalysisManifest;
  current: AnalysisManifest;
  baselineFiles?: ReadonlyMap<string, string>;
  currentFiles: ReadonlyMap<string, string>;
  advisories?: { added: ReadonlySet<string>; modified: ReadonlySet<string> };
}): CauseAttributor {
  const { baseline, current } = input;
  if (!baseline) return () => ['FIRST_SCAN'];
  const prevBundles = new Map(baseline.ruleBundles.map((b) => [b.id, b.digest]));
  const prevScanners = new Map(baseline.scannerBundle.scanners.map((s) => [s.id, `${s.image}|${s.adapterVersion}`]));
  const scopeChanged = digestOf(baseline.scope) !== digestOf(current.scope);
  return (subject) => {
    const causes = new Set<ChangeCause>();
    if (input.baselineFiles && input.baselineFiles.get(subject.path) !== input.currentFiles.get(subject.path)) {
      causes.add(isDependencyManifest(subject.path) ? 'DEPENDENCY_CHANGE' : 'CODE_CHANGE');
    }
    for (const id of subject.vulnerabilityIds) {
      if (input.advisories?.added.has(id)) causes.add('NEW_ADVISORY');
      else if (input.advisories?.modified.has(id)) causes.add('ADVISORY_UPDATED');
    }
    for (const bundle of current.ruleBundles) {
      if (!subject.ruleIds.some((r) => r.startsWith(`${bundle.id}.`))) continue;
      const before = prevBundles.get(bundle.id);
      if (before === undefined) causes.add('RULE_ADDED');
      else if (before !== bundle.digest) causes.add('RULE_UPDATED');
    }
    for (const scanner of current.scannerBundle.scanners) {
      if (!subject.scanners.includes(scanner.id)) continue;
      const before = prevScanners.get(scanner.id);
      if (before === undefined) causes.add('COVERAGE_CHANGE');
      else if (before !== `${scanner.image}|${scanner.adapterVersion}`) causes.add('SCANNER_UPGRADED');
    }
    if (scopeChanged) causes.add('COVERAGE_CHANGE');
    return causes.size > 0 ? [...causes] : ['UNKNOWN'];
  };
}

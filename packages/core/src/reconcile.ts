import type {
  ChangeCause,
  Confidence,
  Finding,
  FindingAssessment,
  FindingCandidate,
  FindingMatchEvent,
  FindingOccurrence,
  FingerprintAnchor,
  Location,
  ReconciliationState,
  Severity,
} from '@spinxsca/schemas';
import { SEVERITY_RANK } from '@spinxsca/schemas';
import type { CauseAttributor, CauseSubject } from './causes';
import type { CoverageOracle } from './coverage';
import type { ReconciliationCommit } from './ports';

/** States in which a finding is considered still open in a baseline. */
export const OPEN_STATES: ReadonlySet<ReconciliationState> = new Set([
  'NEW',
  'EXISTING',
  'REOPENED',
  'NOT_REEVALUATED',
  'NEEDS_RECONCILIATION',
]);

/** States in which a finding is present in the current scan. */
export const PRESENT_STATES: ReadonlySet<ReconciliationState> = new Set([
  'NEW',
  'EXISTING',
  'REOPENED',
  'NEEDS_RECONCILIATION',
]);

export interface PriorFinding {
  finding: Finding;
  /** Assessment in the baseline scan, when the finding was assessed there. */
  baselineAssessment?: FindingAssessment;
  /** Most recent assessment in any scan. */
  latestAssessment?: FindingAssessment;
  latestOccurrence?: FindingOccurrence;
}

/** Candidates that share one semantic fingerprint become a single occurrence. */
export interface CandidateGroup {
  fingerprint: string;
  anchor: FingerprintAnchor;
  candidates: FindingCandidate[];
}

export interface ReconcileInput {
  projectId: string;
  scanId: string;
  snapshotId: string;
  algorithm: string;
  groups: CandidateGroup[];
  prior: PriorFinding[];
  fingerprintIndex: ReadonlyMap<string, string>;
  coverage: CoverageOracle;
  /** Explains why a finding appeared or disappeared (manifest, file and advisory diffs). */
  causesFor: CauseAttributor;
  nextSeq: number;
  now: string;
  newId: (prefix: string) => string;
}

export interface ReconcileOutput extends ReconciliationCommit {
  stateByFinding: Map<string, ReconciliationState>;
}

const CONFIDENCE_RANK: Record<Confidence, number> = { HIGH: 2, MEDIUM: 1, LOW: 0 };

export function groupCandidates(candidates: readonly FindingCandidate[]): CandidateGroup[] {
  const groups = new Map<string, CandidateGroup>();
  for (const candidate of candidates) {
    const key = candidate.fingerprints.semantic;
    const group = groups.get(key);
    if (group) group.candidates.push(candidate);
    else groups.set(key, { fingerprint: key, anchor: candidate.fingerprints.anchor, candidates: [candidate] });
  }
  // Deterministic order by location so new finding ids follow the source order.
  return [...groups.values()].sort((a, b) => {
    const la = primaryLocation(a);
    const lb = primaryLocation(b);
    return la.path.localeCompare(lb.path) || la.startLine - lb.startLine || a.fingerprint.localeCompare(b.fingerprint);
  });
}

function primaryLocation(group: CandidateGroup): Location {
  const locations = group.candidates.flatMap((c) => c.locations);
  return (locations.find((l) => l.role === 'primary') ?? locations[0]) as Location;
}

/**
 * Coverage-aware reconciliation (docs/architecture/02 section 6.2):
 * exact fingerprint -> relocated (same symbol and shape, different path) -> near (same path and
 * symbol, different shape; flagged for review, never auto-merged) -> new. Previously open findings
 * that were not matched become RESOLVED only when coverage proves absence, otherwise NOT_REEVALUATED.
 */
export function reconcile(input: ReconcileInput): ReconcileOutput {
  const out: ReconcileOutput = {
    newFindings: [],
    fingerprintAliases: [],
    occurrences: [],
    assessments: [],
    matchEvents: [],
    stateByFinding: new Map(),
  };
  const priorById = new Map(input.prior.map((p) => [p.finding.findingId, p]));
  const open = input.prior.filter(
    (p) => p.baselineAssessment && OPEN_STATES.has(p.baselineAssessment.reconciliationState),
  );
  const matched = new Set<string>();
  const pendingReview = new Set<string>();
  let seq = input.nextSeq;

  const event = (
    findingId: string,
    candidateId: string | undefined,
    method: FindingMatchEvent['method'],
    confidence: Confidence,
    decision: ReconciliationState,
    detail: string,
  ): void => {
    out.matchEvents.push({
      eventId: input.newId('match'),
      scanId: input.scanId,
      ...(candidateId ? { candidateId } : {}),
      findingId,
      method,
      confidence,
      decision,
      decidedBy: 'host',
      detail,
      createdAt: input.now,
    });
  };

  const createFinding = (group: CandidateGroup): Finding => {
    const primary = sortedCandidates(group)[0] as FindingCandidate;
    const finding: Finding = {
      findingId: `SPX-${String(seq).padStart(6, '0')}`,
      projectId: input.projectId,
      seq,
      category: primary.category,
      ruleFamily: primary.ruleFamily,
      title: primary.title,
      cwe: unique(group.candidates.flatMap((c) => c.cwe)).sort(),
      canonicalFingerprint: group.fingerprint,
      fingerprintAlgorithm: input.algorithm,
      firstSeenScanId: input.scanId,
      createdAt: input.now,
    };
    seq++;
    out.newFindings.push(finding);
    return finding;
  };

  for (const group of input.groups) {
    const primaryCandidate = sortedCandidates(group)[0] as FindingCandidate;
    let findingId: string | undefined;
    let state: ReconciliationState;
    let causes: ChangeCause[] = [];

    const exactId = input.fingerprintIndex.get(group.fingerprint);
    const relocated = exactId ? undefined : findUnique(open, matched, (p) => isRelocation(p, group));
    const near = exactId || relocated ? undefined : findUnique(open, matched, (p) => isNear(p, group));

    if (exactId && !matched.has(exactId)) {
      findingId = exactId;
      const prior = priorById.get(exactId);
      const baselineState = prior?.baselineAssessment?.reconciliationState;
      if (baselineState && OPEN_STATES.has(baselineState)) state = 'EXISTING';
      else if (prior?.latestAssessment?.reconciliationState === 'RESOLVED') {
        state = 'REOPENED';
        causes = input.causesFor(groupSubject(group));
      } else state = 'EXISTING';
      event(
        findingId,
        primaryCandidate.candidateId,
        'EXACT_FINGERPRINT',
        'HIGH',
        state,
        'semantic fingerprint matched',
      );
    } else if (relocated) {
      findingId = relocated.finding.findingId;
      state = 'EXISTING';
      out.fingerprintAliases.push({ findingId, fingerprint: group.fingerprint, algorithm: input.algorithm });
      event(
        findingId,
        primaryCandidate.candidateId,
        'RELOCATED',
        'HIGH',
        state,
        `same symbol and code shape moved from ${relocated.latestOccurrence?.anchor.path} to ${group.anchor.path}`,
      );
    } else {
      const finding = createFinding(group);
      findingId = finding.findingId;
      if (near) {
        state = 'NEEDS_RECONCILIATION';
        pendingReview.add(near.finding.findingId);
        causes = input.causesFor(groupSubject(group));
        event(
          findingId,
          primaryCandidate.candidateId,
          'NEAR',
          'MEDIUM',
          state,
          `possible continuation of ${near.finding.findingId} (same path and symbol, code changed); needs review`,
        );
      } else {
        state = 'NEW';
        causes = input.causesFor(groupSubject(group));
        event(findingId, primaryCandidate.candidateId, 'NONE', 'HIGH', state, 'no prior finding matched');
      }
    }

    matched.add(findingId);
    const occurrence: FindingOccurrence = {
      occurrenceId: input.newId('occ'),
      findingId,
      scanId: input.scanId,
      snapshotId: input.snapshotId,
      locations: mergeLocations(group.candidates),
      fingerprint: group.fingerprint,
      anchor: group.anchor,
      ruleIds: unique(group.candidates.map((c) => c.ruleId)).sort(),
      candidateIds: group.candidates.map((c) => c.candidateId).sort(),
      evidenceIds: unique(group.candidates.flatMap((c) => c.evidenceIds)),
    };
    out.occurrences.push(occurrence);
    out.assessments.push(presentAssessment(input, group, occurrence, state, causes));
    out.stateByFinding.set(findingId, state);
  }

  for (const prior of open) {
    const id = prior.finding.findingId;
    if (matched.has(id)) continue;
    const base = prior.baselineAssessment as FindingAssessment;
    let state: ReconciliationState;
    let reason: string;
    if (pendingReview.has(id)) {
      state = 'NEEDS_RECONCILIATION';
      reason = 'a nearby candidate may be the same finding after a code change; needs review';
    } else {
      const verdict = input.coverage.provesAbsence(prior.finding, prior.latestOccurrence);
      state = verdict.proven ? 'RESOLVED' : 'NOT_REEVALUATED';
      reason = verdict.reason;
    }
    out.assessments.push({
      assessmentId: input.newId('asm'),
      findingId: id,
      scanId: input.scanId,
      reconciliationState: state,
      classification: state === 'RESOLVED' ? 'NOT_EVALUATED' : base.classification,
      severity: base.severity,
      confidence: base.confidence,
      exploitability: base.exploitability,
      verificationLevel: base.verificationLevel,
      evidenceIds: [],
      counterevidence: [],
      missingEvidence: state === 'NOT_REEVALUATED' ? [reason] : [],
      reasoningSummary:
        state === 'RESOLVED'
          ? `Not reported by this scan and coverage proves absence: ${reason}.`
          : state === 'NOT_REEVALUATED'
            ? `Carried forward from scan ${base.scanId}; not re-evaluated: ${reason}.`
            : `Flagged for review: ${reason}.`,
      changeCauses:
        state === 'RESOLVED' && prior.latestOccurrence
          ? input.causesFor(occurrenceSubject(prior.latestOccurrence))
          : [],
      assessedBy: 'host:reconciliation',
      assessedAt: input.now,
    });
    out.matchEvents.push({
      eventId: input.newId('match'),
      scanId: input.scanId,
      findingId: id,
      method: 'NONE',
      confidence: 'HIGH',
      decision: state,
      decidedBy: 'host',
      detail: reason,
      createdAt: input.now,
    });
    out.stateByFinding.set(id, state);
  }
  return out;
}

function presentAssessment(
  input: ReconcileInput,
  group: CandidateGroup,
  occurrence: FindingOccurrence,
  state: ReconciliationState,
  causes: ChangeCause[],
): FindingAssessment {
  const severity = group.candidates
    .map((c) => c.severityHint)
    .reduce<Severity>((a, b) => (SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a), 'INFO');
  const confidence = group.candidates
    .map((c) => c.confidenceHint)
    .reduce<Confidence>((a, b) => (CONFIDENCE_RANK[b] > CONFIDENCE_RANK[a] ? b : a), 'LOW');
  const source = occurrence.locations.find((l) => l.role === 'source');
  const sink = occurrence.locations.find((l) => l.role === 'sink') ?? occurrence.locations[0];
  const rules = occurrence.ruleIds.join(', ');
  return {
    assessmentId: input.newId('asm'),
    findingId: occurrence.findingId,
    scanId: input.scanId,
    occurrenceId: occurrence.occurrenceId,
    reconciliationState: state,
    classification: 'POTENTIAL',
    severity,
    confidence,
    exploitability: 'UNKNOWN',
    verificationLevel: 'L1_STATIC',
    ...(source || sink
      ? {
          attackPath: {
            ...(source ? { source: `${source.path}:${source.startLine}` } : {}),
            ...(sink ? { sink: `${sink.path}:${sink.startLine}` } : {}),
            preconditions: [],
            controls: [],
          },
        }
      : {}),
    evidenceIds: occurrence.evidenceIds,
    counterevidence: [],
    missingEvidence: ['Not yet validated by AI context analysis (L2) or controlled verification (L3).'],
    reasoningSummary: `Static rule match (${rules}). Classified as potential until validated.`,
    changeCauses: causes,
    assessedBy: 'host:scanner-l1',
    assessedAt: input.now,
  };
}

function groupSubject(group: CandidateGroup): CauseSubject {
  return {
    path: group.anchor.path,
    ruleIds: unique(group.candidates.map((c) => c.ruleId)),
    scanners: unique(group.candidates.map((c) => c.scanner)),
    vulnerabilityIds: unique(group.candidates.flatMap((c) => c.vulnerabilityIds ?? [])),
  };
}

function occurrenceSubject(occurrence: FindingOccurrence): CauseSubject {
  const vuln = occurrence.anchor.shape.startsWith('vuln:') ? [occurrence.anchor.shape.slice('vuln:'.length)] : [];
  return { path: occurrence.anchor.path, ruleIds: occurrence.ruleIds, scanners: [], vulnerabilityIds: vuln };
}

/** Deterministic scanner candidates come first; AI candidates are primary only when no scanner reported the issue. */
function sortedCandidates(group: CandidateGroup): FindingCandidate[] {
  return [...group.candidates].sort(
    (a, b) =>
      Number(a.scanner === 'ai') - Number(b.scanner === 'ai') ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.candidateId.localeCompare(b.candidateId),
  );
}

function sameKind(prior: PriorFinding, group: CandidateGroup): boolean {
  const c = group.candidates[0];
  return c !== undefined && prior.finding.category === c.category && prior.finding.ruleFamily === c.ruleFamily;
}

function isRelocation(prior: PriorFinding, group: CandidateGroup): boolean {
  const a = prior.latestOccurrence?.anchor;
  const b = group.anchor;
  return (
    !!a &&
    sameKind(prior, group) &&
    a.path !== b.path &&
    a.symbol !== '' &&
    a.symbol === b.symbol &&
    a.shape === b.shape &&
    a.instance === b.instance
  );
}

function isNear(prior: PriorFinding, group: CandidateGroup): boolean {
  const a = prior.latestOccurrence?.anchor;
  const b = group.anchor;
  // A different advisory on the same package is a different vulnerability, never an edited one.
  if (a?.shape.startsWith('vuln:') || b.shape.startsWith('vuln:')) return false;
  return !!a && sameKind(prior, group) && a.path === b.path && a.symbol === b.symbol && a.shape !== b.shape;
}

function findUnique(
  open: readonly PriorFinding[],
  matched: ReadonlySet<string>,
  predicate: (p: PriorFinding) => boolean,
): PriorFinding | undefined {
  const hits = open.filter((p) => !matched.has(p.finding.findingId) && predicate(p));
  return hits.length === 1 ? hits[0] : undefined;
}

function mergeLocations(candidates: readonly FindingCandidate[]): Location[] {
  const seen = new Set<string>();
  const result: Location[] = [];
  const all = candidates.flatMap((c) => c.locations);
  all.sort((a, b) => roleOrder(a.role) - roleOrder(b.role));
  for (const loc of all) {
    const key = `${loc.role}:${loc.path}:${loc.startLine}:${loc.endLine}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(loc);
  }
  return result;
}

function roleOrder(role: Location['role']): number {
  return ['primary', 'sink', 'source', 'guard', 'related'].indexOf(role);
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

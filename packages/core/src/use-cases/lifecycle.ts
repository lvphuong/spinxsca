import type { Disposition, ScanRun } from '@spinxsca/schemas';
import { SpinxscaError } from '../errors';
import { newId } from '../ids';
import type { BaselineRecord, Clock, ScanRepository } from '../ports';

export interface DisposeInput {
  findingId: string;
  kind: Disposition['kind'];
  reason: string;
  decidedBy: string;
  expiresAt?: string;
  duplicateOf?: string;
}

/** Records a human decision about a finding (ADR-005: separate from scanner/AI assessments). */
export async function disposeFinding(repo: ScanRepository, clock: Clock, input: DisposeInput): Promise<Disposition> {
  const finding = await repo.getFinding(input.findingId);
  if (!finding) throw new SpinxscaError(`finding ${input.findingId} not found`, 'NOT_FOUND');
  if (input.reason.trim().length < 3) throw new SpinxscaError('a reason is required', 'INVALID');
  if (input.kind === 'DUPLICATE_OF') {
    if (!input.duplicateOf || !(await repo.getFinding(input.duplicateOf))) {
      throw new SpinxscaError('DUPLICATE_OF needs an existing --duplicate-of finding', 'INVALID');
    }
  }
  if (input.expiresAt && new Date(input.expiresAt) <= clock.now())
    throw new SpinxscaError('expiry must be in the future', 'INVALID');
  const disposition: Disposition = {
    dispositionId: newId('disp'),
    findingId: finding.findingId,
    kind: input.kind,
    reason: input.reason.trim(),
    ...(input.duplicateOf ? { duplicateOf: input.duplicateOf } : {}),
    scope: { type: 'PROJECT', ref: finding.projectId },
    ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
    decidedBy: input.decidedBy,
    decidedAt: clock.now().toISOString(),
  };
  await repo.saveDisposition(disposition);
  return disposition;
}

/**
 * Promotes a completed scan to the baseline of a branch (ADR-015). The previous baseline is
 * deactivated in the same transaction; a scan with partial coverage cannot become a baseline.
 */
export async function setBaseline(
  repo: ScanRepository,
  clock: Clock,
  input: { branch: string; scanId: string; reason: string },
): Promise<BaselineRecord> {
  const scan: ScanRun | undefined = await repo.getScan(input.scanId);
  if (!scan) throw new SpinxscaError(`scan ${input.scanId} not found`, 'NOT_FOUND');
  if (scan.status !== 'COMPLETED') {
    throw new SpinxscaError(
      `scan ${scan.scanId} is ${scan.status}; only completed scans can become a baseline`,
      'INVALID',
    );
  }
  if (input.reason.trim().length < 3) throw new SpinxscaError('a reason is required', 'INVALID');
  const current = await repo.activeBaseline(scan.projectId, 'BRANCH', input.branch);
  const baseline: BaselineRecord = {
    baselineId: newId('base'),
    projectId: scan.projectId,
    scopeType: 'BRANCH',
    scopeRef: input.branch,
    scanId: scan.scanId,
    reason: input.reason.trim(),
    activatedAt: clock.now().toISOString(),
  };
  await repo.activateBaseline(baseline, current?.baselineId);
  return baseline;
}

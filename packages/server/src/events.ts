import type { Clock } from '@spinxsca/core';
import type { NotificationEvent, Notifier } from './notify';
import type { JobEntry, Registry } from './registry';
import type { ProjectStates } from './state';

/**
 * Side effects of finished jobs, run on the control plane whichever worker executed the job: new
 * findings and permanent failures become outgoing notifications.
 */
export class JobEvents {
  constructor(
    private readonly o: {
      registry: Registry;
      states: ProjectStates;
      notifier: Notifier;
      clock: Clock;
      publicUrl?: string;
    },
  ) {}

  async completed(job: JobEntry, result: Record<string, unknown>): Promise<void> {
    const project = job.projectId ? this.o.registry.project(job.projectId) : undefined;
    const ids = Array.isArray(result.newFindings) ? (result.newFindings as string[]) : [];
    if (!project || ids.length === 0 || typeof result.scanId !== 'string') return;
    const state = this.o.states.get(project.projectId);
    const assessments = new Map((await state.repo.listAssessments(result.scanId)).map((a) => [a.findingId, a]));
    const findings: NotificationEvent['findings'] = [];
    for (const id of ids) {
      const finding = await state.repo.getFinding(id);
      const a = assessments.get(id);
      findings.push({
        findingId: id,
        title: finding?.title ?? id,
        severity: a?.severity ?? 'UNKNOWN',
        category: finding?.category ?? 'OTHER',
        ...(a?.intel?.kev ? { kev: true } : {}),
        ...(a?.intel?.epss ? { epss: a.intel.epss.score } : {}),
        causes: a?.changeCauses ?? [],
      });
    }
    const branch = String(result.branch ?? job.payload.branch ?? '');
    await this.o.notifier.send({
      event: 'findings.new',
      project: { projectId: project.projectId, name: project.name },
      branch,
      scanId: result.scanId,
      jobId: job.jobId,
      trigger:
        (job.payload.trigger as NotificationEvent['trigger']) ?? (job.kind === 'REASSESS' ? 'reassessment' : 'api'),
      findings,
      ...(this.o.publicUrl
        ? { url: `${this.o.publicUrl}/ui/projects/${project.projectId}?branch=${encodeURIComponent(branch)}` }
        : {}),
    });
  }

  async failed(job: JobEntry, error: string): Promise<void> {
    const after = this.o.registry.job(job.jobId);
    const project = job.projectId ? this.o.registry.project(job.projectId) : undefined;
    if (!project || after?.status !== 'FAILED') return;
    await this.o.notifier.send({
      event: 'scan.failed',
      project: { projectId: project.projectId, name: project.name },
      branch: String(job.payload.branch ?? ''),
      jobId: job.jobId,
      trigger: (job.payload.trigger as NotificationEvent['trigger']) ?? 'api',
      findings: [],
      error,
    });
  }
}

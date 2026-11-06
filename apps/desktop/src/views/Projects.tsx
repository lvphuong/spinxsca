import { useCallback, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import type { ApprovalRecord, JobEntry, Project, ReviewCase } from '../api/types';
import { Icon } from '../components/icons';
import { CancelJobButton, type Pending, RunControls, useRunControl } from '../components/RunControls';
import { Banner, Card, EmptyState, LabelPill, PageHeader, Pill, Spinner, useToast } from '../components/ui';
import { ACTIVE_CASE_STATUSES, caseStatus, caseTitle, humanize, preparingJobs, relativeTime, resumeJobFor } from '../lib/format';
import { pickFolder } from '../lib/shell';

interface ProjectActivity {
  latest: ReviewCase | null;
  /** Active cases (running, waiting for a human, paused), newest first. */
  active: ReviewCase[];
  jobs: JobEntry[];
}

const location = (p: Project) => (p.source.kind === 'local' ? p.source.path : p.source.url);

export function Projects({
  api,
  projects,
  approvals,
  onChanged,
  onOpen,
}: {
  api: ApiClient;
  projects: Project[] | undefined;
  approvals: ApprovalRecord[];
  onChanged: () => void;
  onOpen: (p: Project) => void;
}) {
  const toast = useToast();
  const [error, setError] = useState<string | undefined>();
  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState('');
  const [activity, setActivity] = useState<Record<string, ProjectActivity>>({});

  // The most recent review of each project for the status column, plus every review still running,
  // waiting or paused so it can be controlled from here. Refreshed while the page is open.
  const ids = (projects ?? []).map((p) => p.projectId).join(',');
  const load = useCallback(async () => {
    if (!ids) return;
    const rows = await Promise.all(
      ids.split(',').map(async (id) => {
        const [cases, jobs] = await Promise.all([
          api.cases(id).catch(() => [] as ReviewCase[]),
          api.projectJobs(id).catch(() => [] as JobEntry[]),
        ]);
        const value: ProjectActivity = {
          latest: cases[0] ?? null,
          active: cases.filter((c) => ACTIVE_CASE_STATUSES.has(c.status)),
          jobs,
        };
        return [id, value] as const;
      }),
    );
    setActivity(Object.fromEntries(rows));
  }, [api, ids]);
  useEffect(() => {
    const tick = () => void load().catch(() => undefined);
    tick();
    const timer = setInterval(tick, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const add = async () => {
    setError(undefined);
    const path = await pickFolder();
    if (!path) return;
    const name = (path.split(/[\\/]/).filter(Boolean).pop() ?? 'project').replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 100);
    setAdding(true);
    try {
      await api.createProject({ name, path });
      toast(`Added ${name}`);
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setAdding(false);
    }
  };

  const waiting = (id: string) => approvals.filter((a) => (a.project?.projectId ?? a.projectId) === id).length;
  const q = query.trim().toLowerCase();
  const shown = (projects ?? []).filter((p) => !q || p.name.toLowerCase().includes(q) || location(p).toLowerCase().includes(q));
  const addButton = (
    <button type="button" className="btn btn-primary" disabled={adding} onClick={() => void add()}>
      {adding ? <Spinner size={14} /> : <Icon name="folderPlus" size={16} />}
      Add project
    </button>
  );

  return (
    <div className="page">
      <PageHeader title="Projects" subtitle="Code on this computer that Spinx reviews. Open a project to start a review or read its results." actions={projects?.length ? addButton : undefined} />
      {error && (
        <Banner tone="danger" title="The project was not added" onDismiss={() => setError(undefined)}>
          {error}
        </Banner>
      )}
      {projects === undefined ? (
        <div className="loading">
          <Spinner size={18} label="Loading projects" />
        </div>
      ) : projects.length === 0 ? (
        <EmptyState icon="folder" title="Add your first project" action={addButton}>
          Pick a folder on this computer. Spinx scans it as it is on disk, with scanners running in containers without
          network access.
        </EmptyState>
      ) : (
        <>
          {projects.length > 5 && (
            <div className="toolbar">
              <label className="search">
                <Icon name="search" size={15} />
                <input placeholder="Filter projects" aria-label="Filter projects" value={query} onChange={(e) => setQuery(e.target.value)} />
              </label>
            </div>
          )}
          <ActiveReviews
            api={api}
            projects={projects}
            activity={activity}
            onOpen={onOpen}
            onChanged={() => {
              onChanged();
              void load().catch(() => undefined);
            }}
          />
          <div className="table-list" role="list">
            <div className="table-head project-grid" aria-hidden="true">
              <span>Project</span>
              <span>Last review</span>
              <span>AI level</span>
              <span>Inbox</span>
              <span />
            </div>
            {shown.map((p) => {
              const last = activity[p.projectId]?.latest;
              const count = waiting(p.projectId);
              return (
                <div role="listitem" key={p.projectId}>
                  <button type="button" className="table-row project-grid" onClick={() => onOpen(p)}>
                    <span className="project-cell">
                      <span className="project-icon">
                        <Icon name={p.source.kind === 'local' ? 'folder' : 'branch'} size={16} />
                      </span>
                      <span className="project-text">
                        <span className="project-name">{p.name}</span>
                        <span className="project-path mono" title={location(p)}>
                          {location(p)}
                        </span>
                      </span>
                    </span>
                    <span className="cell-status">
                      {last === undefined ? (
                        <span className="faint">—</span>
                      ) : last === null ? (
                        <span className="faint">No reviews yet</span>
                      ) : (
                        <>
                          <LabelPill value={caseStatus(last.status)} dot />
                          <span className="faint">{relativeTime(last.createdAt)}</span>
                        </>
                      )}
                    </span>
                    <span>{p.ai && p.ai.level !== 'off' ? <Pill tone="info">{humanize(p.ai.level)}</Pill> : <span className="faint">Off</span>}</span>
                    <span>{count > 0 ? <Pill tone="warn">{count} waiting</Pill> : <span className="faint">—</span>}</span>
                    <Icon name="chevronRight" size={16} className="row-chevron" />
                  </button>
                </div>
              );
            })}
            {shown.length === 0 && <p className="table-empty">No project matches “{query}”.</p>}
          </div>
        </>
      )}
    </div>
  );
}

/** Reviews still running, waiting for a decision, paused or scanning, with their controls. */
function ActiveReviews({
  api,
  projects,
  activity,
  onOpen,
  onChanged,
}: {
  api: ApiClient;
  projects: Project[];
  activity: Record<string, ProjectActivity>;
  onOpen: (p: Project) => void;
  onChanged: () => void;
}) {
  const rows = projects.flatMap((p) => {
    const a = activity[p.projectId];
    if (!a) return [];
    const scanning = preparingJobs(a.jobs, a.latest ? [a.latest] : []).map((job) => ({ kind: 'job' as const, project: p, job }));
    const cases = a.active.map((c) => ({ kind: 'case' as const, project: p, case: c, jobs: a.jobs }));
    return [...scanning, ...cases];
  });
  if (rows.length === 0) return null;
  return (
    <Card title="Active reviews" icon="activity" className="active-reviews">
      <ul className="active-list">
        {rows.map((r) =>
          r.kind === 'job' ? (
            <li key={r.job.jobId} className="active-row">
              <button type="button" className="active-main" onClick={() => onOpen(r.project)}>
                <span className="project-name">{r.project.name}</span>
                <span className="active-title">
                  {typeof r.job.payload.goal === 'string' && r.job.payload.goal ? r.job.payload.goal : 'Full security review'}
                </span>
              </button>
              <Pill tone="info">
                <Spinner size={10} />
                {r.job.status === 'QUEUED' ? 'Queued' : 'Scanning'}
              </Pill>
              <span className="faint">{relativeTime(r.job.createdAt)}</span>
              <CancelJobButton api={api} projectId={r.project.projectId} jobId={r.job.jobId} onDone={onChanged} />
            </li>
          ) : (
            <ActiveCaseRow key={r.case.caseId} api={api} project={r.project} rc={r.case} jobs={r.jobs} onOpen={onOpen} onChanged={onChanged} />
          ),
        )}
      </ul>
    </Card>
  );
}

function ActiveCaseRow({
  api,
  project,
  rc,
  jobs,
  onOpen,
  onChanged,
}: {
  api: ApiClient;
  project: Project;
  rc: ReviewCase;
  jobs: JobEntry[];
  onOpen: (p: Project) => void;
  onChanged: () => void;
}) {
  const control = useRunControl(api, project.projectId, onChanged);
  const { settle } = control;
  useEffect(() => settle(rc.caseId, rc.status), [rc.caseId, rc.status, settle]);
  return (
    <li className="active-row">
      <button type="button" className="active-main" onClick={() => onOpen(project)}>
        <span className="project-name">{project.name}</span>
        <span className="active-title">{caseTitle(rc)}</span>
      </button>
      <LabelPill value={caseStatus(rc.status)} dot />
      <span className="faint">
        round {rc.round} · {relativeTime(rc.createdAt)}
      </span>
      <RunControls
        compact
        status={rc.status}
        resuming={resumeJobFor(jobs, rc.caseId) !== undefined}
        pending={control.pending[rc.caseId] as Pending}
        onAction={(action) => void control.act(rc.caseId, action)}
      />
    </li>
  );
}


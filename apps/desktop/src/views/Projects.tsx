import { useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import type { ApprovalRecord, Project, ReviewCase } from '../api/types';
import { Icon } from '../components/icons';
import { Banner, EmptyState, LabelPill, PageHeader, Pill, Spinner, useToast } from '../components/ui';
import { caseStatus, humanize, relativeTime } from '../lib/format';
import { pickFolder } from '../lib/shell';

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
  const [latest, setLatest] = useState<Record<string, ReviewCase | null>>({});

  // The most recent review of each project, for the status column.
  const ids = (projects ?? []).map((p) => p.projectId).join(',');
  useEffect(() => {
    if (!ids) return;
    let cancelled = false;
    void Promise.all(
      ids.split(',').map(async (id) => [id, (await api.cases(id).catch(() => []))[0] ?? null] as const),
    ).then((rows) => {
      if (!cancelled) setLatest(Object.fromEntries(rows));
    });
    return () => {
      cancelled = true;
    };
  }, [api, ids]);

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
          <div className="table-list" role="list">
            <div className="table-head project-grid" aria-hidden="true">
              <span>Project</span>
              <span>Last review</span>
              <span>AI level</span>
              <span>Inbox</span>
              <span />
            </div>
            {shown.map((p) => {
              const last = latest[p.projectId];
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

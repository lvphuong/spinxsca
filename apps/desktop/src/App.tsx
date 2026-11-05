import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiClient, type Connection } from './api/client';
import type { ApprovalRecord, Project } from './api/types';
import { Icon, type IconName } from './components/icons';
import { SidecarLogTail } from './components/SidecarLog';
import { Spinner, ToastProvider } from './components/ui';
import {
  type DockerStatus,
  dockerStatus,
  inDesktopShell,
  notify,
  openSidecarLog,
  retrySidecar,
  SIDECAR_MAX_RESTARTS,
  type SidecarStatus,
  sidecarStatus,
} from './lib/shell';
import { Inbox } from './views/Inbox';
import { Onboarding } from './views/Onboarding';
import { Projects } from './views/Projects';
import { Review } from './views/Review';
import { Settings } from './views/Settings';

/** Where the window is. A project page is a drill-down of Projects, not a destination of its own. */
export type Route =
  | { view: 'inbox' }
  | { view: 'projects' }
  | { view: 'project'; projectId: string; caseId?: string }
  | { view: 'settings' };

export type ServiceState = 'checking' | 'online' | 'offline';

export interface Health {
  service: ServiceState;
  docker: DockerStatus | undefined;
  recheckDocker: () => void;
}

export function App({ connection }: { connection: Connection }) {
  const api = useMemo(() => new ApiClient(connection), [connection]);
  const [onboarded, setOnboarded] = useState(false);
  const [route, setRoute] = useState<Route>({ view: 'projects' });
  const [projects, setProjects] = useState<Project[] | undefined>();
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [service, setService] = useState<ServiceState>('checking');
  const [docker, setDocker] = useState<DockerStatus | undefined>();
  // Why the service is not answering, as the shell saw it (desktop only).
  const [sidecar, setSidecar] = useState<SidecarStatus | undefined>();
  const known = useRef(new Set<string>());
  const mainRef = useRef<HTMLElement>(null);

  const refresh = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([api.projects(), api.inbox()]);
      setProjects(p);
      setApprovals(a);
      setService('online');
      setSidecar(undefined);
      const fresh = a.filter((x) => !known.current.has(x.approvalId));
      for (const x of a) known.current.add(x.approvalId);
      if (fresh.length && known.current.size > fresh.length) void notify('Spinx: approval needed', fresh[0]?.title ?? '');
    } catch {
      setService('offline');
      setSidecar(await sidecarStatus().catch(() => undefined));
    }
  }, [api]);

  const recheckDocker = useCallback(() => {
    void dockerStatus().then(setDocker);
  }, []);

  useEffect(() => {
    if (!onboarded) return;
    void refresh();
    recheckDocker();
    const timer = setInterval(() => void refresh(), 5000);
    const dockerTimer = setInterval(recheckDocker, 60_000);
    return () => {
      clearInterval(timer);
      clearInterval(dockerTimer);
    };
  }, [onboarded, refresh, recheckDocker]);

  // Each page starts at the top; the content pane keeps its own scroll otherwise.
  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [route]);

  if (!onboarded) return <Onboarding api={api} onDone={() => setOnboarded(true)} />;

  const health: Health = { service, docker, recheckDocker };
  const project = route.view === 'project' ? projects?.find((p) => p.projectId === route.projectId) : undefined;
  const section = route.view === 'project' ? 'projects' : route.view;
  const nav: Array<{ key: 'inbox' | 'projects'; label: string; icon: IconName; count?: number }> = [
    { key: 'inbox', label: 'Inbox', icon: 'inbox', count: approvals.length },
    { key: 'projects', label: 'Projects', icon: 'folder' },
  ];

  return (
    <ToastProvider>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">
            <span className="brand-mark">
              <Icon name="shieldCheck" size={18} />
            </span>
            <span className="brand-text">
              <strong>Spinx</strong>
              <span>SecureCode AI</span>
            </span>
          </div>
          <nav aria-label="Main" className="nav">
            {nav.map((n) => (
              <button
                key={n.key}
                type="button"
                className={section === n.key ? 'nav-item active' : 'nav-item'}
                aria-current={section === n.key ? 'page' : undefined}
                aria-label={n.count ? `${n.label}, ${n.count} waiting` : n.label}
                title={n.label}
                onClick={() => setRoute({ view: n.key })}
              >
                <Icon name={n.icon} size={17} />
                <span className="nav-label">{n.label}</span>
                {n.count ? <span className="nav-count">{n.count}</span> : null}
              </button>
            ))}
          </nav>
          <div className="sidebar-foot">
            <button
              type="button"
              className={section === 'settings' ? 'nav-item active' : 'nav-item'}
              aria-current={section === 'settings' ? 'page' : undefined}
              title="Settings"
              onClick={() => setRoute({ view: 'settings' })}
            >
              <Icon name="sliders" size={17} />
              <span className="nav-label">Settings</span>
            </button>
            <SystemStatus health={health} onOpen={() => setRoute({ view: 'settings' })} />
          </div>
        </aside>
        <main className="main" ref={mainRef}>
          {service === 'offline' && (
            <OfflineBar
              sidecar={sidecar}
              onRetried={() => {
                setSidecar((s) => (s ? { ...s, gaveUp: false } : s));
                void refresh();
              }}
            />
          )}
          {route.view === 'inbox' && (
            <Inbox
              api={api}
              approvals={approvals}
              onChanged={() => void refresh()}
              onOpenCase={(projectId, caseId) => setRoute({ view: 'project', projectId, caseId })}
            />
          )}
          {route.view === 'projects' && (
            <Projects
              api={api}
              projects={projects}
              approvals={approvals}
              onChanged={() => void refresh()}
              onOpen={(p) => setRoute({ view: 'project', projectId: p.projectId })}
            />
          )}
          {route.view === 'project' && project && (
            <Review
              key={project.projectId}
              api={api}
              project={project}
              {...(route.caseId ? { initialCaseId: route.caseId } : {})}
              onBack={() => setRoute({ view: 'projects' })}
              onChanged={() => void refresh()}
            />
          )}
          {route.view === 'settings' && (
            <Settings api={api} projects={projects ?? []} health={health} baseUrl={connection.baseUrl} onChanged={() => void refresh()} />
          )}
        </main>
      </div>
    </ToastProvider>
  );
}

/** The service is not answering: why, as far as the shell knows, and what can be done about it. */
function OfflineBar({ sidecar, onRetried }: { sidecar: SidecarStatus | undefined; onRetried: () => void }) {
  const [retrying, setRetrying] = useState(false);
  const error = sidecar?.lastError;
  const retry = async () => {
    setRetrying(true);
    try {
      await retrySidecar();
      onRetried();
    } finally {
      setRetrying(false);
    }
  };
  return (
    <div className="offline-bar" role="alert">
      <Icon name="alertCircle" size={15} />
      <span className="offline-text">
        {!error
          ? 'The local service is not answering. It restarts on its own; reviews resume when it is back.'
          : sidecar.gaveUp
            ? `The local service could not be restarted: ${error}. Gave up after ${SIDECAR_MAX_RESTARTS} restarts.`
            : `The local service failed to start: ${error}. Restarting (${sidecar.restarts} of ${SIDECAR_MAX_RESTARTS})…`}
      </span>
      {error && (
        <span className="offline-actions">
          {sidecar.gaveUp && (
            <button type="button" className="btn btn-sm" disabled={retrying} onClick={() => void retry()}>
              {retrying ? <Spinner size={13} /> : <Icon name="refresh" size={14} />}
              Try again
            </button>
          )}
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => void openSidecarLog()}>
            Show log file
          </button>
        </span>
      )}
      <SidecarLogTail status={sidecar} />
    </div>
  );
}

/** Always-visible health of what reviews depend on; a click opens the details in Settings. */
function SystemStatus({ health, onOpen }: { health: Health; onOpen: () => void }) {
  const native = inDesktopShell();
  const service = { checking: ['neutral', 'Connecting…'], online: ['ok', 'Service running'], offline: ['danger', 'Service offline'] }[health.service];
  const docker = !native
    ? ['neutral', 'Docker: desktop only']
    : !health.docker
      ? ['neutral', 'Checking Docker…']
      : health.docker.available
        ? ['ok', 'Docker ready']
        : ['danger', 'Docker unavailable'];
  return (
    <button type="button" className="system-status" onClick={onOpen} title="Environment details">
      <span className={`status-line tone-${service[0]}`}>
        <span className="status-dot" aria-hidden="true" />
        {service[1]}
      </span>
      <span className={`status-line tone-${docker[0]}`}>
        <span className="status-dot" aria-hidden="true" />
        {docker[1]}
      </span>
    </button>
  );
}

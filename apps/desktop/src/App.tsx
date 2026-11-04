import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiClient, type Connection } from './api/client';
import type { ApprovalRecord, Project } from './api/types';
import { notify } from './lib/shell';
import { Inbox } from './views/Inbox';
import { Onboarding } from './views/Onboarding';
import { Projects } from './views/Projects';
import { Review } from './views/Review';
import { Settings } from './views/Settings';

type Tab = 'inbox' | 'projects' | 'review' | 'settings';

export function App({ connection }: { connection: Connection }) {
  const api = useMemo(() => new ApiClient(connection), [connection]);
  const [onboarded, setOnboarded] = useState(false);
  const [tab, setTab] = useState<Tab>('projects');
  const [projects, setProjects] = useState<Project[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [current, setCurrent] = useState<Project | undefined>();
  const known = useRef(new Set<string>());

  const refresh = useCallback(async () => {
    const [p, a] = await Promise.all([api.projects(), api.inbox()]);
    setProjects(p);
    setApprovals(a);
    const fresh = a.filter((x) => !known.current.has(x.approvalId));
    for (const x of a) known.current.add(x.approvalId);
    if (fresh.length && known.current.size > fresh.length) void notify('Spinx: approval needed', fresh[0]?.title ?? '');
  }, [api]);

  useEffect(() => {
    if (!onboarded) return;
    void refresh();
    const timer = setInterval(() => void refresh().catch(() => undefined), 5000);
    return () => clearInterval(timer);
  }, [onboarded, refresh]);

  if (!onboarded) return <Onboarding api={api} onDone={() => setOnboarded(true)} />;
  return (
    <div className="shell">
      <nav aria-label="Main">
        <div className="brand">Spinx SecureCode AI</div>
        <button type="button" className={tab === 'inbox' ? 'active' : ''} onClick={() => setTab('inbox')}>
          Inbox {approvals.length > 0 && <span className="badge">{approvals.length}</span>}
        </button>
        <button type="button" className={tab === 'projects' ? 'active' : ''} onClick={() => setTab('projects')}>
          Projects
        </button>
        <button type="button" disabled={!current} className={tab === 'review' ? 'active' : ''} onClick={() => setTab('review')}>
          Review
        </button>
        <button type="button" className={tab === 'settings' ? 'active' : ''} onClick={() => setTab('settings')}>
          Settings
        </button>
      </nav>
      <main>
        {tab === 'inbox' && <Inbox api={api} approvals={approvals} onChanged={() => void refresh()} />}
        {tab === 'projects' && (
          <Projects
            api={api}
            projects={projects}
            onChanged={() => void refresh()}
            onOpen={(p) => {
              setCurrent(p);
              setTab('review');
            }}
          />
        )}
        {tab === 'review' && current && <Review api={api} project={current} />}
        {tab === 'settings' && <Settings api={api} projects={projects} onChanged={() => void refresh()} />}
      </main>
    </div>
  );
}

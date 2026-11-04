import { useCallback, useEffect, useRef, useState } from 'react';
import type { ApiClient } from '../api/client';
import type { AuditEvent, CaseView, Project, ReviewCase } from '../api/types';
import { ApprovalCard } from '../components/ApprovalCard';
import { Markdown } from '../components/Markdown';

const STAGE_LABEL: Record<string, string> = {
  'policy.decided': 'policy',
  'approval.requested': 'asks a human',
  'approval.resolved': 'decided',
  'tool.finished': 'ran',
  'tool.failed': 'failed',
  'item.transition': 'work item',
  'verdict.applied': 'verdict',
  'validation.oracle': 'proof of concept',
  'case.started': 'started',
  'case.stopped': 'stopped',
};

/** Start a review and follow a case: timeline, objectives and coverage, findings, waiting approvals. */
export function Review({ api, project }: { api: ApiClient; project: Project }) {
  const [cases, setCases] = useState<ReviewCase[]>([]);
  const [selected, setSelected] = useState<string | undefined>();
  const [view, setView] = useState<CaseView | undefined>();
  const [timeline, setTimeline] = useState<AuditEvent[]>([]);
  const [goal, setGoal] = useState(project.ai?.goal ?? '');
  const [branch, setBranch] = useState(project.defaultBranch);
  const [error, setError] = useState<string | undefined>();
  const stream = useRef<AbortController | undefined>(undefined);

  const refresh = useCallback(async () => {
    const list = await api.cases(project.projectId);
    setCases(list);
    if (selected) setView(await api.caseView(project.projectId, selected));
  }, [api, project.projectId, selected]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!selected) return;
    stream.current?.abort();
    const controller = new AbortController();
    stream.current = controller;
    setTimeline([]);
    void api
      .events(
        project.projectId,
        selected,
        (e) => {
          if (e.event === 'audit') setTimeline((t) => [...t, e.data as AuditEvent].slice(-300));
          if (e.event === 'audit' || e.event === 'case') void refresh();
        },
        { signal: controller.signal },
      )
      .catch(() => undefined);
    return () => controller.abort();
  }, [api, project.projectId, selected, refresh]);

  const start = async () => {
    setError(undefined);
    try {
      await api.startReview(project.projectId, { branch, ...(goal.trim() ? { goal: goal.trim() } : {}) });
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <section>
      <h1>{project.name}</h1>
      <div className="card">
        <h2>New review</h2>
        <label>
          Branch <input value={branch} onChange={(e) => setBranch(e.target.value)} />
        </label>
        <label>
          Goal <textarea rows={3} value={goal} onChange={(e) => setGoal(e.target.value)} placeholder="What should this review achieve?" />
        </label>
        <button type="button" className="primary" onClick={() => void start()}>
          Start review
        </button>
        {error && <p className="error" role="alert">{error}</p>}
      </div>
      <div className="split">
        <ul className="list cases">
          {cases.map((c) => (
            <li key={c.caseId} className={c.caseId === selected ? 'active' : ''}>
              <button type="button" className="link" onClick={() => setSelected(c.caseId)}>
                {c.caseId}
              </button>{' '}
              <span className={`chip status-${c.status}`}>{c.status.toLowerCase()}</span>
            </li>
          ))}
        </ul>
        {view && (
          <div className="case">
            <p className="muted">
              {view.case.status} {view.case.stopReason ? `— ${view.case.stopReason}` : ''} · round {view.case.round} · ${view.ledger.costUsd.toFixed(2)} ·{' '}
              {view.ledger.sandboxRuns} sandbox runs
            </p>
            {view.approvals.filter((a) => a.status === 'PENDING').map((a) => (
              <ApprovalCard
                key={a.approvalId}
                approval={a}
                onDecide={(d) => void api.decide(project.projectId, a.approvalId, d).then(refresh)}
              />
            ))}
            <h2>Objectives</h2>
            <ul className="objectives">
              {view.objectives.map((o) => (
                <li key={o.objectiveId}>
                  <span className={`chip status-${o.status}`}>{o.status.replace('_', ' ').toLowerCase()}</span> {o.title}
                  {o.reason && <span className="muted"> — {o.reason}</span>}
                </li>
              ))}
            </ul>
            <h2>Coverage</h2>
            <ul>
              {view.checks.map((c) => (
                <li key={c.checkId}>
                  <span className={`chip status-${c.outcome}`}>{c.outcome}</span> {c.checkId}
                  {c.reason && <span className="muted"> — {c.reason}</span>}
                </li>
              ))}
            </ul>
            <h2>Findings</h2>
            <table className="findings">
              <thead>
                <tr>
                  <th>Handle</th>
                  <th>Finding</th>
                  <th>Verdict</th>
                  <th>Severity</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {view.handles.map((h) => {
                  const v = view.verdicts.find((x) => x.handle === h.handle);
                  return (
                    <tr key={h.handle}>
                      <td>{h.handle}</td>
                      <td>
                        {h.title}
                        <div className="muted">
                          {h.path}:{h.startLine}
                        </div>
                      </td>
                      <td>
                        {v?.verdict ?? 'unreviewed'}
                        {v?.applicability && (
                          <div className="muted">
                            {v.applicability.status}
                            {v.applicability.reachability ? ` · ${v.applicability.reachability}` : ''}
                          </div>
                        )}
                        {v?.poc && <div className="muted">PoC {v.poc.outcome}</div>}
                      </td>
                      <td>{v?.severity ?? h.severity}</td>
                      <td className="rationale">{v ? <Markdown text={v.rationale} /> : null}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <h2>Timeline</h2>
            <ol className="timeline">
              {timeline.map((e) => (
                <li key={e.seq}>
                  <span className="muted">{e.at.slice(11, 19)}</span> <strong>{STAGE_LABEL[e.stage] ?? e.stage}</strong> {e.actor}{' '}
                  {typeof e.data.tool === 'string' ? <code>{e.data.tool}</code> : null}{' '}
                  {typeof e.data.outcome === 'string' ? <span className="muted">{e.data.outcome}</span> : null}
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </section>
  );
}

import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import type { ApiClient } from '../api/client';
import type { AuditEvent, CaseView, JobEntry, Project, ReviewCase } from '../api/types';
import { ApprovalCard, type Decision } from '../components/ApprovalCard';
import { Icon, type IconName } from '../components/icons';
import { Markdown } from '../components/Markdown';
import { Banner, Card, EmptyState, LabelPill, PageHeader, Pill, SeverityBadge, Spinner, Stat, useToast } from '../components/ui';
import {
  applicability,
  caseStatus,
  caseTitle,
  checkOutcome,
  clockTime,
  failedReviewJob,
  type FindingFilter,
  type FindingRow,
  findingRows,
  humanize,
  matchesFilter,
  objectiveStatus,
  pocOutcome,
  preparingJobs,
  reachability,
  relativeTime,
  type Tone,
  usd,
  verdictLabel,
  verificationLevel,
} from '../lib/format';

const STAGE: Record<string, { label: string; tone: Tone }> = {
  'policy.decided': { label: 'Policy decided', tone: 'neutral' },
  'approval.requested': { label: 'Asked a human', tone: 'warn' },
  'approval.resolved': { label: 'Human decided', tone: 'ok' },
  'tool.finished': { label: 'Ran', tone: 'neutral' },
  'tool.failed': { label: 'Failed', tone: 'danger' },
  'item.transition': { label: 'Work item', tone: 'neutral' },
  'verdict.applied': { label: 'Verdict', tone: 'info' },
  'validation.oracle': { label: 'Proof of concept', tone: 'danger' },
  'case.started': { label: 'Started', tone: 'info' },
  'case.stopped': { label: 'Stopped', tone: 'neutral' },
};

const STATUS_BANNER: Record<string, { tone: Tone; title: string; icon: IconName }> = {
  PARKED: { tone: 'warn', title: 'Waiting for your decision', icon: 'clock' },
  CONVERGED: { tone: 'ok', title: 'Review complete', icon: 'checkCircle' },
  STAGNATED: { tone: 'warn', title: 'Stopped without progress', icon: 'alert' },
  BUDGET_EXHAUSTED: { tone: 'warn', title: 'Stopped at the budget limit', icon: 'alert' },
  CANCELLED: { tone: 'neutral', title: 'Cancelled', icon: 'minusCircle' },
  FAILED: { tone: 'danger', title: 'Review failed', icon: 'xCircle' },
};

type Tab = 'findings' | 'objectives' | 'activity';

/** A project: start a review and follow its cases — status, decisions, findings, objectives, activity. */
export function Review({
  api,
  project,
  initialCaseId,
  onBack,
  onChanged,
}: {
  api: ApiClient;
  project: Project;
  initialCaseId?: string;
  onBack: () => void;
  onChanged: () => void;
}) {
  const pid = project.projectId;
  const toast = useToast();
  const [cases, setCases] = useState<ReviewCase[] | undefined>();
  const [jobs, setJobs] = useState<JobEntry[]>([]);
  const [selected, setSelected] = useState<string | undefined>(initialCaseId);
  const [view, setView] = useState<CaseView | undefined>();
  const [timeline, setTimeline] = useState<AuditEvent[]>([]);
  const [live, setLive] = useState(false);
  const [composer, setComposer] = useState(false);
  const [goal, setGoal] = useState(project.ai?.goal ?? '');
  const [branch, setBranch] = useState(project.defaultBranch);
  const [starting, setStarting] = useState(false);
  const [awaitingSince, setAwaitingSince] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [dismissedJob, setDismissedJob] = useState<string | undefined>();
  const [busy, setBusy] = useState<string | undefined>();
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  const loadView = useCallback(
    async (caseId: string) => {
      const v = await api.caseView(pid, caseId);
      if (selectedRef.current === caseId) setView(v);
    },
    [api, pid],
  );

  const refresh = useCallback(async () => {
    const [list, jobList] = await Promise.all([api.cases(pid), api.projectJobs(pid).catch(() => [] as JobEntry[])]);
    setCases(list);
    setJobs(jobList);
    const first = list[0];
    if (!selectedRef.current && first) setSelected(first.caseId);
    else if (selectedRef.current) await loadView(selectedRef.current);
  }, [api, pid, loadView]);

  // Bursts of stream events collapse into one refresh.
  const pending = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const scheduleRefresh = useCallback(() => {
    if (pending.current) return;
    pending.current = setTimeout(() => {
      pending.current = undefined;
      void refresh().catch(() => undefined);
    }, 300);
  }, [refresh]);

  useEffect(() => {
    void refresh().catch((err) => setError((err as Error).message));
    const timer = setInterval(() => void refresh().catch(() => undefined), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    setView(undefined);
    if (selected) void loadView(selected).catch(() => undefined);
  }, [selected, loadView]);

  // A review started here opens as soon as its case exists.
  useEffect(() => {
    if (!awaitingSince || !cases) return;
    const fresh = cases.find((c) => c.createdAt >= awaitingSince);
    if (fresh) {
      setSelected(fresh.caseId);
      setAwaitingSince(undefined);
    }
  }, [cases, awaitingSince]);

  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    setTimeline([]);
    setLive(true);
    void api
      .events(
        pid,
        selected,
        (e) => {
          if (e.event === 'audit') setTimeline((t) => [...t, e.data as AuditEvent].slice(-500));
          if (e.event === 'audit' || e.event === 'case') scheduleRefresh();
        },
        { signal: controller.signal },
      )
      .catch(() => undefined)
      .finally(() => {
        if (!controller.signal.aborted) setLive(false);
      });
    return () => controller.abort();
  }, [api, pid, selected, scheduleRefresh]);

  useEffect(() => () => clearTimeout(pending.current), []);

  const start = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    setStarting(true);
    try {
      const since = new Date(Date.now() - 2000).toISOString();
      await api.startReview(pid, { branch: branch.trim() || project.defaultBranch, ...(goal.trim() ? { goal: goal.trim() } : {}) });
      setAwaitingSince(since);
      setComposer(false);
      toast('Review queued. Spinx scans the code first, then the review starts.', 'info');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStarting(false);
    }
  };

  const decide = async (approvalId: string, d: Decision) => {
    setBusy(approvalId);
    try {
      await api.decide(pid, approvalId, d);
      toast(d.decision === 'deny' ? 'Denied. The review continues without it.' : 'Approved. The review resumes shortly.');
    } catch (err) {
      toast((err as Error).message, 'danger');
    } finally {
      setBusy(undefined);
      onChanged();
      void refresh().catch(() => undefined);
    }
  };

  const list = cases ?? [];
  const preparing = preparingJobs(jobs, list);
  const failed = failedReviewJob(jobs, list);
  const showComposer = composer || (cases !== undefined && list.length === 0 && preparing.length === 0);
  const sourceLabel = project.source.kind === 'local' ? project.source.path : project.source.url;

  return (
    <div className="page page-wide">
      <PageHeader
        back={{ label: 'Projects', onClick: onBack }}
        title={project.name}
        subtitle={
          <span className="meta-row">
            <span className="meta-item mono" title={sourceLabel}>
              <Icon name={project.source.kind === 'local' ? 'folder' : 'branch'} size={13} />
              {sourceLabel}
            </span>
            <span className="meta-item">
              <Icon name="branch" size={13} />
              {project.defaultBranch}
            </span>
            <span className="meta-item">
              <Icon name="sparkles" size={13} />
              AI {project.ai?.level ?? 'off'}
            </span>
          </span>
        }
        actions={
          !showComposer && (
            <button type="button" className="btn btn-primary" onClick={() => setComposer(true)}>
              <Icon name="play" size={14} />
              New review
            </button>
          )
        }
      />

      {failed && failed.jobId !== dismissedJob && (
        <Banner tone="danger" title="The last review could not start" onDismiss={() => setDismissedJob(failed.jobId)}>
          {failed.error ?? 'The job failed without a message.'}
        </Banner>
      )}

      {showComposer && (
        <form className="card composer" onSubmit={(e) => void start(e)}>
          <div className="composer-head">
            <h2>Start a review</h2>
            <p className="muted">
              Spinx scans the code, then an AI reviewer triages each finding, gathers evidence and asks you before anything
              runs your code or changes the repository.
            </p>
          </div>
          <div className="form-grid">
            <label className="field">
              <span className="field-label">Goal</span>
              <textarea
                rows={3}
                value={goal}
                onChange={(e) => setGoal(e.target.value)}
                placeholder="e.g. Check authorization on the admin API and confirm the injection findings. Leave empty for a full review."
              />
            </label>
            <label className="field field-narrow">
              <span className="field-label">Branch</span>
              <input value={branch} onChange={(e) => setBranch(e.target.value)} spellCheck={false} />
              <span className="field-hint">{project.source.kind === 'local' ? 'Local folders are reviewed as they are on disk.' : 'Reviewed at its latest commit.'}</span>
            </label>
          </div>
          {error && (
            <p className="field-error" role="alert">
              {error}
            </p>
          )}
          <div className="form-actions">
            {list.length > 0 && (
              <button type="button" className="btn btn-ghost" onClick={() => setComposer(false)}>
                Cancel
              </button>
            )}
            <button type="submit" className="btn btn-primary" disabled={starting}>
              {starting ? <Spinner size={14} /> : <Icon name="play" size={14} />}
              Start review
            </button>
          </div>
        </form>
      )}

      {cases === undefined ? (
        <div className="loading">
          <Spinner size={18} label="Loading reviews" />
        </div>
      ) : list.length === 0 && preparing.length === 0 ? null : (
        <div className="review-layout">
          <aside className="case-list" aria-label="Reviews">
            <div className="case-list-head">
              <h2>Reviews</h2>
              <span className="count">{list.length}</span>
            </div>
            <ul>
              {preparing.map((j) => (
                <li key={j.jobId}>
                  <div className="case-item preparing">
                    <div className="case-item-top">
                      <Pill tone="info">
                        <Spinner size={10} />
                        {j.status === 'QUEUED' ? (j.error ? 'Retrying' : 'Queued') : 'Scanning'}
                      </Pill>
                      <span className="faint">{relativeTime(j.createdAt)}</span>
                    </div>
                    <div className="case-item-title">{typeof j.payload.goal === 'string' && j.payload.goal ? j.payload.goal : 'Full security review'}</div>
                    <div className="case-item-meta">{j.error ? `Last attempt failed: ${j.error}` : 'The review starts when the scan finishes.'}</div>
                  </div>
                </li>
              ))}
              {list.map((c) => (
                <li key={c.caseId}>
                  <button
                    type="button"
                    className={c.caseId === selected ? 'case-item active' : 'case-item'}
                    aria-current={c.caseId === selected ? 'true' : undefined}
                    onClick={() => setSelected(c.caseId)}
                  >
                    <div className="case-item-top">
                      <LabelPill value={caseStatus(c.status)} dot />
                      <span className="faint" title={c.createdAt}>
                        {relativeTime(c.createdAt)}
                      </span>
                    </div>
                    <div className="case-item-title">{caseTitle(c)}</div>
                    <div className="case-item-meta mono">
                      {c.caseId} · round {c.round}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </aside>
          <section className="case-detail" aria-label="Review details">
            {view ? (
              <CaseDetail view={view} timeline={timeline} live={live} busy={busy} onDecide={(id, d) => void decide(id, d)} />
            ) : selected ? (
              <div className="loading">
                <Spinner size={18} label="Loading review" />
              </div>
            ) : (
              <EmptyState icon="activity" title="Preparing the review">
                Spinx is scanning {String(preparing[0]?.payload.branch ?? project.defaultBranch)} with the configured scanners.
                The review and its findings appear here when the scan finishes.
              </EmptyState>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function CaseDetail({
  view,
  timeline,
  live,
  busy,
  onDecide,
}: {
  view: CaseView;
  timeline: AuditEvent[];
  live: boolean;
  busy: string | undefined;
  onDecide: (approvalId: string, d: Decision) => void;
}) {
  const [tab, setTab] = useState<Tab>('findings');
  const [filter, setFilter] = useState<FindingFilter>('all');
  const [open, setOpen] = useState<Set<string>>(new Set());
  const c = view.case;

  const rows = findingRows(view.handles, view.verdicts);
  const counts = {
    all: rows.length,
    confirmed: rows.filter((r) => matchesFilter(r, 'confirmed')).length,
    open: rows.filter((r) => matchesFilter(r, 'open')).length,
    dismissed: rows.filter((r) => matchesFilter(r, 'dismissed')).length,
  };
  const shown = rows.filter((r) => matchesFilter(r, filter));
  const pending = view.approvals.filter((a) => a.status === 'PENDING');
  const met = view.objectives.filter((o) => o.status === 'MET').length;
  const status = caseStatus(c.status);
  const banner = STATUS_BANNER[c.status];
  const toggle = (handle: string) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(handle)) n.delete(handle);
      else n.add(handle);
      return n;
    });

  const tabs: Array<{ key: Tab; label: string; count?: number }> = [
    { key: 'findings', label: 'Findings', count: rows.length },
    { key: 'objectives', label: 'Objectives & coverage', count: view.objectives.length + view.checks.length },
    { key: 'activity', label: 'Activity', count: timeline.length },
  ];

  return (
    <>
      <header className="case-header">
        <div>
          <h2>{caseTitle(c)}</h2>
          <div className="meta-row">
            <LabelPill value={status} dot />
            <span className="meta-item mono">{c.caseId}</span>
            <span className="meta-item" title={c.createdAt}>
              <Icon name="clock" size={13} />
              Started {relativeTime(c.createdAt)}
            </span>
            <span className="meta-item">Round {c.round}</span>
            <span className="meta-item">{humanize(c.mode)}</span>
          </div>
        </div>
      </header>

      {c.status === 'RUNNING' ? (
        <Banner tone="info" title={`Review in progress · round ${c.round}`} icon={<Spinner size={16} />}>
          Findings and objectives update live.
        </Banner>
      ) : banner ? (
        <Banner tone={banner.tone} title={banner.title} icon={<Icon name={banner.icon} size={18} />}>
          {c.status === 'PARKED' && pending.length > 0
            ? `${pending.length} request${pending.length === 1 ? '' : 's'} below need${pending.length === 1 ? 's' : ''} an answer before the review continues.`
            : c.stopReason}
        </Banner>
      ) : null}

      <div className="stats">
        <Stat label="Findings" value={rows.length} hint={`${counts.open} need review`} />
        <Stat label="Confirmed" value={counts.confirmed} tone={counts.confirmed > 0 ? 'danger' : undefined} hint={`${counts.dismissed} false positive${counts.dismissed === 1 ? '' : 's'}`} />
        <Stat
          label="Objectives"
          value={`${met}/${view.objectives.length}`}
          tone={view.objectives.length > 0 && met === view.objectives.length ? 'ok' : undefined}
          hint="met"
        />
        <Stat
          label="Cost"
          value={usd(view.ledger.costUsd)}
          hint={`${view.ledger.modelCalls} model calls · ${view.ledger.sandboxRuns} sandbox runs`}
        />
      </div>

      {pending.length > 0 && (
        <section className="decisions">
          <h3 className="section-title">
            <Icon name="clock" size={15} />
            Needs your decision
            <span className="count">{pending.length}</span>
          </h3>
          <div className="stack">
            {pending.map((a) => (
              <ApprovalCard key={a.approvalId} approval={a} busy={busy === a.approvalId} onDecide={(d) => onDecide(a.approvalId, d)} />
            ))}
          </div>
        </section>
      )}

      <div className="tabs" role="tablist" aria-label="Review sections">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            id={`tab-${t.key}`}
            aria-selected={tab === t.key}
            aria-controls={`panel-${t.key}`}
            className={tab === t.key ? 'tab active' : 'tab'}
            onClick={() => setTab(t.key)}
          >
            {t.label}
            {t.count !== undefined && <span className="count">{t.count}</span>}
            {t.key === 'activity' && live && <span className="live-dot" title="Live" />}
          </button>
        ))}
      </div>

      {tab === 'findings' && (
        <div role="tabpanel" id="panel-findings" aria-labelledby="tab-findings">
          {rows.length === 0 ? (
            <EmptyState icon="shieldCheck" title="No findings in this review">
              The scanners and the reviewer found nothing to report on this snapshot.
            </EmptyState>
          ) : (
            <>
              <div className="segmented" role="group" aria-label="Filter findings">
                {(
                  [
                    ['all', 'All'],
                    ['confirmed', 'Confirmed'],
                    ['open', 'Needs review'],
                    ['dismissed', 'False positives'],
                  ] as const
                ).map(([key, label]) => (
                  <button key={key} type="button" aria-pressed={filter === key} className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>
                    {label}
                    <span className="count">{counts[key]}</span>
                  </button>
                ))}
              </div>
              <ul className="findings">
                {shown.map((r) => (
                  <Finding key={r.handle.handle} row={r} open={open.has(r.handle.handle)} onToggle={() => toggle(r.handle.handle)} />
                ))}
                {shown.length === 0 && <li className="table-empty">No finding in this group.</li>}
              </ul>
            </>
          )}
        </div>
      )}

      {tab === 'objectives' && (
        <div role="tabpanel" id="panel-objectives" aria-labelledby="tab-objectives" className="two-col">
          <Card title="Objectives" icon="target">
            {view.objectives.length === 0 ? (
              <p className="muted">No objectives recorded.</p>
            ) : (
              <ul className="checklist">
                {view.objectives.map((o) => {
                  const s = objectiveStatus(o.status);
                  return (
                    <li key={o.objectiveId} className={`tone-${s.tone}`}>
                      <Icon name={o.status === 'MET' ? 'checkCircle' : o.status === 'NOT_MET' ? 'xCircle' : o.status === 'WAIVED' ? 'minusCircle' : 'circle'} size={17} />
                      <div>
                        <div className="checklist-title">{o.title}</div>
                        {o.reason && <div className="checklist-reason">{o.reason}</div>}
                      </div>
                      <LabelPill value={s} />
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
          <Card title="Coverage" icon="list">
            {view.checks.length === 0 ? (
              <p className="muted">No coverage checks recorded.</p>
            ) : (
              <ul className="checklist">
                {view.checks.map((ch) => {
                  const s = checkOutcome(ch.outcome);
                  return (
                    <li key={ch.checkId} className={`tone-${s.tone}`}>
                      <Icon name={ch.outcome === 'RAN' ? 'checkCircle' : ch.outcome === 'DEGRADED' ? 'alertCircle' : 'minusCircle'} size={17} />
                      <div>
                        <div className="checklist-title mono">{ch.checkId}</div>
                        {ch.reason && <div className="checklist-reason">{ch.reason}</div>}
                      </div>
                      <LabelPill value={s} />
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
        </div>
      )}

      {tab === 'activity' && (
        <div role="tabpanel" id="panel-activity" aria-labelledby="tab-activity" className="card activity">
          <div className="activity-head">
            {live ? (
              <span className="live">
                <span className="live-dot" />
                Live
              </span>
            ) : (
              <span className="faint">Stream closed · showing recorded events</span>
            )}
            <span className="faint">Newest first</span>
          </div>
          {timeline.length === 0 ? (
            <p className="muted">No events yet.</p>
          ) : (
            <ol className="timeline">
              {[...timeline].reverse().map((e) => {
                const stage = STAGE[e.stage] ?? { label: humanize(e.stage), tone: 'neutral' as Tone };
                return (
                  <li key={e.seq} className={`tone-${stage.tone}`}>
                    <span className="tl-time mono">{clockTime(e.at)}</span>
                    <span className="tl-dot" aria-hidden="true" />
                    <span className="tl-body">
                      <strong>{stage.label}</strong>
                      {typeof e.data.tool === 'string' && <code className="tag-code">{e.data.tool}</code>}
                      {typeof e.data.outcome === 'string' && <span className="tl-outcome">{e.data.outcome}</span>}
                      <span className="tl-actor mono">{e.actor}</span>
                    </span>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      )}
    </>
  );
}

function Finding({ row, open, onToggle }: { row: FindingRow; open: boolean; onToggle: () => void }) {
  const { handle: h, verdict: v } = row;
  const verdict = verdictLabel(v?.verdict);
  const id = `finding-${h.handle}`;
  return (
    <li className={open ? 'finding open' : 'finding'}>
      <button type="button" className="finding-row" aria-expanded={open} aria-controls={id} onClick={onToggle}>
        <SeverityBadge severity={row.severity} />
        <span className="finding-main">
          <span className="finding-title">{h.title}</span>
          <span className="finding-loc mono">
            {h.path}:{h.startLine}
            <span className="faint"> · {h.handle}</span>
          </span>
        </span>
        <span className="finding-verdict">
          <LabelPill value={verdict} />
          {v?.poc && <LabelPill value={pocOutcome(v.poc.outcome)} />}
          {v?.applicability && <LabelPill value={applicability(v.applicability.status)} />}
        </span>
        <Icon name="chevronDown" size={16} className="finding-chevron" />
      </button>
      {open && (
        <div className="finding-detail" id={id}>
          <dl className="facts">
            <div>
              <dt>Category</dt>
              <dd>{humanize(h.category)}</dd>
            </div>
            {v && (
              <div>
                <dt>Verification</dt>
                <dd>{verificationLevel(v.verificationLevel)}</dd>
              </div>
            )}
            {v?.applicability?.reachability && (
              <div>
                <dt>Reachability</dt>
                <dd>{reachability(v.applicability.reachability)}</dd>
              </div>
            )}
            {v?.applicability?.justification && (
              <div>
                <dt>Justification</dt>
                <dd>{humanize(v.applicability.justification)}</dd>
              </div>
            )}
            {v?.poc && (
              <div>
                <dt>Proof of concept</dt>
                <dd>
                  {pocOutcome(v.poc.outcome).label}
                  {v.poc.oracle ? ` · ${humanize(v.poc.oracle)}` : ''}
                </dd>
              </div>
            )}
          </dl>
          <div className="rationale">
            {v?.rationale ? <Markdown text={v.rationale} /> : <p className="muted">The reviewer has not written a rationale for this finding yet.</p>}
          </div>
        </div>
      )}
    </li>
  );
}

import { useState } from 'react';
import type { ApprovalRecord } from '../api/types';
import { relativeTime, riskLabel } from '../lib/format';
import { DiffView } from './DiffView';
import { Icon, type IconName } from './icons';
import { Pill } from './ui';

const EFFECT: Record<ApprovalRecord['effect'], { label: string; tone: 'safe' | 'warn' | 'danger'; icon: IconName }> = {
  sandbox: { label: 'Stays in the sandbox (no network, copy of your code)', tone: 'safe', icon: 'shieldCheck' },
  workspace: { label: 'Writes to a workspace copy, not your repository', tone: 'safe', icon: 'shieldCheck' },
  repository: { label: 'Changes your repository', tone: 'danger', icon: 'alert' },
  external: { label: 'Acts on an external system', tone: 'danger', icon: 'alert' },
  governance: { label: 'Changes how findings are judged', tone: 'warn', icon: 'shieldAlert' },
};

const GRANT_LABEL = { once: 'Approve once', case: 'Approve for this review', standing: 'Always allow this target' } as const;

export interface Decision {
  decision: 'approve' | 'deny';
  grant?: 'once' | 'case' | 'standing';
  reason?: string;
}

/**
 * One action waiting for a human. The card states where the effect lands, shows the real diff for
 * patches and harnesses, offers only the grants the policy allows, and marks human-only requests.
 * The safe default (approve once) sits next to Deny; broader grants come first and read as such.
 */
export function ApprovalCard({
  approval,
  onDecide,
  busy,
  context,
}: {
  approval: ApprovalRecord;
  onDecide: (d: Decision) => void;
  busy?: boolean;
  /** Where the request comes from, for lists that mix projects and cases. */
  context?: { project?: string; onOpen?: () => void };
}) {
  const [reason, setReason] = useState('');
  const effect = EFFECT[approval.effect] ?? EFFECT.governance;
  const grants = approval.humanOnly ? (['once'] as const) : approval.offeredGrants;
  const broader = grants.filter((g) => g !== 'once');
  const risk = riskLabel(approval.risk);
  const withReason = reason.trim() ? { reason: reason.trim() } : {};
  return (
    <article className={`approval tone-${effect.tone}`} aria-label={approval.title} aria-busy={busy || undefined}>
      <header className="approval-header">
        <div className="approval-meta">
          {context?.project && (
            <>
              <span className="approval-project">
                <Icon name="folder" size={13} />
                {context.project}
              </span>
              <span aria-hidden="true">·</span>
            </>
          )}
          {context && (
            <>
              <span className="mono">{approval.caseId}</span>
              <span aria-hidden="true">·</span>
            </>
          )}
          <span title={approval.requestedAt}>Requested {relativeTime(approval.requestedAt)}</span>
          {context?.onOpen && (
            <button type="button" className="link-btn" onClick={context.onOpen}>
              Open review
              <Icon name="chevronRight" size={13} />
            </button>
          )}
        </div>
        <h3>{approval.title}</h3>
        <div className="approval-tags">
          <code className="tag-code">{approval.tool}</code>
          <Pill tone={risk.tone} title={approval.risk}>
            {risk.label}
          </Pill>
          {approval.humanOnly && (
            <Pill tone="danger" title="Only a human can approve this; it is never remembered">
              <Icon name="lock" size={12} />
              human decision
            </Pill>
          )}
        </div>
      </header>

      <div className={`effect effect-${effect.tone}`}>
        <Icon name={effect.icon} size={16} />
        <span>{effect.label}</span>
      </div>

      {approval.summary && <p className="approval-summary">{approval.summary}</p>}
      {approval.targets.length > 0 && (
        <div className="approval-targets">
          <span className="field-label">Targets</span>
          {approval.targets.map((t) => (
            <code key={`${t.kind}:${t.value}`} className="tag-code" title={t.kind}>
              {t.value}
            </code>
          ))}
        </div>
      )}
      {approval.diff && <DiffView diff={approval.diff} />}
      <details className="approval-args">
        <summary>
          <Icon name="chevronRight" size={13} />
          Technical details
        </summary>
        <pre className="code-block">{approval.argsPreview}</pre>
      </details>

      <footer className="approval-footer">
        <input
          className="reason-input"
          placeholder="Reason (optional)"
          title="Kept in the audit log with your decision"
          aria-label="Reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <div className="approval-actions">
          {broader.map((g) => (
            <button key={g} type="button" className="btn" disabled={busy} onClick={() => onDecide({ decision: 'approve', grant: g, ...withReason })}>
              {GRANT_LABEL[g]}
            </button>
          ))}
          <button type="button" className="btn btn-danger-outline" disabled={busy} onClick={() => onDecide({ decision: 'deny', ...withReason })}>
            Deny
          </button>
          {grants.includes('once') && (
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => onDecide({ decision: 'approve', grant: 'once', ...withReason })}>
              <Icon name="check" size={15} />
              {GRANT_LABEL.once}
            </button>
          )}
        </div>
      </footer>
    </article>
  );
}

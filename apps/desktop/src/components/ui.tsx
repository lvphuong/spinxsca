import { createContext, type ReactNode, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { Label, Tone } from '../lib/format';
import { Icon, type IconName } from './icons';

/** Small building blocks shared by the views. Colours come from tones, never from raw values. */

export function Pill({ tone = 'neutral', children, title, dot }: { tone?: Tone; children: ReactNode; title?: string; dot?: boolean }) {
  return (
    <span className={`pill tone-${tone}`} title={title}>
      {dot && <span className="pill-dot" aria-hidden="true" />}
      {children}
    </span>
  );
}

export const LabelPill = ({ value, dot }: { value: Label; dot?: boolean }) => (
  <Pill tone={value.tone} dot={dot}>
    {value.label}
  </Pill>
);

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toUpperCase();
  return (
    <span className={`sev sev-${s.toLowerCase()}`} title={`Severity: ${s.toLowerCase()}`}>
      {s.charAt(0) + s.slice(1).toLowerCase()}
    </span>
  );
}

export function Spinner({ size = 14, label }: { size?: number; label?: string }) {
  return <span className="spinner" style={{ width: size, height: size }} role={label ? 'status' : undefined} aria-label={label} />;
}

export function PageHeader({
  title,
  subtitle,
  actions,
  back,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  back?: { label: string; onClick: () => void };
}) {
  return (
    <header className="page-header">
      <div className="page-heading">
        {back && (
          <button type="button" className="crumb" onClick={back.onClick}>
            <Icon name="chevronLeft" size={14} />
            {back.label}
          </button>
        )}
        <h1>{title}</h1>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

const BANNER_ICON: Record<Tone, IconName> = {
  neutral: 'info',
  info: 'info',
  ok: 'checkCircle',
  warn: 'alert',
  danger: 'alertCircle',
};

export function Banner({
  tone,
  title,
  children,
  action,
  icon,
  onDismiss,
}: {
  tone: Tone;
  title?: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <div className={`banner tone-${tone}`} role={tone === 'danger' ? 'alert' : undefined}>
      <span className="banner-icon">{icon ?? <Icon name={BANNER_ICON[tone]} size={18} />}</span>
      <div className="banner-body">
        {title && <div className="banner-title">{title}</div>}
        {children && <div className="banner-text">{children}</div>}
      </div>
      {action && <div className="banner-action">{action}</div>}
      {onDismiss && (
        <button type="button" className="icon-btn" aria-label="Dismiss" onClick={onDismiss}>
          <Icon name="x" size={14} />
        </button>
      )}
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: { icon: IconName; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icon} size={22} />
      </span>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: Tone }) {
  return (
    <div className={`stat${tone ? ` tone-${tone}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Card({ title, icon, actions, children, className }: { title?: ReactNode; icon?: IconName; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={className ? `card ${className}` : 'card'}>
      {(title || actions) && (
        <header className="card-header">
          {title && (
            <h2>
              {icon && <Icon name={icon} size={16} />}
              {title}
            </h2>
          )}
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

interface Toast {
  id: number;
  text: string;
  tone: Tone;
}

const ToastContext = createContext<(text: string, tone?: Tone) => void>(() => undefined);

/** Short confirmations ("Review queued", "Approved") that do not need a place on the page. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(0);
  const push = useCallback((text: string, tone: Tone = 'ok') => {
    const id = ++next.current;
    setToasts((t) => [...t.slice(-2), { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000);
  }, []);
  const value = useMemo(() => push, [push]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast tone-${t.tone}`}>
            <Icon name={t.tone === 'danger' ? 'alertCircle' : t.tone === 'ok' ? 'checkCircle' : 'info'} size={16} />
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

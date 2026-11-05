import type { ReactNode } from 'react';

/** Stroke icons on a 24px grid, drawn for this app (no icon package in the webview bundle). */
const PATHS = {
  inbox: (
    <>
      <path d="M3 13h5l1.5 2.5h5L16 13h5" />
      <path d="M5.5 5h13l2.5 8v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-5z" />
    </>
  ),
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  folderPlus: (
    <>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
      <path d="M12 10.5v5M9.5 13h5" />
    </>
  ),
  sliders: (
    <>
      <path d="M4 7h9M17 7h3M4 17h3M11 17h9" />
      <circle cx="15" cy="7" r="2" />
      <circle cx="9" cy="17" r="2" />
    </>
  ),
  shield: <path d="M12 3l7.5 3v5.5c0 4.3-3.1 8-7.5 9.5-4.4-1.5-7.5-5.2-7.5-9.5V6z" />,
  shieldCheck: (
    <>
      <path d="M12 3l7.5 3v5.5c0 4.3-3.1 8-7.5 9.5-4.4-1.5-7.5-5.2-7.5-9.5V6z" />
      <path d="M8.75 12l2.25 2.25 4.25-4.5" />
    </>
  ),
  shieldAlert: (
    <>
      <path d="M12 3l7.5 3v5.5c0 4.3-3.1 8-7.5 9.5-4.4-1.5-7.5-5.2-7.5-9.5V6z" />
      <path d="M12 8.5v4M12 15.75v.01" />
    </>
  ),
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  checkCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M8.5 12.25l2.5 2.5 4.5-5" />
    </>
  ),
  x: <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />,
  xCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.25 9.25l5.5 5.5M14.75 9.25l-5.5 5.5" />
    </>
  ),
  alert: (
    <>
      <path d="M10.3 4.3a2 2 0 0 1 3.4 0l7.4 12.7a2 2 0 0 1-1.7 3H4.6a2 2 0 0 1-1.7-3z" />
      <path d="M12 9.5v4M12 16.75v.01" />
    </>
  ),
  alertCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.75v5M12 16.25v.01" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.25M12 7.75v.01" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  circle: <circle cx="12" cy="12" r="8.5" />,
  minusCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M8.5 12h7" />
    </>
  ),
  play: <path d="M8 5.75v12.5a.75.75 0 0 0 1.13.65l10.4-6.25a.75.75 0 0 0 0-1.3L9.13 5.1A.75.75 0 0 0 8 5.75z" />,
  chevronRight: <path d="M9.5 6l6 6-6 6" />,
  chevronDown: <path d="M6 9.5l6 6 6-6" />,
  chevronLeft: <path d="M14.5 6l-6 6 6 6" />,
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M20 20l-4.25-4.25" />
    </>
  ),
  refresh: (
    <>
      <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
      <path d="M19.5 4.5v4h-4" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15.5" r="4" />
      <path d="M11 12.5l8.5-8.5M16 7.5l2.5 2.5M13.75 9.75l1.75 1.75" />
    </>
  ),
  box: (
    <>
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" />
      <path d="M4 7.5l8 4.5 8-4.5M12 12v9" />
    </>
  ),
  server: (
    <>
      <rect x="3.5" y="4" width="17" height="7" rx="2" />
      <rect x="3.5" y="13" width="17" height="7" rx="2" />
      <path d="M7.5 7.5h.01M7.5 16.5h.01" />
    </>
  ),
  activity: <path d="M3 12h4l3-7.5 4 15 3-7.5h4" />,
  sparkles: (
    <>
      <path d="M11 3.5l1.9 5.1L18 10.5l-5.1 1.9L11 17.5l-1.9-5.1L4 10.5l5.1-1.9z" />
      <path d="M18.5 15.5l.75 1.75 1.75.75-1.75.75-.75 1.75-.75-1.75-1.75-.75 1.75-.75z" />
    </>
  ),
  branch: (
    <>
      <circle cx="6.5" cy="5.5" r="2" />
      <circle cx="6.5" cy="18.5" r="2" />
      <circle cx="17.5" cy="7.5" r="2" />
      <path d="M6.5 7.5v9M17.5 9.5c0 4-4 4.5-9.5 7.5" />
    </>
  ),
  flask: (
    <>
      <path d="M9 3.5h6M10 3.5v5.5l-5.2 8.9A2 2 0 0 0 6.5 21h11a2 2 0 0 0 1.7-3.1L14 9V3.5" />
      <path d="M7.25 15h9.5" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10.5" width="14" height="10" rx="2" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3" />
    </>
  ),
  external: (
    <>
      <path d="M14 4h6v6M20 4l-8.5 8.5" />
      <path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />
    </>
  ),
  trash: <path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l.9 12.1a1 1 0 0 0 1 .9h7.2a1 1 0 0 0 1-.9L17.5 7" />,
  plus: <path d="M12 5v14M5 12h14" />,
  file: (
    <>
      <path d="M14 3.5H6.5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V8z" />
      <path d="M14 3.5V8h4.5" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4.5" />
      <circle cx="12" cy="12" r="0.75" />
    </>
  ),
  list: <path d="M9 6.5h11M9 12h11M9 17.5h11M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01" />,
  code: <path d="M8.5 7.5L4 12l4.5 4.5M15.5 7.5L20 12l-4.5 4.5M13.5 5l-3 14" />,
  terminal: (
    <>
      <rect x="3" y="4.5" width="18" height="15" rx="2" />
      <path d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5" />
    </>
  ),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 16, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      className={className ? `icon ${className}` : 'icon'}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

/**
 * Bridge to the Tauri shell. Every call is optional: in a plain browser (development, tests) the
 * app runs against a sidecar URL without native features.
 */
const inTauri = () => typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

/** True inside the desktop shell; false in a plain browser (development, tests). */
export const inDesktopShell = inTauri;

export async function invokeShell<T>(command: string, args: Record<string, unknown> = {}): Promise<T | undefined> {
  if (!inTauri()) return undefined;
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(command, args);
}

export async function pickFolder(): Promise<string | undefined> {
  if (!inTauri()) return window.prompt('Folder to review') ?? undefined;
  const { open } = await import('@tauri-apps/plugin-dialog');
  const picked = await open({ directory: true, multiple: false });
  return typeof picked === 'string' ? picked : undefined;
}

export async function openExternal(url: string): Promise<void> {
  if (!/^https:\/\//i.test(url)) return;
  if (!inTauri()) {
    window.open(url, '_blank', 'noopener,noreferrer');
    return;
  }
  const { openUrl } = await import('@tauri-apps/plugin-opener');
  await openUrl(url);
}

export async function notify(title: string, body: string): Promise<void> {
  if (!inTauri()) return;
  const { isPermissionGranted, requestPermission, sendNotification } = await import('@tauri-apps/plugin-notification');
  let granted = await isPermissionGranted();
  if (!granted) granted = (await requestPermission()) === 'granted';
  if (granted) sendNotification({ title, body });
}

export interface DockerStatus {
  available: boolean;
  version?: string;
  detail: string;
}

export const dockerStatus = () => invokeShell<DockerStatus>('docker_status');
export const providerKeyPresent = (provider: string) => invokeShell<boolean>('provider_key_present', { provider });
export const setProviderKey = (provider: string, key: string) =>
  invokeShell<void>('set_provider_key', { provider, key });
export const deleteProviderKey = (provider: string) => invokeShell<void>('delete_provider_key', { provider });
/** Restarts the shell's supervisor tries before giving up (supervisor.rs MAX_RESTARTS). */
export const SIDECAR_MAX_RESTARTS = 5;

/** What the shell knows about the local service process (desktop only). */
export interface SidecarStatus {
  running: boolean;
  restarts: number;
  port?: number | null;
  /** Why the last start failed; null once the service reported ready. */
  lastError?: string | null;
  /** End of the service log at the time of that failure. */
  logTail?: string | null;
  /** Restarts exhausted; `retrySidecar` starts it again. */
  gaveUp: boolean;
  logPath: string;
}

export const sidecarStatus = () => invokeShell<SidecarStatus>('sidecar_status');
export const retrySidecar = () => invokeShell<void>('retry_sidecar');
/** Shows the service log in the file manager. */
export const openSidecarLog = () => invokeShell<void>('open_sidecar_log');

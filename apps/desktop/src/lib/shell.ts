/**
 * Bridge to the Tauri shell. Every call is optional: in a plain browser (development, tests) the
 * app runs against a sidecar URL without native features.
 */
const inTauri = () => typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

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
export const sidecarStatus = () => invokeShell<{ running: boolean; restarts: number; port?: number }>('sidecar_status');

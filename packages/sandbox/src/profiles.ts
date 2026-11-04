import type { SandboxProfile } from '@spinxsca/core';

export interface ProfileSpec {
  /** tmpfs mounts inside the container. */
  tmpfs: readonly string[];
  /** Default resources when the caller does not ask for less. */
  resources: { cpus: number; memoryMb: number; pidsLimit: number; timeoutSec: number };
  ulimits: readonly string[];
}

/**
 * Fixed sandbox profiles (ADR-043). They differ only in scratch space and resources: the network is
 * disabled, capabilities dropped, the root filesystem read-only and the user unprivileged for all.
 */
export const PROFILES: Readonly<Record<SandboxProfile, ProfileSpec>> = {
  scan: {
    tmpfs: ['/tmp:rw,nosuid,nodev,size=1g'],
    resources: { cpus: 2, memoryMb: 4096, pidsLimit: 512, timeoutSec: 1800 },
    ulimits: ['nofile=4096:4096'],
  },
  analysis: {
    tmpfs: ['/tmp:rw,nosuid,nodev,noexec,size=256m'],
    resources: { cpus: 1, memoryMb: 1024, pidsLimit: 128, timeoutSec: 60 },
    ulimits: ['nofile=1024:1024', 'fsize=268435456'],
  },
  validation: {
    tmpfs: ['/tmp:rw,nosuid,nodev,size=512m'],
    resources: { cpus: 2, memoryMb: 2048, pidsLimit: 256, timeoutSec: 300 },
    ulimits: ['nofile=1024:1024', 'fsize=268435456'],
  },
  patch: {
    tmpfs: ['/tmp:rw,nosuid,nodev,size=1g'],
    resources: { cpus: 2, memoryMb: 2048, pidsLimit: 512, timeoutSec: 600 },
    ulimits: ['nofile=4096:4096'],
  },
};

/** Images must be content addressed: "<name>@sha256:<64 hex>" or a local image id "sha256:<64 hex>". */
export const PINNED_IMAGE = /(^|@)sha256:[0-9a-f]{64}$/;

export function isPinnedImage(image: string): boolean {
  return PINNED_IMAGE.test(image);
}

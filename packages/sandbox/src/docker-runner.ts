import { spawn } from 'node:child_process';
import type {
  ContainerRunResult,
  ContainerRunSpec,
  Logger,
  SandboxPreflight,
  SandboxProfile,
  SandboxRunner,
} from '@spinxsca/core';
import { silentLogger } from '@spinxsca/core';

const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;

export interface DockerSandboxOptions {
  dockerBin?: string;
  /** Optional custom seccomp profile path; Docker's default allow-list profile is used otherwise. */
  seccompProfile?: string;
  logger?: Logger;
}

/**
 * Runs scanner containers with a hardened, host-chosen profile (ADR-021, ADR-025): no network,
 * all capabilities dropped, no-new-privileges, read-only root filesystem, non-root user, resource
 * limits and a hard timeout. Profiles are fixed here; nothing a model or repository supplies can
 * widen them.
 */
export class DockerSandboxRunner implements SandboxRunner {
  private readonly docker: string;
  private readonly logger: Logger;

  constructor(private readonly options: DockerSandboxOptions = {}) {
    this.docker = options.dockerBin ?? 'docker';
    this.logger = options.logger ?? silentLogger;
  }

  /** The hardening flags shared by every profile. Exposed for tests and preflight. */
  hardeningArgs(profile: SandboxProfile): string[] {
    const args = [
      '--network',
      'none',
      '--cap-drop',
      'ALL',
      '--security-opt',
      'no-new-privileges',
      '--read-only',
      '--tmpfs',
      '/tmp:rw,nosuid,nodev,size=1g',
      '--user',
      containerUser(),
    ];
    if (this.options.seccompProfile) args.push('--security-opt', `seccomp=${this.options.seccompProfile}`);
    // validation and patch profiles get dedicated writable workspaces in later phases; the network
    // stays disabled for all of them.
    void profile;
    return args;
  }

  buildRunArgs(spec: ContainerRunSpec): string[] {
    const args = ['run', '--rm', '--name', spec.name, ...this.hardeningArgs(spec.profile)];
    args.push('--pids-limit', String(spec.resources.pidsLimit ?? 512));
    args.push('--memory', `${spec.resources.memoryMb}m`, '--cpus', String(spec.resources.cpus));
    args.push('--workdir', spec.workdir);
    for (const mount of spec.mounts) {
      if (mount.hostPath.includes(',')) throw new Error(`mount path must not contain commas: ${mount.hostPath}`);
      args.push(
        '--mount',
        `type=bind,source=${mount.hostPath},target=${mount.containerPath}${mount.readOnly ? ',readonly' : ''}`,
      );
    }
    for (const [key, value] of Object.entries(spec.env).sort(([a], [b]) => a.localeCompare(b))) {
      args.push('--env', `${key}=${value}`);
    }
    args.push(spec.image, ...spec.args);
    return args;
  }

  async run(spec: ContainerRunSpec, signal?: AbortSignal): Promise<ContainerRunResult> {
    const args = this.buildRunArgs(spec);
    this.logger.debug('docker run', { name: spec.name, image: spec.image });
    const started = Date.now();
    let timedOut = false;
    const kill = (): void => {
      spawn(this.docker, ['kill', spec.name], { stdio: 'ignore' }).on('error', () => {});
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, spec.resources.timeoutSec * 1000);
    const onAbort = (): void => kill();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const result = await exec(this.docker, args);
      return { ...result, timedOut, durationMs: Date.now() - started };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  /**
   * Verifies the runtime is reachable and reads back the effective configuration of a container
   * created with the scan profile, so a misconfigured daemon cannot silently weaken isolation.
   */
  async preflight(image: string): Promise<SandboxPreflight> {
    const checks: SandboxPreflight['checks'] = [];
    const version = await exec(this.docker, ['version', '--format', '{{.Server.Version}}']).catch((err: Error) => ({
      exitCode: 1,
      stdout: '',
      stderr: err.message,
    }));
    if (version.exitCode !== 0) {
      checks.push({ name: 'docker daemon', ok: false, detail: version.stderr.trim() || 'docker is not available' });
      return { ok: false, runtime: 'docker', checks };
    }
    const serverVersion = version.stdout.trim();
    checks.push({ name: 'docker daemon', ok: true, detail: `server ${serverVersion}` });

    const present = await exec(this.docker, ['image', 'inspect', '--format', '{{.Id}}', image]);
    checks.push({
      name: 'scanner image',
      ok: present.exitCode === 0,
      detail: present.exitCode === 0 ? `${image} present` : `${image} not pulled yet (pulled on first scan)`,
    });

    if (present.exitCode === 0) {
      const name = `spinxsca-preflight-${process.pid}-${Date.now()}`;
      const created = await exec(this.docker, ['create', '--name', name, ...this.hardeningArgs('scan'), image, 'true']);
      if (created.exitCode === 0) {
        const inspected = await exec(this.docker, ['inspect', '--format', '{{json .HostConfig}}', name]);
        await exec(this.docker, ['rm', '-f', name]);
        checks.push(...verifyHostConfig(inspected.stdout));
      } else {
        checks.push({ name: 'hardened container', ok: false, detail: created.stderr.trim() });
      }
    }
    // A missing image is not fatal: docker pulls it on first use.
    const ok = checks.filter((c) => c.name !== 'scanner image').every((c) => c.ok);
    return { ok, runtime: 'docker', version: serverVersion, checks };
  }
}

function verifyHostConfig(json: string): SandboxPreflight['checks'] {
  let config: {
    NetworkMode?: string;
    CapDrop?: string[] | null;
    ReadonlyRootfs?: boolean;
    SecurityOpt?: string[] | null;
    Privileged?: boolean;
  };
  try {
    config = JSON.parse(json);
  } catch {
    return [{ name: 'hardened container', ok: false, detail: 'could not read container configuration' }];
  }
  const securityOpt = config.SecurityOpt ?? [];
  return [
    { name: 'network disabled', ok: config.NetworkMode === 'none', detail: `NetworkMode=${config.NetworkMode}` },
    {
      name: 'capabilities dropped',
      ok: (config.CapDrop ?? []).map((c) => c.toUpperCase()).includes('ALL'),
      detail: `CapDrop=${JSON.stringify(config.CapDrop)}`,
    },
    { name: 'read-only rootfs', ok: config.ReadonlyRootfs === true, detail: `ReadonlyRootfs=${config.ReadonlyRootfs}` },
    {
      name: 'no-new-privileges',
      ok: securityOpt.some((o) => o.startsWith('no-new-privileges')),
      detail: securityOpt.join(' ') || 'none',
    },
    {
      name: 'seccomp confined',
      ok: !securityOpt.some((o) => o.replace(/[:=]/, '=') === 'seccomp=unconfined'),
      detail: 'docker default or custom profile',
    },
    { name: 'not privileged', ok: config.Privileged !== true, detail: `Privileged=${config.Privileged}` },
  ];
}

/** Host uid:gid so bind-mounted output is writable on Linux; never root inside the container. */
export function containerUser(): string {
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  const gid = typeof process.getgid === 'function' ? process.getgid() : undefined;
  if (uid === undefined || gid === undefined || uid === 0) return '65534:65534';
  return `${uid}:${gid}`;
}

function exec(bin: string, args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = new BoundedBuffer(MAX_CAPTURE_BYTES);
    const stderr = new BoundedBuffer(MAX_CAPTURE_BYTES);
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => resolve({ exitCode: code ?? 1, stdout: stdout.text(), stderr: stderr.text() }));
  });
}

/** Keeps the last `limit` bytes of a stream. */
class BoundedBuffer {
  private chunks: Buffer[] = [];
  private size = 0;
  constructor(private readonly limit: number) {}
  push(chunk: Buffer): void {
    this.chunks.push(chunk);
    this.size += chunk.byteLength;
    while (this.size > this.limit && this.chunks.length > 1) {
      this.size -= (this.chunks.shift() as Buffer).byteLength;
    }
  }
  text(): string {
    return Buffer.concat(this.chunks).toString('utf8');
  }
}

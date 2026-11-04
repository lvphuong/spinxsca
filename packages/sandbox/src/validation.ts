import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import {
  decidePoc,
  lintHarness,
  marker,
  type RedactionSpan,
  type RunEvidence,
  type SandboxRunner,
  type SecretScrubber,
  type SourceTree,
  sha256,
  stableStringify,
  type ValidationPort,
  type ValidationRunResult,
} from '@spinxsca/core';
import type { PocOracle } from '@spinxsca/schemas';
import { materializeRedactedCopy } from './materialize';
import { PROFILES } from './profiles';
import { NODE_IMAGE, PYTHON_IMAGE } from './test-runner';

const INTERPRETERS: Readonly<Record<string, string>> = {
  node: NODE_IMAGE,
  python3: PYTHON_IMAGE,
  python: PYTHON_IMAGE,
};
const LOG_LIMIT = 6000;

export interface ValidationPortOptions {
  sandbox: SandboxRunner;
  source: SourceTree;
  paths: readonly string[];
  /** Host directory holding the case's validation workspaces (kept across restarts). */
  root: string;
  allows?: (path: string) => boolean;
  redactions?: readonly RedactionSpan[];
  scrubber: SecretScrubber;
  timeoutSec?: number;
  memoryMb?: number;
}

/**
 * L3 controlled validation (ADR-045). Each handle gets a workspace: a redacted copy of the snapshot
 * plus `harness/`; installed dependencies are mounted read-only when present, never installed. A run
 * executes the same harness twice in the `validation` profile (no network): attack with the nonce,
 * control with another token, each with a fresh canary and oracle directory. The host oracle decides.
 */
export function localValidationPort(o: ValidationPortOptions): ValidationPort {
  const dirOf = (id: string) => join(o.root, id);
  const harnessDir = (id: string) => join(dirOf(id), 'work', 'harness');

  async function files(id: string): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    const walk = async (dir: string, rel: string) => {
      if (!existsSync(dir)) return;
      for (const e of await readdir(dir, { withFileTypes: true })) {
        if (e.isDirectory()) await walk(join(dir, e.name), `${rel}${e.name}/`);
        else out[`harness/${rel}${e.name}`] = await readFile(join(dir, e.name), 'utf8');
      }
    };
    await walk(harnessDir(id), '');
    return out;
  }

  return {
    workspaces() {
      if (!existsSync(o.root)) return [];
      return readdirSync(o.root, { withFileTypes: true })
        .filter((e) => e.isDirectory() && e.name.startsWith('ws-'))
        .map((e) => e.name)
        .sort();
    },
    async open(handle) {
      const id = `ws-${handle.toLowerCase()}`;
      if (!existsSync(join(dirOf(id), 'work', 'src'))) {
        await materializeRedactedCopy({
          source: o.source,
          paths: o.paths,
          dest: join(dirOf(id), 'work', 'src'),
          ...(o.allows ? { allows: o.allows } : {}),
          ...(o.redactions ? { redactions: o.redactions } : {}),
          scrubber: o.scrubber,
        });
        await mkdir(harnessDir(id), { recursive: true });
      }
      return { workspaceId: id, interpreters: Object.keys(INTERPRETERS) };
    },
    async writeHarness(id, relPath, content) {
      const base = resolve(harnessDir(id));
      const clean = relPath.replace(/^harness\//, '');
      const target = resolve(base, clean);
      if (!target.startsWith(base + sep)) throw new Error(`harness files must stay inside harness/: ${relPath}`);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, content);
    },
    harnessFiles: files,
    async lastRun(id, handle) {
      const path = join(dirOf(id), 'runs.json');
      if (!existsSync(path)) return undefined;
      const runs = JSON.parse(await readFile(path, 'utf8')) as ValidationRunResult[];
      return runs.filter((r) => r.handle === handle).at(-1);
    },
    async run({ workspaceId, handle, command, oracle, signal }) {
      if (!existsSync(join(dirOf(workspaceId), 'work'))) throw new Error(`unknown workspace ${workspaceId}`);
      const [interpreter, ...args] = command;
      const image = interpreter ? INTERPRETERS[interpreter] : undefined;
      if (!image) throw new Error(`interpreter must be one of ${Object.keys(INTERPRETERS).join(', ')}`);
      if (args.some((a) => a.startsWith('/') || a.split('/').includes('..'))) {
        throw new Error('harness arguments must be relative paths inside the workspace');
      }
      const harness = await files(workspaceId);
      const lint = lintHarness(harness);
      const nonce = randomBytes(12).toString('hex');
      const controlToken = randomBytes(12).toString('hex');
      const attack = await runOnce('attack', nonce);
      const control = await runOnce('control', controlToken);
      const decided = lint.length
        ? {
            outcome: 'INVALID_HARNESS' as const,
            attackTriggered: false,
            controlTriggered: false,
            detail: `harness rejected: ${lint.join('; ')}`,
          }
        : decidePoc({ oracle, nonce, controlToken, attack, control });
      const scrub = (r: RunEvidence) =>
        o.scrubber
          .scrub(
            `exit ${r.exitCode}${r.timedOut ? ' (timed out)' : ''}\n${r.stdout}\n${r.stderr}`
              .replaceAll(nonce, '<NONCE>')
              .replaceAll(controlToken, '<CONTROL>'),
          )
          .slice(-LOG_LIMIT);
      const result: ValidationRunResult = {
        workspaceId,
        handle,
        oracle,
        command: [...command],
        outcome: decided.outcome,
        attackTriggered: decided.attackTriggered,
        controlTriggered: decided.controlTriggered,
        detail: decided.detail,
        harnessDigest: sha256(stableStringify(harness)),
        attackLog: scrub(attack),
        controlLog: scrub(control),
        lintProblems: lint,
        at: new Date().toISOString(),
      };
      const runsPath = join(dirOf(workspaceId), 'runs.json');
      const runs = existsSync(runsPath) ? (JSON.parse(await readFile(runsPath, 'utf8')) as ValidationRunResult[]) : [];
      runs.push(result);
      await writeFile(runsPath, JSON.stringify(runs, null, 2));
      return result;

      async function runOnce(mode: 'attack' | 'control', token: string): Promise<RunEvidence> {
        const scratch = await mkdtemp(join(dirOf(workspaceId), `run-${mode}-`));
        const canary = join(scratch, 'canary');
        const oracleDir = join(scratch, 'oracle');
        await mkdir(canary, { recursive: true });
        await mkdir(oracleDir, { recursive: true });
        await writeFile(join(canary, 'secret.txt'), `${marker('CANARY_READ', token)}\n`);
        const limits = PROFILES.validation.resources;
        const deps = ['node_modules', '.venv'].filter((d) => existsSync(join(o.source.root, d)));
        try {
          const r = await o.sandbox.run(
            {
              name: `spinxsca-poc-${randomBytes(6).toString('hex')}`,
              image: image as string,
              args: [interpreter as string, ...args],
              env: {
                HOME: '/tmp',
                SPX_MODE: mode,
                SPX_NONCE: token,
                SPX_CANARY_PATH: '/canary/secret.txt',
                SPX_COMMAND_MARKER: `/oracle/${marker('COMMAND_MARKER', token)}`,
                NODE_ENV: 'test',
                PYTHONDONTWRITEBYTECODE: '1',
              },
              mounts: [
                { hostPath: join(dirOf(workspaceId), 'work'), containerPath: '/work', readOnly: false },
                { hostPath: canary, containerPath: '/canary', readOnly: true },
                { hostPath: oracleDir, containerPath: '/oracle', readOnly: false },
                ...deps.map((d) => ({
                  hostPath: join(o.source.root, d),
                  containerPath: `/work/src/${d}`,
                  readOnly: true,
                })),
              ],
              workdir: '/work',
              profile: 'validation',
              resources: {
                cpus: limits.cpus,
                memoryMb: Math.min(o.memoryMb ?? limits.memoryMb, limits.memoryMb * 4),
                pidsLimit: limits.pidsLimit,
                timeoutSec: Math.min(o.timeoutSec ?? 120, limits.timeoutSec),
              },
            },
            signal,
          );
          const oracleFiles: Record<string, string> = {};
          for (const name of await readdir(oracleDir)) {
            oracleFiles[name] = (await readFile(join(oracleDir, name), 'utf8').catch(() => '')).slice(0, 4096);
          }
          return { exitCode: r.exitCode, stdout: r.stdout, stderr: r.stderr, timedOut: r.timedOut, oracleFiles };
        } finally {
          await rm(scratch, { recursive: true, force: true });
        }
      }
    },
  };
}

/** Oracle markers exposed for prompts: the agent learns the format, never the nonce. */
export function oracleGuide(oracle: PocOracle): string | undefined {
  switch (oracle) {
    case 'CANARY_READ':
      return 'Make the vulnerable code read the file at process.env.SPX_CANARY_PATH (a path traversal target) and print what it returns.';
    case 'COMMAND_MARKER':
      return 'Inject a command that creates the file process.env.SPX_COMMAND_MARKER (e.g. `touch <path>`); the host checks it exists.';
    case 'UNESCAPED_REFLECTION':
      return 'Send `<spx-` + SPX_NONCE + `>` as input and print the rendered output; it counts only if it comes back unescaped.';
    case 'DATA_DIFFERENTIAL':
      return 'Seed a row the caller must not see whose value is `SPX-ROW-` followed by SPX_NONCE, run the vulnerable query as the caller and print the result.';
  }
}

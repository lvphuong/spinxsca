import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { Registry, RemoteWorker, type RemoteWorkerConfig, registerWorker } from '@spinxsca/server';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { openEngine, scanDeps } from '../engine';
import { CliError, createLogger, EXIT } from '../ui';

const CONFIG_FILE = 'worker.json';

export async function workerRegisterCommand(options: {
  server: string;
  provisioningToken: string;
  dataDir: string;
  name?: string;
}): Promise<number> {
  const dataDir = resolve(options.dataDir);
  const config = await registerWorker({
    server: options.server,
    provisioningToken: options.provisioningToken,
    name: options.name ?? hostname(),
  });
  const path = join(dataDir, CONFIG_FILE);
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  process.stderr.write(
    `${pc.green('registered')} worker ${config.workerId} with ${config.server}; credential stored in ${path} (mode 600)\n`,
  );
  return EXIT.OK;
}

export async function workerRunCommand(options: {
  dataDir: string;
  config?: string;
  poll: string;
  once?: boolean;
  verbose?: boolean;
}): Promise<number> {
  const dataDir = resolve(options.dataDir);
  let config: RemoteWorkerConfig;
  try {
    config = JSON.parse(readFileSync(join(dataDir, CONFIG_FILE), 'utf8')) as RemoteWorkerConfig;
  } catch {
    throw new CliError(`no worker registration in ${dataDir}; run \`spinxsca worker register\` first`);
  }
  const loaded = loadConfig(options.config);
  const logger = createLogger(Boolean(options.verbose));
  const worker: RemoteWorker = new RemoteWorker({
    config,
    dataDir,
    logger,
    engines: ({ sourceDir, stateDir, repo, artifacts }) => {
      const engine = openEngine({
        scanRoot: sourceDir,
        stateDir,
        config: loaded,
        kbDir: worker.kbDir,
        logger,
        ...(repo ? { repo } : {}),
        ...(artifacts ? { artifacts } : {}),
      });
      return { deps: scanDeps(engine), close: () => engine.close() };
    },
  });
  if (options.once) {
    const job = await worker.runOnce();
    process.stderr.write(job ? `ran job ${job.jobId}\n` : 'no job available\n');
    return EXIT.OK;
  }
  process.stderr.write(`${pc.green('spinxsca worker')} ${config.workerId} polling ${config.server}\n`);
  const running = worker.start(Number(options.poll) * 1000);
  await new Promise<void>((resolveStop) => {
    process.once('SIGINT', () => resolveStop());
    process.once('SIGTERM', () => resolveStop());
  });
  process.stderr.write('stopping after the current job…\n');
  await worker.stop();
  await running;
  return EXIT.OK;
}

export async function provisionWorkerCommand(options: {
  dataDir: string;
  pool?: string[];
  ttl: string;
  uses: string;
}): Promise<number> {
  const registry = Registry.open(resolve(options.dataDir));
  try {
    const pools = options.pool?.length ? options.pool : ['default'];
    const issued = registry.createProvisioningToken(
      pools,
      'cli',
      new Date(),
      Number(options.ttl),
      Number(options.uses),
    );
    registry.audit('cli', 'worker.provision', undefined, { pools, expiresAt: issued.expiresAt }, new Date());
    process.stderr.write(
      `${pc.green('provisioning token')} for pools ${pools.join(', ')}, ${options.uses} registration(s), expires ${issued.expiresAt}:\n`,
    );
    process.stdout.write(`${issued.token}\n`);
    return EXIT.OK;
  } finally {
    registry.close();
  }
}

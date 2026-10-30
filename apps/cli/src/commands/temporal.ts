import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildServer } from '@spinxsca/server';
import { startTemporalWorker, TemporalDispatcher } from '@spinxsca/temporal';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { openEngine, resolveKbDir, scanDeps } from '../engine';
import { createLogger, EXIT } from '../ui';

export interface TemporalFlags {
  temporalAddress: string;
  temporalNamespace: string;
  temporalTaskQueue: string;
}

/** Prebuilt workflow bundle next to the CLI bundle; absent when running from source (tsx). */
export function workflowBundlePath(): string | undefined {
  const path = join(dirname(fileURLToPath(import.meta.url)), 'temporal-workflows.js');
  return existsSync(path) ? path : undefined;
}

export function connectDispatcher(flags: TemporalFlags, pools: readonly string[]): Promise<TemporalDispatcher> {
  return TemporalDispatcher.connect({
    address: flags.temporalAddress,
    namespace: flags.temporalNamespace,
    taskQueue: flags.temporalTaskQueue,
    pools,
  });
}

/**
 * Extra Temporal worker for a server's data directory (same host or shared volume): it executes the
 * job activities with the registry, project state and knowledge base of that directory.
 */
export async function temporalWorkerCommand(
  options: TemporalFlags & { dataDir: string; config?: string; kbDir?: string; concurrency: string; verbose?: boolean },
): Promise<number> {
  const dataDir = resolve(options.dataDir);
  const loaded = loadConfig(options.config);
  const logger = createLogger(Boolean(options.verbose));
  const kbDir =
    options.kbDir || process.env.SPINXSCA_KB_DIR || loaded.config.knowledge_base?.dir
      ? resolveKbDir(loaded, options.kbDir)
      : join(dataDir, 'kb');
  const built = buildServer({
    dataDir,
    kbDir,
    logger,
    worker: false,
    kbSyncIntervalMinutes: 0,
    ...(process.env.SPINXSCA_DATABASE_URL ? { databaseUrl: process.env.SPINXSCA_DATABASE_URL } : {}),
    engines: ({ sourceDir, stateDir, repo, artifacts }) => {
      const engine = openEngine({
        scanRoot: sourceDir,
        stateDir,
        config: loaded,
        kbDir,
        logger,
        ...(repo ? { repo } : {}),
        ...(artifacts ? { artifacts } : {}),
      });
      return { deps: scanDeps(engine), close: () => engine.close() };
    },
  });
  const bundle = workflowBundlePath();
  const worker = await startTemporalWorker({
    address: options.temporalAddress,
    namespace: options.temporalNamespace,
    taskQueue: options.temporalTaskQueue,
    worker: built.worker,
    logger,
    maxConcurrentActivities: Number(options.concurrency),
    ...(bundle ? { workflowBundlePath: bundle } : {}),
  });
  process.stderr.write(
    `${pc.green('temporal worker')} ${options.temporalAddress} · queue ${options.temporalTaskQueue} · data ${dataDir}\n`,
  );
  await new Promise<void>((done) => {
    process.once('SIGINT', () => done());
    process.once('SIGTERM', () => done());
  });
  await worker.shutdown();
  await built.close();
  return EXIT.OK;
}

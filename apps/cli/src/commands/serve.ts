import { join, resolve } from 'node:path';
import { Registry, type Role, startServer } from '@spinxsca/server';
import { startTemporalWorker } from '@spinxsca/temporal';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { aiOptions } from '../context';
import { openEngine, resolveKbDir, scanDeps } from '../engine';
import { CliError, createLogger, EXIT } from '../ui';
import { gatePolicy } from './gate';
import { connectDispatcher, type TemporalFlags, workflowBundlePath } from './temporal';

interface ServeOptions extends TemporalFlags {
  dataDir: string;
  config?: string;
  kbDir?: string;
  host: string;
  port: string;
  kbSyncInterval: string;
  notifyUrl?: string[];
  publicUrl?: string;
  worker: boolean;
  pool?: string[];
  orchestrator: string;
  secureCookies?: boolean;
  verbose?: boolean;
}

function serverKbDir(dataDir: string, configPath: string | undefined, flag: string | undefined): string {
  const loaded = loadConfig(configPath);
  return flag || process.env.SPINXSCA_KB_DIR || loaded.config.knowledge_base?.dir
    ? resolveKbDir(loaded, flag)
    : join(dataDir, 'kb');
}

export async function serveCommand(options: ServeOptions): Promise<number> {
  const dataDir = resolve(options.dataDir);
  const loaded = loadConfig(options.config);
  const logger = createLogger(Boolean(options.verbose));
  const kbDir = serverKbDir(dataDir, options.config, options.kbDir);
  const ai = loaded.config.ai?.level && loaded.config.ai.level !== 'off' ? aiOptions(loaded, {}) : null;
  const port = Number(options.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new CliError(`invalid --port ${options.port}`);
  const registry = Registry.open(dataDir);
  const hasAdmin = registry.tokens().some((t) => t.role === 'admin' && !t.revokedAt);
  registry.close();
  if (!hasAdmin)
    throw new CliError(
      `no admin token in ${dataDir}; run \`spinxsca server init --data-dir ${options.dataDir}\` first`,
    );
  if (!['internal', 'temporal'].includes(options.orchestrator))
    throw new CliError(`unknown --orchestrator ${options.orchestrator} (internal, temporal)`);
  const temporal = options.orchestrator === 'temporal';
  const dispatcher = temporal
    ? await connectDispatcher(options, [...(options.pool?.length ? options.pool : ['default']), 'control'])
    : undefined;
  const server = await startServer({
    ...(dispatcher ? { dispatcher } : {}),
    dataDir,
    kbDir,
    logger,
    host: options.host,
    port,
    gatePolicy: gatePolicy(loaded.config),
    kbSyncIntervalMinutes: Number(options.kbSyncInterval),
    notifyUrls: options.notifyUrl ?? [],
    ...(process.env.SPINXSCA_NOTIFY_SECRET ? { notifySecret: process.env.SPINXSCA_NOTIFY_SECRET } : {}),
    ...(options.publicUrl ? { publicUrl: options.publicUrl.replace(/\/+$/, '') } : {}),
    ...(options.secureCookies ? { secureCookies: true } : {}),
    worker: options.worker,
    ...(options.pool?.length ? { pools: options.pool } : {}),
    ...(process.env.SPINXSCA_DATABASE_URL ? { databaseUrl: process.env.SPINXSCA_DATABASE_URL } : {}),
    engines: ({ sourceDir, stateDir, repo, artifacts }) => {
      const engine = openEngine({
        scanRoot: sourceDir,
        stateDir,
        config: loaded,
        kbDir,
        logger,
        ...(ai ? { ai } : {}),
        ...(repo ? { repo } : {}),
        ...(artifacts ? { artifacts } : {}),
      });
      return { deps: scanDeps(engine), close: () => engine.close() };
    },
  });
  // With Temporal, this process also hosts the job activities unless --no-worker (then run
  // `spinxsca temporal-worker` against the same data directory).
  const bundle = workflowBundlePath();
  const temporalWorker =
    temporal && options.worker
      ? await startTemporalWorker({
          address: options.temporalAddress,
          namespace: options.temporalNamespace,
          taskQueue: options.temporalTaskQueue,
          worker: server.worker,
          logger,
          ...(bundle ? { workflowBundlePath: bundle } : {}),
        })
      : undefined;
  process.stderr.write(
    `${pc.green('spinxsca server')} listening on ${server.url} · data ${dataDir} · state ${process.env.SPINXSCA_DATABASE_URL ? 'PostgreSQL' : 'SQLite'} · knowledge base ${kbDir}${options.worker ? '' : ' · scan worker disabled'}\n`,
  );
  if (options.host !== '127.0.0.1' && options.host !== 'localhost' && !options.secureCookies) {
    process.stderr.write(
      `${pc.yellow('warning')} listening beyond localhost without --secure-cookies: put the server behind HTTPS\n`,
    );
  }
  await new Promise<void>((resolveStop) => {
    const stop = () => resolveStop();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  process.stderr.write('stopping…\n');
  await temporalWorker?.shutdown();
  await server.close();
  return EXIT.OK;
}

export async function serverInitCommand(options: { dataDir: string; name: string }): Promise<number> {
  return createToken({ dataDir: options.dataDir, name: options.name, role: 'admin' });
}

export async function createToken(options: { dataDir: string; name: string; role: string }): Promise<number> {
  if (!['admin', 'member', 'viewer'].includes(options.role))
    throw new CliError(`unknown role "${options.role}" (admin, member, viewer)`);
  const registry = Registry.open(resolve(options.dataDir));
  try {
    const { token, entry } = registry.createToken(options.name, options.role as Role, new Date());
    registry.audit('cli', 'token.create', entry.tokenId, { name: entry.name, role: entry.role }, new Date());
    process.stderr.write(
      `${pc.green('created')} ${entry.role} token ${entry.tokenId} (${entry.name}); it is shown once:\n`,
    );
    process.stdout.write(`${token}\n`);
    return EXIT.OK;
  } finally {
    registry.close();
  }
}

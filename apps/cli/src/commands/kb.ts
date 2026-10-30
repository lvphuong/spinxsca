import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  exportOsv,
  importOsvFiles,
  type KbSnapshot,
  LocalKnowledgeBase,
  syncEcosystem,
  syncEpss,
  syncKev,
  syncNvd,
  syncPackages,
} from '@spinxsca/kb';
import { DockerSandboxRunner } from '@spinxsca/sandbox';
import { OsvScannerAdapter } from '@spinxsca/scanners';
import { LocalSourceTree } from '@spinxsca/workspace';
import pc from 'picocolors';
import { loadConfig } from '../config';
import type { CommonOptions } from '../context';
import { resolveKbDir } from '../engine';
import { CliError, EXIT, status, table } from '../ui';

function openKb(options: CommonOptions): { kb: LocalKnowledgeBase; dir: string } {
  const dir = resolveKbDir(loadConfig(options.config), options.kbDir);
  return { kb: LocalKnowledgeBase.open(dir), dir };
}

function describeSnapshot(s: KbSnapshot): string {
  return `${s.snapshotId} · ${s.recordCount} advisories · mirrored ${s.ecosystems.join(', ') || 'none'} · ${s.createdAt}`;
}

export async function kbSyncCommand(
  path: string | undefined,
  options: CommonOptions & { ecosystem?: string[]; intel?: string[] },
): Promise<number> {
  const { kb, dir } = openKb(options);
  try {
    const downloadDir = join(dir, 'downloads');
    const onProgress = (m: string) => {
      if (!options.json) status(m);
    };
    const results: Record<string, unknown> = {};
    if (options.ecosystem?.length) {
      for (const ecosystem of options.ecosystem)
        results[ecosystem] = await syncEcosystem(kb.store, ecosystem, { downloadDir, onProgress });
    }
    if (path) {
      onProgress(`extracting dependency inventory from ${resolve(path)}`);
      const work = mkdtempSync(join(tmpdir(), 'spinxsca-inventory-'));
      try {
        const packages = await new OsvScannerAdapter({ database: kb }).inventory({
          source: new LocalSourceTree(path),
          sandbox: new DockerSandboxRunner(),
          workDir: work,
        });
        if (packages.length === 0) onProgress('no dependency manifests found');
        else results.project = await syncPackages(kb.store, packages, { onProgress });
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    }
    const intel = new Set(
      (options.intel ?? [])
        .flatMap((v) => v.split(','))
        .map((v) => v.trim().toLowerCase())
        .filter(Boolean),
    );
    for (const name of intel)
      if (!['kev', 'epss', 'nvd'].includes(name))
        throw new CliError(`unknown intelligence source "${name}" (expected kev, epss, nvd)`);
    if (!options.ecosystem?.length && !path && intel.size === 0) {
      const sources = kb.store.sources();
      if (sources.length === 0) {
        throw new CliError(
          'nothing to refresh; pass --ecosystem <name> to mirror an ecosystem or a project path to sync its packages',
        );
      }
      for (const source of sources) {
        if (source.kind === 'osv-ecosystem' && source.ecosystem) {
          results[source.ecosystem] = await syncEcosystem(kb.store, source.ecosystem, { downloadDir, onProgress });
        } else if (source.kind === 'osv-api') {
          results.packages = await syncPackages(kb.store, kb.store.coveredPackages('osv:api'), { onProgress });
        } else if (source.kind.startsWith('intel-')) {
          intel.add(source.kind.slice('intel-'.length));
        }
      }
    }
    // Intelligence after advisories: EPSS and NVD keep only CVEs the advisories reference.
    if (intel.has('kev')) results.kev = await syncKev(kb.store, { onProgress });
    if (intel.has('epss')) results.epss = await syncEpss(kb.store, { onProgress });
    if (intel.has('nvd')) {
      const apiKey = process.env.NVD_API_KEY;
      if (!apiKey)
        onProgress('NVD_API_KEY is not set: NVD allows 5 requests per 30 s, a first sync takes several minutes');
      results.nvd = await syncNvd(kb.store, { onProgress, ...(apiKey ? { apiKey } : {}) });
    }
    const snapshot = kb.store.createSnapshot();
    if (options.json) process.stdout.write(`${JSON.stringify({ results, snapshot }, null, 2)}\n`);
    else process.stdout.write(`${pc.green('snapshot')} ${describeSnapshot(snapshot)}\n`);
    return EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbStatusCommand(options: CommonOptions): Promise<number> {
  const { kb, dir } = openKb(options);
  try {
    const stats = kb.store.stats();
    const latest = kb.store.latestSnapshot();
    const sources = kb.store.sources();
    if (options.json) {
      process.stdout.write(`${JSON.stringify({ dir, stats, latest: latest ?? null, sources }, null, 2)}\n`);
      return EXIT.OK;
    }
    const lines = [
      `${pc.bold('Knowledge base')} ${dir}`,
      `${pc.dim('records')}  ${stats.records} (${stats.revisions} revisions) · ${stats.intelRevisions} intelligence revisions · ${stats.snapshots} snapshots`,
      `${pc.dim('latest')}   ${latest ? describeSnapshot(latest) : 'none (run `spinxsca kb sync`)'}`,
    ];
    if (sources.length) {
      lines.push(
        '',
        table(
          ['SOURCE', 'KIND', 'SYNCED', 'RECORDS'],
          sources.map((s) => [s.sourceId, s.kind, s.syncedAt ?? '-', String(s.records)]),
        ),
      );
    }
    process.stdout.write(`${lines.join('\n')}\n`);
    return EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbSnapshotsCommand(options: CommonOptions): Promise<number> {
  const { kb } = openKb(options);
  try {
    const snapshots = kb.store.snapshots();
    if (options.json) process.stdout.write(`${JSON.stringify(snapshots, null, 2)}\n`);
    else if (snapshots.length === 0) process.stdout.write('No snapshots.\n');
    else
      process.stdout.write(
        `${table(
          ['SNAPSHOT', 'ADVISORIES', 'MIRRORED', 'CREATED'],
          snapshots.map((s) => [s.snapshotId, String(s.recordCount), s.ecosystems.join(',') || '-', s.createdAt]),
        )}\n`,
      );
    return EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbLookupCommand(id: string, options: CommonOptions & { snapshot?: string }): Promise<number> {
  const { kb } = openKb(options);
  try {
    const snapshot = options.snapshot ? kb.store.snapshot(options.snapshot) : undefined;
    if (options.snapshot && !snapshot) throw new CliError(`snapshot ${options.snapshot} not found`);
    const found = kb.store.lookup(id, snapshot);
    if (!found) throw new CliError(`${id} not found in the knowledge base`);
    if (options.json) {
      process.stdout.write(`${JSON.stringify(found.record, null, 2)}\n`);
      return EXIT.OK;
    }
    const r = found.record;
    const lines = [
      `${pc.bold(r.id)} ${r.summary ?? ''}`,
      `${pc.dim('aliases')}   ${(r.aliases ?? []).join(', ') || '-'}`,
      `${pc.dim('severity')}  ${r.database_specific?.severity ?? '-'} ${(r.severity ?? []).map((s) => `${s.type} ${s.score}`).join(' ')}`,
      `${pc.dim('cwe')}       ${(r.database_specific?.cwe_ids ?? []).join(', ') || '-'}`,
      `${pc.dim('modified')}  ${r.modified ?? '-'}${r.withdrawn ? pc.yellow(` · withdrawn ${r.withdrawn}`) : ''}`,
      `${pc.dim('source')}    ${found.sourceId}`,
      ...(r.affected ?? []).map(
        (a) =>
          `${pc.dim('affects')}   ${a.package?.ecosystem}/${a.package?.name} ${(a.ranges ?? [])
            .map((x) =>
              x.events
                .map((e) =>
                  Object.entries(e)
                    .map(([k, v]) => `${k} ${v}`)
                    .join(' '),
                )
                .join(', '),
            )
            .join('; ')}`,
      ),
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
    return EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbImportCommand(
  paths: string[],
  options: CommonOptions & { authoritativeFor?: string; name?: string },
): Promise<number> {
  const { kb } = openKb(options);
  try {
    const stats = importOsvFiles(
      kb.store,
      paths.map((p) => resolve(p)),
      {
        ...(options.name ? { sourceName: options.name } : {}),
        ...(options.authoritativeFor
          ? { authoritativeFor: options.authoritativeFor.split(',').map((s) => s.trim()) }
          : {}),
      },
    );
    const snapshot = kb.store.createSnapshot();
    if (options.json) process.stdout.write(`${JSON.stringify({ stats, snapshot }, null, 2)}\n`);
    else
      process.stdout.write(
        `${pc.green('imported')} ${stats.added} new, ${stats.updated} updated, ${stats.unchanged} unchanged, ${stats.invalid} invalid from ${stats.files} file(s)\n${pc.green('snapshot')} ${describeSnapshot(snapshot)}\n`,
      );
    return stats.invalid > 0 ? EXIT.POLICY_FAILED : EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbExportCommand(
  outDir: string,
  options: CommonOptions & { snapshot?: string; ecosystem?: string[] },
): Promise<number> {
  const { kb } = openKb(options);
  try {
    const snapshot = options.snapshot ? kb.store.snapshot(options.snapshot) : kb.store.latestSnapshot();
    if (!snapshot) throw new CliError('no snapshot to export');
    const count = exportOsv(kb.store, snapshot, resolve(outDir), options.ecosystem);
    process.stdout.write(
      `${pc.green('exported')} ${count} OSV records of ${snapshot.snapshotId} to ${resolve(outDir)}\n`,
    );
    return EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbBundleKeygenCommand(options: { out: string }): Promise<number> {
  const { generateSigningKey } = await import('@spinxsca/kb');
  const dir = resolve(options.out);
  mkdirSync(dir, { recursive: true });
  const key = generateSigningKey();
  const privatePath = join(dir, 'kb-signing.key');
  if (existsSync(privatePath)) throw new CliError(`${privatePath} exists; refusing to overwrite a signing key`);
  writeFileSync(privatePath, key.privateKeyPem, { mode: 0o600 });
  writeFileSync(join(dir, 'kb-signing.pub'), key.publicKeyPem);
  process.stdout.write(
    `${pc.green('key')} ${key.keyId}: private ${privatePath} (mode 600), public ${join(dir, 'kb-signing.pub')}\n`,
  );
  return EXIT.OK;
}

export async function kbBundleExportCommand(
  options: CommonOptions & { out: string; signKey: string; snapshot?: string },
): Promise<number> {
  const { exportBundle } = await import('@spinxsca/kb');
  const { kb } = openKb(options);
  try {
    const snapshot = options.snapshot ? kb.store.snapshot(options.snapshot) : kb.store.latestSnapshot();
    if (!snapshot)
      throw new CliError(
        options.snapshot
          ? `snapshot ${options.snapshot} not found`
          : 'the knowledge base has no snapshot; run `spinxsca kb sync` first',
      );
    const bundle = exportBundle(kb.store, snapshot, readFileSync(resolve(options.signKey), 'utf8'));
    writeFileSync(resolve(options.out), bundle);
    process.stdout.write(
      `${pc.green('bundle')} ${resolve(options.out)} · ${describeSnapshot(snapshot)} · ${(bundle.length / 1048576).toFixed(1)} MB\n`,
    );
    return EXIT.OK;
  } finally {
    kb.close();
  }
}

export async function kbBundleImportCommand(
  file: string,
  options: CommonOptions & { trustKey: string[] },
): Promise<number> {
  const { importBundle } = await import('@spinxsca/kb');
  const { kb } = openKb(options);
  try {
    const keys = options.trustKey.map((k) => readFileSync(resolve(k), 'utf8'));
    const { snapshot, header, added } = importBundle(kb.store, readFileSync(resolve(file)), keys);
    if (options.json) process.stdout.write(`${JSON.stringify({ snapshot, header, added }, null, 2)}\n`);
    else
      process.stdout.write(
        `${pc.green('verified')} signed by ${header.keyId} · ${describeSnapshot(snapshot)} · ${added} advisories added\n`,
      );
    return EXIT.OK;
  } catch (err) {
    throw new CliError((err as Error).message);
  } finally {
    kb.close();
  }
}

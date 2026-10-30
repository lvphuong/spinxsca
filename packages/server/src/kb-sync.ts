import { join } from 'node:path';
import { syncEcosystem, syncEpss, syncKev, syncNvd, syncPackages } from '@spinxsca/kb';
import type { KbSyncFn } from './worker';

export interface DefaultKbSyncOptions {
  /** OSV ecosystems to mirror in full (in addition to the packages of registered projects). */
  ecosystems?: readonly string[];
  intel?: ReadonlyArray<'kev' | 'epss' | 'nvd'>;
  nvdApiKey?: string;
  fetch?: typeof fetch;
}

/** Default refresh: OSV advisories for every package any project depends on, mirrored ecosystems, then intelligence. */
export function defaultKbSync(options: DefaultKbSyncOptions = {}): KbSyncFn {
  return async (kb, { inventories, logger }) => {
    const onProgress = (m: string) => logger.info(m);
    const http = options.fetch ? { fetch: options.fetch } : {};
    const result: Record<string, unknown> = {};
    for (const ecosystem of options.ecosystems ?? []) {
      result[`ecosystem:${ecosystem}`] = await syncEcosystem(kb.store, ecosystem, {
        downloadDir: join(kb.store.dir, 'downloads'),
        onProgress,
        ...http,
      });
    }
    const packages = [
      ...new Map(
        inventories
          .flatMap((i) => i.packages)
          .map((p) => [`${p.ecosystem}\u0000${p.name}`, { ecosystem: p.ecosystem, name: p.name }]),
      ).values(),
    ];
    if (packages.length) result.packages = await syncPackages(kb.store, packages, { onProgress, ...http });
    const intel = new Set(options.intel ?? ['kev', 'epss']);
    if (intel.has('kev')) result.kev = await syncKev(kb.store, { onProgress, ...http });
    if (intel.has('epss')) result.epss = await syncEpss(kb.store, { onProgress, ...http });
    if (intel.has('nvd'))
      result.nvd = await syncNvd(kb.store, {
        onProgress,
        ...http,
        ...(options.nvdApiKey ? { apiKey: options.nvdApiKey } : {}),
      });
    return result;
  };
}

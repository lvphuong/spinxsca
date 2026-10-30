import { z } from 'zod';

/**
 * Loose view of an OSV record (https://ossf.github.io/osv-schema/). Records are stored verbatim; only
 * the fields needed for indexing are parsed, unknown fields pass through untouched.
 */
export const OsvRecord = z.looseObject({
  id: z.string().min(1),
  modified: z.string().optional(),
  published: z.string().optional(),
  withdrawn: z.string().optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  severity: z.array(z.looseObject({ type: z.string(), score: z.string() })).optional(),
  affected: z
    .array(
      z.looseObject({
        package: z.looseObject({ ecosystem: z.string().optional(), name: z.string().optional() }).optional(),
        ranges: z
          .array(z.looseObject({ type: z.string(), events: z.array(z.record(z.string(), z.string())) }))
          .optional(),
        versions: z.array(z.string()).optional(),
      }),
    )
    .optional(),
  database_specific: z
    .looseObject({ severity: z.string().optional(), cwe_ids: z.array(z.string()).optional() })
    .optional(),
});
export type OsvRecord = z.infer<typeof OsvRecord>;

/** "Debian:12" -> "Debian"; language ecosystems are returned unchanged. */
export function baseEcosystem(ecosystem: string): string {
  return ecosystem.split(':')[0] ?? ecosystem;
}

/** Package name normalization used for coverage lookups (PEP 503 for PyPI). */
export function normalizePackageName(ecosystem: string, name: string): string {
  const eco = baseEcosystem(ecosystem);
  if (eco === 'PyPI') return name.toLowerCase().replace(/[-_.]+/g, '-');
  if (eco === 'npm') return name.toLowerCase();
  return name;
}

export function affectedPackages(record: OsvRecord): Array<{ ecosystem: string; name: string }> {
  const seen = new Map<string, { ecosystem: string; name: string }>();
  for (const affected of record.affected ?? []) {
    const ecosystem = affected.package?.ecosystem;
    const name = affected.package?.name;
    if (!ecosystem || !name) continue;
    const eco = baseEcosystem(ecosystem);
    const key = `${eco}\u0000${normalizePackageName(eco, name)}`;
    seen.set(key, { ecosystem: eco, name: normalizePackageName(eco, name) });
  }
  return [...seen.values()];
}

/** Fixed versions for one package, for remediation messages. */
export function fixedVersions(record: OsvRecord, ecosystem: string, name: string): string[] {
  const wanted = normalizePackageName(ecosystem, name);
  const out = new Set<string>();
  for (const affected of record.affected ?? []) {
    const pkg = affected.package;
    if (!pkg?.name || !pkg.ecosystem) continue;
    if (
      baseEcosystem(pkg.ecosystem) !== baseEcosystem(ecosystem) ||
      normalizePackageName(ecosystem, pkg.name) !== wanted
    )
      continue;
    for (const range of affected.ranges ?? []) {
      if (range.type === 'GIT') continue;
      for (const event of range.events) if (event.fixed) out.add(event.fixed);
    }
  }
  return [...out];
}

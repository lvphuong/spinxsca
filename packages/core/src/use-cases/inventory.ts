import type { ArtifactStore, ScanRepository } from '../ports';

export interface InventoryPackage {
  ecosystem: string;
  name: string;
  version: string;
  purl: string;
}

/**
 * Dependency inventory of a scan, read from the CycloneDX SBOM the dependency scanner stored. Used to
 * find which projects a new advisory concerns without re-running any analysis.
 */
export async function dependencyInventory(
  repo: ScanRepository,
  artifacts: ArtifactStore,
  scanId: string,
): Promise<InventoryPackage[] | undefined> {
  const task = (await repo.listTasks(scanId)).find((t) => t.scannerId === 'osv-scanner' && t.outputDigest);
  if (!task?.outputDigest || !(await artifacts.has(task.outputDigest))) return undefined;
  const output = JSON.parse(await artifacts.getText(task.outputDigest)) as {
    rawArtifacts?: { sbom?: { digest: `sha256:${string}` } };
  };
  const digest = output.rawArtifacts?.sbom?.digest;
  if (!digest || !(await artifacts.has(digest))) return undefined;
  const sbom = JSON.parse(await artifacts.getText(digest)) as {
    components?: Array<{
      group?: string;
      name: string;
      version?: string;
      purl?: string;
      properties?: Array<{ name: string; value: string }>;
    }>;
  };
  const out: InventoryPackage[] = [];
  for (const c of sbom.components ?? []) {
    const ecosystem = c.properties?.find((p) => p.name === 'spinxsca:ecosystem')?.value;
    if (!ecosystem) continue;
    out.push({
      ecosystem,
      name: c.group ? `${c.group}:${c.name}` : c.name,
      version: c.version ?? '',
      purl: c.purl ?? '',
    });
  }
  return out;
}

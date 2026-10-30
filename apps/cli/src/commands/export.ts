import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { type CommonOptions, withEngine } from '../context';
import { type ExportFormat, renderExport, sbomFor } from '../engine';
import { CliError, EXIT, status } from '../ui';

const FORMATS: ExportFormat[] = ['sarif', 'json', 'md', 'csv', 'cyclonedx', 'pr-comment'];

async function latestScanId(
  engine: Parameters<Parameters<typeof withEngine>[2]>[0],
  explicit?: string,
): Promise<string> {
  if (explicit) return explicit;
  const project = await engine.repo.getProject();
  const scan = project ? await engine.repo.latestScan(project.project.projectId, ['COMPLETED', 'PARTIAL']) : undefined;
  if (!scan) throw new CliError('no completed scan found; run `spinxsca scan` first');
  return scan.scanId;
}

export async function exportCommand(
  path: string | undefined,
  options: CommonOptions & { format: string; scan?: string; out?: string },
): Promise<number> {
  const format = options.format as ExportFormat;
  if (!FORMATS.includes(format))
    throw new CliError(`unknown format "${options.format}" (expected ${FORMATS.join(', ')})`);
  return withEngine(path, options, async (engine) => {
    const scanId = await latestScanId(engine, options.scan);
    const content = await renderExport(engine, scanId, format);
    if (options.out) {
      writeFileSync(resolve(options.out), content);
      status(`wrote ${format} for ${scanId} to ${resolve(options.out)}`);
    } else process.stdout.write(content);
    return EXIT.OK;
  });
}

export async function sbomCommand(
  path: string | undefined,
  options: CommonOptions & { scan?: string; out?: string },
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const scanId = await latestScanId(engine, options.scan);
    const content = await sbomFor(engine, scanId);
    if (options.out) {
      writeFileSync(resolve(options.out), content);
      status(`wrote CycloneDX SBOM for ${scanId} to ${resolve(options.out)}`);
    } else process.stdout.write(content);
    return EXIT.OK;
  });
}

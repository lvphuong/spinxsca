/**
 * Writes JSON Schema files for every public artifact schema to packages/schemas/json/.
 * Run with `pnpm schemas:export`.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import * as schemas from '../src/index';

const exported: Record<string, z.ZodType> = {
  'analysis-manifest': schemas.AnalysisManifest,
  'source-snapshot': schemas.SourceSnapshot,
  coverage: schemas.Coverage,
  evidence: schemas.Evidence,
  'finding-candidate': schemas.FindingCandidate,
  finding: schemas.Finding,
  'finding-occurrence': schemas.FindingOccurrence,
  'finding-assessment': schemas.FindingAssessment,
  disposition: schemas.Disposition,
  'finding-match-event': schemas.FindingMatchEvent,
  'scan-run': schemas.ScanRun,
  'scan-task': schemas.ScanTask,
  'scanner-capability': schemas.ScannerCapability,
  'spinxsca-config': schemas.SpinxscaConfig,
  'eval-case': schemas.EvalCase,
};

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'json');
mkdirSync(outDir, { recursive: true });
for (const [name, schema] of Object.entries(exported)) {
  const json = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' });
  writeFileSync(join(outDir, `${name}.schema.json`), `${JSON.stringify(json, null, 2)}\n`);
}
console.log(`wrote ${Object.keys(exported).length} schemas to ${outDir}`);

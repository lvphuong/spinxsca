import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { generateScaleFixture } from '../apps/cli/src/eval/scale-fixture';

/**
 * Generates a synthetic large repository for manual scale runs (ADR-055):
 *   pnpm tsx scripts/gen-scale-fixture.ts --files 2000 --loc 300000 --planted 40 --seed 7 --out /tmp/scale
 * then `pnpm spinxsca scan /tmp/scale --ai standard --ai-provider scripted --shards on --json`.
 * The CI suite (`evals/scale`) generates a smaller fixture through the eval harness instead.
 */
function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? (process.argv[i + 1] as string) : fallback;
}

const out = resolve(arg('out', '/tmp/spinxsca-scale'));
const options = {
  files: Number(arg('files', '2000')),
  loc: Number(arg('loc', '300000')),
  planted: Number(arg('planted', '40')),
  seed: Number(arg('seed', '7')),
};
mkdirSync(out, { recursive: true });
const fixture = generateScaleFixture(out, options);
writeFileSync(
  join(out, 'case.yaml'),
  // JSON is valid YAML, so the case file needs no extra dependency.
  JSON.stringify(
    {
      id: 'scale-synthetic',
      title: `Synthetic ${fixture.files}-file repository`,
      languages: ['javascript', 'typescript', 'python'],
      source: '.',
      findings: fixture.planted.map((p) => ({
        id: p.id,
        category: p.category,
        cwe: p.cwe,
        path: p.path,
        lines: p.lines,
        detectable_by: ['ai'],
        min_phase: 7,
        family: p.family,
        notes: p.kind,
      })),
      negatives: fixture.negatives,
    },
    null,
    2,
  ),
);
process.stdout.write(
  `${out}: ${fixture.files} files, ${fixture.loc} lines, ${fixture.planted.length} planted finding(s)\n`,
);

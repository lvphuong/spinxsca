import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { loadPromptBundle } from '@spinxsca/agent';
import { ENGINE_PHASE, ENGINE_VERSION, FINGERPRINT_ALGORITHM } from '@spinxsca/core';
import { LocalKnowledgeBase } from '@spinxsca/kb';
import { DockerSandboxRunner } from '@spinxsca/sandbox';
import { imageRef, loadRuleBundle, PINNED_IMAGES } from '@spinxsca/scanners';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { resolveKbDir } from '../engine';
import { bundleSpecs, resolvePromptsDir, resolveRulesRoot } from '../rules';
import { EXIT } from '../ui';

export async function infoCommand(options: { json?: boolean; config?: string; kbDir?: string }): Promise<number> {
  const rulesRoot = resolveRulesRoot();
  const bundles = await Promise.all(bundleSpecs(rulesRoot, []).map((b) => loadRuleBundle(b.id, b.dir)));
  const images = Object.entries(PINNED_IMAGES).map(([id, image]) => ({ id, image: imageRef(image) }));
  const sandbox = new DockerSandboxRunner();
  const preflight = await sandbox.preflight(imageRef(PINNED_IMAGES.semgrep));
  const missing: string[] = [];
  for (const image of images.slice(1)) {
    const check = await sandbox.preflight(image.image);
    if (!check.checks.find((c) => c.name === 'scanner image')?.ok) missing.push(image.id);
  }
  const prompts = loadPromptBundle(resolvePromptsDir());
  const kbDir = resolveKbDir(loadConfig(options.config), options.kbDir);
  let latest: ReturnType<LocalKnowledgeBase['store']['latestSnapshot']>;
  if (existsSync(join(kbDir, 'kb.db'))) {
    const kb = LocalKnowledgeBase.open(kbDir);
    latest = kb.store.latestSnapshot();
    kb.close();
  }
  const info = {
    engineVersion: ENGINE_VERSION,
    phase: ENGINE_PHASE,
    node: process.version,
    fingerprintAlgorithm: FINGERPRINT_ALGORITHM,
    scanners: images,
    imagesNotPulled: missing,
    ruleBundles: bundles.map((b) => ({ ...b.ref, dir: b.dir, rules: b.ruleIds })),
    promptBundle: { dir: prompts.dir, digest: prompts.digest },
    knowledgeBase: { dir: kbDir, latestSnapshot: latest ?? null },
    sandbox: preflight,
  };
  if (options.json) {
    process.stdout.write(`${JSON.stringify(info, null, 2)}\n`);
    return preflight.ok ? EXIT.OK : EXIT.ERROR;
  }
  const lines = [
    `${pc.bold('spinxsca')} ${ENGINE_VERSION} (phase ${ENGINE_PHASE}) · node ${process.version}`,
    `${pc.dim('fingerprint')} ${FINGERPRINT_ALGORITHM}`,
    ...images.map(
      (i) =>
        `${pc.dim('scanner')}     ${i.id.padEnd(12)} ${i.image}${missing.includes(i.id) ? pc.yellow(' (not pulled yet)') : ''}`,
    ),
    ...bundles.map((b) => `${pc.dim('rules')}       ${b.ref.id} · ${b.ref.ruleCount} rules · ${b.ref.digest}`),
    `${pc.dim('prompts')}     ${prompts.digest}`,
    `${pc.dim('kb')}          ${kbDir} · ${latest ? `${latest.snapshotId} (${latest.recordCount} advisories, mirrored ${latest.ecosystems.join(', ') || 'none'})` : pc.yellow('empty, run `spinxsca kb sync`')}`,
    '',
    pc.bold(`Sandbox preflight (${preflight.runtime}${preflight.version ? ` ${preflight.version}` : ''})`),
    ...preflight.checks.map(
      (c) =>
        `  ${c.ok ? pc.green('✓') : c.name === 'scanner image' ? pc.yellow('!') : pc.red('✗')} ${c.name.padEnd(22)} ${pc.dim(c.detail)}`,
    ),
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
  return preflight.ok ? EXIT.OK : EXIT.ERROR;
}

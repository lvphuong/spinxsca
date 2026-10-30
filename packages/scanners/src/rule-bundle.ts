import { readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { sha256 } from '@spinxsca/core';
import type { RuleBundleRef } from '@spinxsca/schemas';
import { parse } from 'yaml';

export interface LoadedRuleBundle {
  ref: RuleBundleRef;
  /** Absolute host directory mounted read-only into the scanner container. */
  dir: string;
  /** Rule ids as written in the YAML files. */
  ruleIds: string[];
  languages: string[];
}

/**
 * A rule bundle is a directory of Semgrep YAML files. Its digest covers every rule file (path and
 * content), so any rule edit changes the Analysis Manifest (ADR-003).
 */
export async function loadRuleBundle(id: string, dir: string): Promise<LoadedRuleBundle> {
  const files = (await listYaml(dir)).sort();
  const parts: string[] = [];
  const ruleIds: string[] = [];
  const languages = new Set<string>();
  for (const file of files) {
    const content = await readFile(file, 'utf8');
    const rel = relative(dir, file).split(sep).join('/');
    parts.push(`${rel}\u0000${content}`);
    const doc = parse(content) as { rules?: Array<{ id?: string; languages?: string[] }> } | null;
    for (const rule of doc?.rules ?? []) {
      if (!rule.id) throw new Error(`rule without id in ${rel}`);
      ruleIds.push(rule.id);
      for (const language of rule.languages ?? []) languages.add(language);
    }
  }
  if (ruleIds.length === 0) throw new Error(`rule bundle ${id} at ${dir} contains no rules`);
  const duplicate = ruleIds.find((rule, i) => ruleIds.indexOf(rule) !== i);
  if (duplicate) throw new Error(`duplicate rule id ${duplicate} in bundle ${id}`);
  const digest = sha256(parts.join('\n'));
  return {
    ref: { id, version: digest.slice('sha256:'.length, 'sha256:'.length + 12), digest, ruleCount: ruleIds.length },
    dir,
    ruleIds: ruleIds.sort(),
    languages: [...languages].sort(),
  };
}

async function listYaml(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await listYaml(path)));
    else if (entry.isFile() && /\.ya?ml$/.test(entry.name)) out.push(path);
  }
  return out;
}

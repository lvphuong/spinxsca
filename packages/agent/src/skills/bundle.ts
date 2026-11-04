import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256 } from '@spinxsca/core';
import type { Digest } from '@spinxsca/schemas';
import { z } from 'zod';
import { parseFrontMatter } from '../personas/loader';

export const SkillMeta = z.strictObject({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/),
  description: z.string().min(1).max(400),
  /** Tools the playbook expects; a persona sees the skill only if it holds all of them. */
  allowed_tools: z.array(z.string()).default([]),
  /** Finding categories the playbook applies to (for suggestions). */
  categories: z.array(z.string()).default([]),
});
export type SkillMeta = z.infer<typeof SkillMeta>;

export interface Skill {
  meta: SkillMeta;
  body: string;
}

export interface SkillBundle {
  digest: Digest;
  skills: Map<string, Skill>;
  /** Skills a persona may load: listed in its manifest and covered by its tools. */
  forPersona(skillIds: readonly string[], tools: readonly string[]): Skill[];
  /** One line per skill for the system prompt (progressive disclosure: bodies load on demand). */
  index(skills: readonly Skill[]): string;
}

/** Loads `playbooks/<id>/SKILL.md` (ADR-046). */
export function loadSkills(dir: string): SkillBundle {
  const skills = new Map<string, Skill>();
  const parts: string[] = [];
  if (existsSync(dir)) {
    for (const id of readdirSync(dir).sort()) {
      const file = join(dir, id, 'SKILL.md');
      if (!existsSync(file)) continue;
      const text = readFileSync(file, 'utf8');
      parts.push(`${id}\u0000${text}`);
      const { meta, body } = parseFrontMatter(text);
      const parsed = SkillMeta.parse(meta);
      if (parsed.name !== id) throw new Error(`skill ${parsed.name} must live in ${id}/SKILL.md`);
      skills.set(id, { meta: parsed, body: body.trim() });
    }
  }
  return {
    digest: sha256(parts.join('\n')),
    skills,
    forPersona(skillIds, tools) {
      const held = new Set(tools);
      return skillIds
        .map((id) => skills.get(id))
        .filter((s): s is Skill => Boolean(s?.meta.allowed_tools.every((t) => held.has(t))));
    },
    index(list) {
      return list.map((s) => `- ${s.meta.name}: ${s.meta.description}`).join('\n');
    },
  };
}

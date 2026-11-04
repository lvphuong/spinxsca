import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';
import type { Skill } from './bundle';

/** `load_skill`: returns a playbook body on demand, only from the persona's own skill list. */
export function createSkillTool(skills: readonly Skill[]): AgentTool<{ name: string }> {
  const byName = new Map(skills.map((s) => [s.meta.name, s]));
  return defineTool({
    name: 'load_skill',
    description: `Load a playbook with step-by-step guidance. Available: ${[...byName.keys()].join(', ') || '(none)'}.`,
    input: z.strictObject({ name: z.string().min(1) }),
    risk: 'READ',
    run: async ({ name }) => {
      const skill = byName.get(name);
      if (!skill) return `No playbook named ${name}. Available: ${[...byName.keys()].join(', ') || '(none)'}.`;
      return `# Playbook: ${skill.meta.name}\n\n${skill.body}`;
    },
  });
}

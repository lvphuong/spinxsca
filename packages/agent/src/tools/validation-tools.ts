import type { ValidationPort } from '@spinxsca/core';
import { type ActionTarget, PocOracle } from '@spinxsca/schemas';
import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';

/** PoC tools of the exploit persona (ADR-045). The host oracle, not the agent, decides the outcome. */
export function createValidationTools(o: {
  port: ValidationPort;
  interpreters: Readonly<Record<string, string>>;
  onRun?: (handle: string) => Promise<void>;
}): AgentTool<never>[] {
  const ws = z.string().regex(/^ws-[a-z0-9-]+$/);
  return [
    defineTool({
      name: 'harness_write',
      description:
        'Write a file of your PoC harness into the validation workspace (under harness/). The code under test is at ../src relative to harness/.',
      input: z.strictObject({
        workspaceId: ws,
        path: z.string().min(1).max(200).describe('Path inside harness/, e.g. poc.js'),
        content: z.string().min(1).max(20_000),
      }),
      risk: 'WRITE_WORKSPACE',
      targets: ({ workspaceId, path }) => [
        { kind: 'workspace_path', value: `${workspaceId}/harness/${path.replace(/^harness\//, '')}` } as ActionTarget,
      ],
      describe: ({ path, content }) => ({
        title: `Write the PoC harness file ${path}`,
        summary: 'Stays in a sandbox workspace copy; nothing in the repository changes.',
        diff: content
          .split('\n')
          .slice(0, 80)
          .map((l) => `+${l}`)
          .join('\n'),
      }),
      run: async ({ workspaceId, path, content }) => {
        await o.port.writeHarness(workspaceId, path, content);
        return `Wrote harness/${path.replace(/^harness\//, '')} (${content.length} characters).`;
      },
    }) as AgentTool<never>,
    defineTool({
      name: 'validation_run',
      description:
        'Run your harness in the sandbox (no network) twice: attack (SPX_MODE=attack) and control (SPX_MODE=control), each with its own SPX_NONCE. The host oracle decides whether the vulnerability was demonstrated.',
      input: z.strictObject({
        handle: z.string().regex(/^CF-\d+$/),
        workspaceId: ws,
        command: z.array(z.string().min(1).max(200)).min(2).max(6).describe('e.g. ["node", "harness/poc.js"]'),
        oracle: PocOracle,
      }),
      risk: 'EXEC_REPO_CODE',
      idempotent: false,
      targets: ({ handle, workspaceId }) => [
        { kind: 'handle', value: handle },
        { kind: 'workspace_path', value: workspaceId },
      ],
      sandbox: ({ command }) => ({
        network: 'none',
        image: o.interpreters[command[0] ?? ''] ?? 'unknown',
        profile: 'validation',
      }),
      describe: ({ handle, command, oracle }) => ({
        title: `Run a proof of concept for ${handle} in the sandbox`,
        summary: `${command.join(' ')} · oracle ${oracle} · no network, workspace copy, time limited`,
      }),
      run: async (input, { signal }) => {
        await o.onRun?.(input.handle);
        const r = await o.port.run({ ...input, ...(signal ? { signal } : {}) });
        return [
          `Host decision: ${r.outcome} — ${r.detail}`,
          `attack marker: ${r.attackTriggered ? 'seen' : 'not seen'}; control marker: ${r.controlTriggered ? 'seen' : 'not seen'}`,
          ...(r.lintProblems.length ? [`Harness problems: ${r.lintProblems.join('; ')}`] : []),
          '--- attack run ---',
          r.attackLog,
          '--- control run ---',
          r.controlLog,
        ].join('\n');
      },
    }) as AgentTool<never>,
  ];
}

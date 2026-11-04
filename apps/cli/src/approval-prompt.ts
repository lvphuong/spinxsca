import { createInterface } from 'node:readline/promises';
import type { HumanApprover } from '@spinxsca/agent';
import type { GrantScope } from '@spinxsca/schemas';
import pc from 'picocolors';

const EFFECT: Record<string, string> = {
  sandbox: 'runs in the sandbox (no network, copy of the code)',
  workspace: 'writes to a workspace copy, not your repository',
  repository: pc.bold('changes your repository'),
  external: pc.bold('acts on an external system'),
  governance: pc.bold('changes how findings are judged'),
};

/**
 * Interactive approver for attended runs (ADR-041): shows the action as the host describes it and
 * asks for a decision. Grants beyond "once" are offered only when the policy allows them; human-only
 * requests can only be approved once. Without a TTY it answers nothing, so the request parks.
 */
export function ttyApprover(
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stderr,
): HumanApprover {
  let queue: Promise<unknown> = Promise.resolve();
  return (request) => {
    const ask = async () => {
      if (!(input as { isTTY?: boolean }).isTTY) return undefined;
      const lines = [
        '',
        pc.bold(pc.yellow('Approval needed')),
        `  ${request.title}`,
        `  tool ${request.tool} · risk ${request.risk} · ${EFFECT[request.effect] ?? request.effect}`,
        ...(request.humanOnly ? [pc.red('  human decision required (cannot be delegated or remembered)')] : []),
        ...(request.flags.includes('protectedTouched')
          ? [pc.red('  touches a protected file (CI, build, auth or container configuration)')]
          : []),
        ...(request.targets.length ? [`  targets: ${request.targets.map((t) => t.value).join(', ')}`] : []),
        ...(request.summary ? [`  ${request.summary}`] : []),
        pc.dim(
          request.argsPreview
            .split('\n')
            .slice(0, 20)
            .map((l) => `    ${l}`)
            .join('\n'),
        ),
        ...(request.diff
          ? [
              request.diff
                .split('\n')
                .slice(0, 60)
                .map((l) => (l.startsWith('+') ? pc.green(l) : l.startsWith('-') ? pc.red(l) : l))
                .join('\n'),
            ]
          : []),
      ];
      output.write(`${lines.join('\n')}\n`);
      type Choice = [key: string, label: string, value: GrantScope | 'deny' | 'park'];
      const choices: Choice[] = [['y', 'yes, once', 'once']];
      if (request.offeredGrants.includes('case')) choices.push(['c', 'yes, for this case', 'case']);
      if (request.offeredGrants.includes('standing')) choices.push(['s', 'yes, always for this target', 'standing']);
      choices.push(['n', 'no', 'deny'], ['p', 'decide later (inbox)', 'park']);
      const rl = createInterface({ input, output });
      try {
        const answer = (await rl.question(`  ${choices.map(([k, label]) => `[${k}] ${label}`).join('  ')} › `))
          .trim()
          .toLowerCase();
        const choice = choices.find(([k]) => k === answer)?.[2] ?? 'park';
        if (choice === 'park') return undefined;
        if (choice === 'deny') return { approved: false, reason: 'declined by the operator' };
        return { approved: true, grant: choice };
      } finally {
        rl.close();
      }
    };
    // One prompt at a time even when workers run in parallel.
    const next = queue.then(ask, ask);
    queue = next.catch(() => undefined);
    return next as ReturnType<HumanApprover>;
  };
}

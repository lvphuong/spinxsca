import type {
  AnalysisShellPort,
  CandidateDraft,
  CaseRepository,
  DependencyPort,
  HandleTable,
  KbLookupPort,
  ProbePort,
  SecretScrubber,
} from '@spinxsca/core';
import { type ActionTarget, JournalKind, MemoryKind, type RunRef, SourceRef } from '@spinxsca/schemas';
import { z } from 'zod';
import { type AgentTool, defineTool, type SandboxSpec } from '../runtime/tools';

/** What the typed security tools of a case act on (ADR-043). Ports are optional: absent tools are not offered. */
export interface CaseToolContext {
  caseId: string;
  projectId: string;
  persona: string;
  runId: string;
  itemId?: string;
  cases: CaseRepository;
  handles: HandleTable;
  probe?: ProbePort;
  dependencies?: DependencyPort;
  kb?: KbLookupPort;
  shell?: AnalysisShellPort;
  /** Pinned images, for the policy engine's sandbox floors. */
  images: { toolbox: string; scanners: Readonly<Record<string, string>> };
  scrubber: SecretScrubber;
  /** Registers drafts found by a probe as agent findings; returns their handles. */
  registerDrafts?: (drafts: CandidateDraft[], producer: RunRef) => Promise<string[]>;
  /** Evidence excerpts (already redacted) of a handle. */
  evidenceOf?: (handle: string) => Promise<string>;
  now: () => Date;
}

const handle = z.string().regex(/^CF-\d+$/, 'expected a case handle such as CF-3');
const relPath = z.string().min(1).max(500);
const json = (value: unknown) => JSON.stringify(value, null, 2);

function sandboxed(image: string, profile: 'scan' | 'analysis'): () => SandboxSpec {
  return () => ({ network: 'none', image, profile });
}

/** Read and analysis tools: findings, dependencies, knowledge base, probes, shell. */
export function createSecurityTools(ctx: CaseToolContext): AgentTool<never>[] {
  const producer: RunRef = { persona: ctx.persona, runId: ctx.runId };
  const tools: AgentTool<never>[] = [];

  tools.push(
    defineTool({
      name: 'get_finding',
      description: 'Show one finding of this case by handle (scanner, rule, location, severity, advisory ids).',
      input: z.strictObject({ handle }),
      risk: 'READ',
      targets: ({ handle: h }) => [{ kind: 'handle', value: h }],
      run: async ({ handle: h }) => {
        const found = ctx.handles.get(h);
        if (!found) return `Unknown handle ${h}.`;
        const { draftRef: _ref, caseId: _case, ...visible } = found;
        return json(visible);
      },
    }) as AgentTool<never>,
    defineTool({
      name: 'finding_evidence',
      description: 'Redacted code excerpts recorded as evidence for a finding.',
      input: z.strictObject({ handle }),
      risk: 'READ',
      targets: ({ handle: h }) => [{ kind: 'handle', value: h }],
      run: async ({ handle: h }) =>
        ctx.evidenceOf ? ctx.scrubber.scrub(await ctx.evidenceOf(h)) : 'No evidence store.',
    }) as AgentTool<never>,
    defineTool({
      name: 'journal_read',
      description: 'Read the case journal (observations, evidence, decisions, gaps), newest last.',
      input: z.strictObject({ handle: handle.optional(), limit: z.number().int().min(1).max(100).default(30) }),
      risk: 'READ',
      run: async ({ handle: h, limit }) => {
        const entries = (await ctx.cases.listJournal(ctx.caseId))
          .filter((e) => !h || e.handles.includes(h))
          .slice(-limit);
        return (
          entries
            .map(
              (e) =>
                `[${e.seq}] ${e.kind} ${e.author}${e.handles.length ? ` (${e.handles.join(', ')})` : ''}: ${e.text}`,
            )
            .join('\n') || '(empty)'
        );
      },
    }) as AgentTool<never>,
    defineTool({
      name: 'journal_record',
      description:
        'Record an observation, hypothesis, piece of evidence, decision or gap in the case journal. Cite code with refs. Never include secret values.',
      input: z.strictObject({
        kind: JournalKind.exclude(['VERDICT']),
        text: z.string().min(1).max(4000),
        handles: z.array(handle).max(10).default([]),
        refs: z.array(SourceRef).max(10).default([]),
      }),
      risk: 'RECORD',
      targets: ({ handles }) => handles.map((h) => ({ kind: 'handle', value: h }) as ActionTarget),
      run: async ({ kind, text, handles, refs }) => {
        const entry = await ctx.cases.appendJournal({
          caseId: ctx.caseId,
          kind,
          author: `${ctx.persona}/${ctx.runId}`,
          ...(ctx.itemId ? { itemId: ctx.itemId } : {}),
          handles,
          text: ctx.scrubber.scrub(text),
          refs,
        });
        return `Recorded as journal entry ${entry.seq}.`;
      },
    }) as AgentTool<never>,
    defineTool({
      name: 'propose_disposition',
      description:
        "Suggest a human disposition (false positive, accepted risk, won't fix) with evidence. It is only a proposal shown to a human; it never changes the finding.",
      input: z.strictObject({
        handle,
        kind: z.enum(['FALSE_POSITIVE', 'ACCEPTED_RISK', 'WONT_FIX']),
        reason: z.string().min(10).max(1500),
        refs: z.array(SourceRef).min(1).max(8),
      }),
      risk: 'RECORD',
      targets: ({ handle: h }) => [{ kind: 'handle', value: h }],
      run: async ({ handle: h, kind, reason, refs }) => {
        await ctx.cases.appendJournal({
          caseId: ctx.caseId,
          kind: 'PROPOSAL',
          author: `${ctx.persona}/${ctx.runId}`,
          handles: [h],
          text: ctx.scrubber.scrub(`Proposed disposition ${kind}: ${reason}`),
          refs,
          data: { proposal: 'disposition', kind },
        });
        return 'Proposal recorded for a human to review. Continue your work; do not treat the finding as dismissed.';
      },
    }) as AgentTool<never>,
    defineTool({
      name: 'propose_memory',
      description:
        'Propose a project memory (an architecture fact, a convention or a lesson) for future reviews. Lessons and conventions wait for a human.',
      input: z.strictObject({
        kind: MemoryKind.exclude(['DISPOSITION', 'VERDICT_CACHE']),
        key: z.string().min(1).max(120),
        text: z.string().min(10).max(1500),
      }),
      risk: 'RECORD',
      run: async ({ kind, key, text }) => {
        const now = ctx.now().toISOString();
        await ctx.cases.saveMemory({
          memoryId: `mem_${ctx.caseId}_${ctx.runId}_${key}`.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 120),
          projectId: ctx.projectId,
          kind,
          // Architecture notes are usable at once (untrusted, invalidated by churn); the rest waits for a human.
          status: kind === 'ARCHITECTURE' ? 'active' : 'proposed',
          key,
          text: ctx.scrubber.scrub(text),
          sourceCaseId: ctx.caseId,
          createdBy: `agent:${ctx.persona}/${ctx.runId}`,
          createdAt: now,
          updatedAt: now,
        });
        return kind === 'ARCHITECTURE' ? 'Saved.' : 'Saved as a proposal; a human decides whether it is kept.';
      },
    }) as AgentTool<never>,
  );

  if (ctx.dependencies) {
    const deps = ctx.dependencies;
    tools.push(
      defineTool({
        name: 'deps_inventory',
        description: 'Packages from the lockfiles with direct/transitive and runtime/development scope.',
        input: z.strictObject({ name: z.string().max(200).optional(), ecosystem: z.string().max(20).optional() }),
        risk: 'READ',
        idempotent: true,
        run: async ({ name, ecosystem }) => {
          const all = await deps.inventory();
          const rows = all.filter(
            (d) =>
              (!name || d.name.includes(name)) && (!ecosystem || d.ecosystem.toLowerCase() === ecosystem.toLowerCase()),
          );
          return rows.length
            ? rows
                .slice(0, 200)
                .map(
                  (d) =>
                    `${d.ecosystem} ${d.name}@${d.version} ${d.direct === undefined ? '' : d.direct ? 'direct' : 'transitive'} ${d.scope} (${d.manifestPath})`,
                )
                .join('\n')
            : 'No matching packages.';
        },
      }) as AgentTool<never>,
      defineTool({
        name: 'deps_reachability',
        description:
          'Where a package is imported, which calls use it (optionally only the vulnerable functions) and whether an endpoint reaches them.',
        input: z.strictObject({
          ecosystem: z.string().min(1).max(20),
          name: z.string().min(1).max(200),
          symbols: z
            .array(z.string().min(1).max(120))
            .max(20)
            .optional()
            .describe('Vulnerable functions, e.g. ["template"]'),
          symbolSource: z.enum(['advisory', 'model']).optional(),
        }),
        risk: 'READ',
        idempotent: true,
        run: async (input) => json(await deps.reachability(input)),
      }) as AgentTool<never>,
    );
  }

  if (ctx.kb) {
    const kb = ctx.kb;
    tools.push(
      defineTool({
        name: 'kb_lookup',
        description:
          'Advisories from the local knowledge base snapshot (affected packages, fixed versions, KEV, EPSS, symbols).',
        input: z.strictObject({ ids: z.array(z.string().min(3).max(80)).min(1).max(10) }),
        risk: 'READ',
        idempotent: true,
        run: async ({ ids }) => {
          const found = await kb.advisories(ids);
          return found.length ? json(found) : 'No advisories found in the knowledge base snapshot.';
        },
      }) as AgentTool<never>,
    );
  }

  if (ctx.probe) {
    const probe = ctx.probe;
    const describeDrafts = async (drafts: CandidateDraft[]) => {
      if (!drafts.length) return 'No results.';
      const handles = ctx.registerDrafts ? await ctx.registerDrafts(drafts, producer) : [];
      return drafts
        .slice(0, 50)
        .map(
          (d, i) => `${handles[i] ?? '-'} ${d.ruleId} ${d.locations[0]?.path}:${d.locations[0]?.startLine} ${d.title}`,
        )
        .join('\n');
    };
    tools.push(
      defineTool({
        name: 'run_scanner',
        description: `Re-run a configured scanner on specific paths (${probe.scanners.join(', ')}). Use it to check a fix-free variant area or a file the scan skipped.`,
        input: z.strictObject({ scanner: z.string().min(1), paths: z.array(relPath).min(1).max(50) }),
        risk: 'ANALYZE',
        idempotent: true,
        targets: ({ paths }) => paths.map((p) => ({ kind: 'repo_path', value: p }) as ActionTarget),
        sandbox: (input) => sandboxed(ctx.images.scanners[input.scanner] ?? 'unknown', 'scan')(),
        run: async ({ scanner, paths }, { signal }) => {
          const result = await probe.run({ kind: 'scanner', scanner, paths }, signal);
          return [...result.problems.map((p) => `Problem: ${p}`), await describeDrafts(result.drafts)].join('\n');
        },
      }) as AgentTool<never>,
      defineTool({
        name: 'semgrep_rule',
        description:
          'Run up to five Semgrep rules you write (YAML with a top-level "rules" list; no fix, no paths) to hunt variants. Give the seed finding location when generalising it: the rule must match the seed first.',
        input: z.strictObject({
          yaml: z.string().min(20).max(20_000),
          seed: z.strictObject({ path: relPath, line: z.number().int().positive() }).optional(),
          paths: z.array(relPath).max(50).optional(),
        }),
        risk: 'ANALYZE',
        idempotent: true,
        targets: ({ paths }) => (paths ?? []).map((p) => ({ kind: 'repo_path', value: p }) as ActionTarget),
        sandbox: sandboxed(ctx.images.scanners.semgrep ?? 'unknown', 'scan'),
        run: async ({ yaml, seed, paths }, { signal }) => {
          const result = await probe.run(
            { kind: 'semgrep_rule', yaml, ...(seed ? { seed } : {}), ...(paths ? { paths } : {}) },
            signal,
          );
          return [
            ...result.problems.map((p) => `Problem: ${p}`),
            ...(result.reproducedSeed === true ? ['The rule reproduces the seed.'] : []),
            await describeDrafts(result.drafts),
          ].join('\n');
        },
      }) as AgentTool<never>,
    );
  }

  if (ctx.shell) {
    const shell = ctx.shell;
    tools.push(
      defineTool({
        name: 'shell_exec',
        description:
          'Run one shell command over a read-only, secret-redacted copy of the repository at /src (no network, 60 s, small /tmp). For grep/find/sed/awk/jq/rg style analysis; nothing you run here can change the repository.',
        input: z.strictObject({
          command: z.string().min(1).max(2000),
          timeoutSec: z.number().int().min(1).max(60).optional(),
        }),
        risk: 'ANALYZE',
        idempotent: true,
        sandbox: sandboxed(ctx.images.toolbox, 'analysis'),
        outputLimit: 15_000,
        run: async ({ command, timeoutSec }, { signal }) => {
          const r = await shell.exec(command, { ...(timeoutSec ? { timeoutSec } : {}), ...(signal ? { signal } : {}) });
          return `exit ${r.exitCode}${r.timedOut ? ' (timed out)' : ''}\n${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ''}`;
        },
      }) as AgentTool<never>,
    );
  }

  tools.push(
    defineTool({
      name: 'request_tool',
      description:
        'Ask a human for a capability you do not have (explain what and why). The request is recorded; do not wait for it.',
      input: z.strictObject({ capability: z.string().min(3).max(200), reason: z.string().min(10).max(1000) }),
      risk: 'GOVERNANCE',
      describe: ({ capability, reason }) => ({
        title: `The agent asks for a new capability: ${capability}`,
        summary: reason,
      }),
      run: async ({ capability, reason }) => {
        await ctx.cases.appendJournal({
          caseId: ctx.caseId,
          kind: 'PROPOSAL',
          author: `${ctx.persona}/${ctx.runId}`,
          handles: [],
          text: ctx.scrubber.scrub(`Capability approved by a human: ${capability}. Reason: ${reason}`),
          refs: [],
          data: { proposal: 'tool', capability },
        });
        return 'A human approved the request; the capability is considered for the next round.';
      },
    }) as AgentTool<never>,
  );
  return tools;
}

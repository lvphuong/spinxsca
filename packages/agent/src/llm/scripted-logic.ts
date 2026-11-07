import { SCRIPTED_CAPABILITIES } from './catalog';
import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  type LlmProvider,
  type ProviderCapabilities,
  ZERO_USAGE,
} from './types';

/**
 * Deterministic stand-in for the recon-first investigation roles in CI and tests (ADR-027,
 * ADR-049). It derives a recon deliverable and BOLA findings ONLY from the host-injected census
 * worksheet, so `--ai standard --ai-provider scripted` exercises recon → investigator → critic →
 * auditor, the closed-ended checks, drafts, reconciliation and the gate without a model call.
 *
 * This is a test double: production prompts forbid treating the census as findings (it is
 * heuristic evidence), and this provider never reads code beyond one `read_file` per packet.
 */
interface CensusRow {
  method: string;
  route: string;
  path: string;
  line: number;
  handler?: { key: string; path: string; startLine: number; endLine: number };
  flagged: boolean;
  scoped: string[];
}
interface CensusGroup {
  group: string;
  rows: CensusRow[];
}

const textOf = (blocks: readonly ContentBlock[]) =>
  blocks.map((b) => (b.type === 'text' ? b.text : b.type === 'tool_result' ? b.content : '')).join('\n');

function censusOf(prompt: string): CensusGroup[] {
  const m = /<census_json>\n([\s\S]*?)\n<\/census_json>/.exec(prompt);
  if (!m) return [];
  try {
    return (JSON.parse(m[1] as string) as { groups: CensusGroup[] }).groups ?? [];
  } catch {
    return [];
  }
}

function packetOf(
  prompt: string,
): { packetId: string; entryPoints: Array<{ path: string; line: number; label: string }> } | undefined {
  const m = /<packet>\n([\s\S]*?)\n<\/packet>/.exec(prompt);
  if (!m) return undefined;
  try {
    return JSON.parse(m[1] as string);
  } catch {
    return undefined;
  }
}

/** Ids and locations parsed back from the rendered `<ground_truth>` block. */
function groundTruthOf(prompt: string) {
  const invariants = [...prompt.matchAll(/^- (INV-\d+) @ (\S+?):(\d+)(?:-\d+)?:/gm)].map((m) => ({
    id: m[1] as string,
    path: m[2] as string,
    line: Number(m[3]),
  }));
  const baselines = [...prompt.matchAll(/^- (BL-\d+) /gm)].map((m) => m[1] as string);
  const families: Array<{ id: string; members: Array<{ path: string; line: number }> }> = [];
  let current: (typeof families)[number] | undefined;
  for (const line of prompt.split('\n')) {
    const fam = /^- (FAM-\d+) /.exec(line);
    if (fam) {
      current = { id: fam[1] as string, members: [] };
      families.push(current);
      continue;
    }
    const member = /^ {2}- (\S+?):(\d+) /.exec(line);
    if (member && current) current.members.push({ path: member[1] as string, line: Number(member[2]) });
    else if (!/^ {2}- /.test(line) && line.startsWith('#')) current = undefined;
  }
  return { invariants, baselines, families };
}

export class ScriptedLogicProvider implements LlmProvider {
  readonly id = 'scripted';
  readonly model = 'scripted';
  readonly requests: CompletionRequest[] = [];

  capabilities(): ProviderCapabilities {
    return { ...SCRIPTED_CAPABILITIES };
  }

  async complete(request: CompletionRequest): Promise<CompletionResult> {
    this.requests.push(request);
    const content = this.respond(request);
    return {
      content,
      stopReason: content.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn',
      usage: { ...ZERO_USAGE, inputTokens: 200, outputTokens: 40 },
      model: this.model,
      fallbacks: [],
    };
  }

  private respond(request: CompletionRequest): ContentBlock[] {
    const tools = new Set(request.tools.map((t) => t.name));
    const prompt = textOf(request.messages[0]?.content ?? []);
    const used = new Set(
      request.messages.flatMap((m) =>
        m.content.filter((b) => b.type === 'tool_use').map((b) => (b as { name: string }).name),
      ),
    );
    const call = (name: string, input: unknown): ContentBlock[] => [
      { type: 'tool_use', id: `scripted-${request.messages.length}-${name}`, name, input },
    ];
    if (tools.has('submit_recon')) return call('submit_recon', reconFrom(censusOf(prompt)));
    if (tools.has('submit_threat_model'))
      return call('submit_threat_model', {
        summary: 'Scripted provider: no threat model.',
        trustBoundaries: [],
        packets: [],
        notes: ['scripted'],
      });
    if (tools.has('submit_investigation')) {
      const packet = packetOf(prompt);
      const critic = /[Cc]ompleteness re-pass/.test(request.system) || /Completeness re-pass/.test(prompt);
      if (!packet || critic) {
        return call('submit_investigation', {
          findings: [],
          resolvedQuestions: [],
          reviewedFiles: [],
          deferred: ['scripted stand-in: no code analysis performed'],
          invariantResults: [],
          variantLog: [],
        });
      }
      const first = packet.entryPoints[0];
      if (first && tools.has('read_file') && !used.has('read_file'))
        return call('read_file', { path: first.path, start_line: first.line });
      return call('submit_investigation', investigationFrom(packet, groundTruthOf(prompt), censusOf(prompt)));
    }
    if (tools.has('submit_explanation')) return call('submit_explanation', explanationFrom(prompt));
    return [{ type: 'text', text: 'Scripted logic provider: nothing to submit.' }];
  }
}

export function scriptedLogicProvider(): ScriptedLogicProvider {
  return new ScriptedLogicProvider();
}

function reconFrom(groups: CensusGroup[]) {
  const flaggedGroups = groups.filter((g) => g.rows.some((r) => r.flagged));
  let inv = 0;
  let bl = 0;
  const invariants: unknown[] = [];
  const baselines: unknown[] = [];
  const families: unknown[] = [];
  const packets = flaggedGroups.slice(0, 8).map((g, i) => {
    const packetId = `logic-${i + 1}`;
    const safe =
      g.rows.find((r) => !r.flagged && r.scoped.some((s) => s === 'user' || s === 'tenant')) ??
      g.rows.find((r) => !r.flagged);
    let baselineId: string | undefined;
    if (safe) {
      baselineId = `BL-${++bl}`;
      baselines.push({
        baselineId,
        pattern: `${g.group}: scoped lookup`,
        location: { path: safe.path, startLine: safe.line, endLine: safe.line },
        whyCorrect: `${safe.method} ${safe.route} scopes its data access to the caller.`,
      });
    }
    const familyId = `FAM-${i + 1}`;
    families.push({
      familyId,
      rootCause: `${g.group} operations that load an object by identifier`,
      ...(baselineId ? { baselineId } : {}),
      members: g.rows.map((r) => ({ path: r.path, startLine: r.line, label: `${r.method} ${r.route}` })),
    });
    for (const r of g.rows.filter((x) => x.flagged)) {
      invariants.push({
        invariantId: `INV-${++inv}`,
        location: { path: r.path, startLine: r.line, endLine: r.line },
        expected: `${r.method} ${r.route} only returns or changes objects owned by the caller`,
        howToCheck: 'Read the handler and the data access it reaches for an owner or tenant predicate.',
        packets: [packetId],
        familyId,
      });
    }
    return {
      packetId,
      perspective: 'AUTHZ_AND_BUSINESS_LOGIC',
      attacker: 'authenticated user',
      protectedAsset: `${g.group} records of other users`,
      entryPoints: g.rows
        .filter((r) => r.flagged)
        .slice(0, 8)
        .map((r) => ({ path: r.path, line: r.line, label: `${r.method} ${r.route}` })),
      expectedControls: ['ownership or tenant scope on the lookup'],
      questions: [`Does every ${g.group} operation that takes an identifier verify the caller owns the object?`],
    };
  });
  return {
    threatModel: {
      summary: `Scripted recon: ${groups.length} resource groups from the census, ${flaggedGroups.length} with an unscoped sibling.`,
      trustBoundaries: ['client -> API'],
      packets,
      notes: ['scripted stand-in derived from the census worksheet'],
    },
    groundTruth: {
      archetype: 'http_api',
      archetypeNote: 'scripted',
      trustClaims: [],
      invariants,
      baselines,
      families: families.filter((f) => (f as { members: unknown[] }).members.length >= 2),
      carveouts: [],
      residualUnknowns: [],
      notes: ['scripted stand-in'],
    },
  };
}

function investigationFrom(
  packet: { packetId: string; entryPoints: Array<{ path: string; line: number; label: string }> },
  gt: ReturnType<typeof groundTruthOf>,
  groups: CensusGroup[],
) {
  const rows = groups.flatMap((g) => g.rows);
  const findings = packet.entryPoints.map((e) => {
    const row = rows.find((r) => r.path === e.path && r.line === e.line);
    const start = row?.handler?.startLine ?? e.line;
    const end = row?.handler?.endLine ?? e.line;
    const invariant = gt.invariants.find((i) => i.path === e.path && i.line === e.line);
    const family = gt.families.find((f) => f.members.some((m) => m.path === e.path && m.line === e.line));
    return {
      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
      cwe: ['CWE-639'],
      title: `Missing ownership check in ${e.label}`,
      summary: `${e.label} loads or changes an object by identifier without scoping the data access to the caller, unlike its sibling operations.`,
      confidence: 'MEDIUM',
      severity: 'HIGH',
      attacker: 'authenticated user',
      invariantViolated: 'callers may only act on objects they own',
      claim: `An authenticated user can act on any object through ${e.label} because the handler never checks ownership.`,
      preconditions: ['the caller holds a valid session'],
      capabilitiesGained: ['read or change records of other users'],
      proofObligations: [],
      threatModelClass: 'real_bug',
      ...(invariant ? { invariantId: invariant.id } : {}),
      ...(family ? { familyId: family.id } : {}),
      ...(gt.baselines[0] ? { baselineReference: gt.baselines[0] } : {}),
      locations: [{ path: e.path, startLine: start, endLine: Math.max(start, end), role: 'primary' }],
      evidence: [`${e.path}:${e.line} routes to a handler whose data access has no owner predicate (scripted)`],
      counterevidence: [],
      remediation: 'Scope the lookup by the authenticated principal or add an ownership guard.',
    };
  });
  const flagged = new Set(packet.entryPoints.map((e) => `${e.path}:${e.line}`));
  return {
    findings,
    resolvedQuestions: [],
    reviewedFiles: [...new Set(packet.entryPoints.map((e) => e.path))],
    deferred: [],
    invariantResults: gt.invariants.map((i) => ({
      invariantId: i.id,
      result: flagged.has(`${i.path}:${i.line}`) ? 'FAIL' : 'PASS',
      evidence: [{ path: i.path, startLine: i.line, endLine: i.line }],
      note: 'scripted',
    })),
    variantLog: gt.families.flatMap((f) =>
      f.members.map((m) => ({
        familyId: f.id,
        member: { path: m.path, startLine: m.line },
        verdict: flagged.has(`${m.path}:${m.line}`) ? 'VULNERABLE' : 'SAFE',
        note: 'scripted',
      })),
    ),
  };
}

function explanationFrom(prompt: string) {
  const m = /<finding_context>\n([\s\S]*?)\n<\/finding_context>/.exec(prompt);
  const ctx = m
    ? (JSON.parse(m[1] as string) as {
        findingId: string;
        title: string;
        scannerSeverity?: string;
        locations: Array<{ path: string; startLine: number; endLine: number }>;
      })
    : undefined;
  const loc = ctx?.locations[0] ?? { path: '', startLine: 1, endLine: 1 };
  return {
    summary: `Scripted explanation of ${ctx?.findingId ?? 'finding'}: ${ctx?.title ?? ''}.`,
    classification: 'POTENTIAL',
    severity: ctx?.scannerSeverity ?? 'MEDIUM',
    severityRationale: 'Scripted provider keeps the reported severity.',
    selfRefutationCheck: 'Not applicable to the scripted provider.',
    confidence: 'LOW',
    attackPath: {
      attacker: 'remote user',
      entryPoint: `${loc.path}:${loc.startLine}`,
      source: 'request input',
      sink: `${loc.path}:${loc.startLine}`,
      preconditions: [],
      controls: [],
    },
    evidence: [{ path: loc.path, startLine: loc.startLine, endLine: loc.endLine, explanation: 'Reported location.' }],
    counterevidence: [],
    missingEvidence: ['Scripted provider does not analyse the code.'],
    remediation: { strategy: 'Apply the fix recommended by the rule.', steps: ['Follow the recommendation.'] },
  };
}

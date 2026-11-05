import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  type LlmProvider,
  type ProviderCapabilities,
  ZERO_USAGE,
} from './types';

/** Vulnerable functions of common advisories, standing in for model knowledge in scripted runs. */
const KNOWN_SYMBOLS: Readonly<Record<string, string[]>> = {
  'GHSA-35jh-r3h4-6jhm': ['template'],
  'GHSA-p6mc-m468-83gw': ['zipObjectDeep'],
  'GHSA-29mw-wpgm-hmr9': ['toNumber', 'trim', 'trimEnd'],
  'GHSA-jf85-cpcp-j695': ['merge', 'mergeWith', 'defaultsDeep'],
  'GHSA-4xc9-xhrj-v574': ['zipObjectDeep'],
};

const textOf = (blocks: readonly ContentBlock[]) =>
  blocks.map((b) => (b.type === 'text' ? b.text : b.type === 'tool_result' ? b.content : '')).join('\n');

const field = (prompt: string, name: string) => new RegExp(`^${name}: (.+)$`, 'm').exec(prompt)?.[1]?.trim();

/**
 * Deterministic stand-in for the autonomous review personas (ADR-027): it exercises the governed
 * tool path (one real tool call per item) and submits schema-valid deliverables derived only from
 * the host's prompt and tool results. It never analyses code: CI uses it to test the orchestration,
 * the policy engine and the store, not detection quality.
 */
export class ScriptedReviewProvider implements LlmProvider {
  readonly id = 'scripted';
  readonly model = 'scripted';
  readonly requests: CompletionRequest[] = [];

  capabilities(): ProviderCapabilities {
    return { tools: true, thinking: false, promptCaching: false, refusalFallback: false };
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
    const submit = request.tools.find((t) => t.name.startsWith('submit_'))?.name;
    const prompt = textOf(request.messages[0]?.content ?? []);
    const used = new Set(
      request.messages.flatMap((m) =>
        m.content.filter((b) => b.type === 'tool_use').map((b) => (b as { name: string }).name),
      ),
    );
    const last = request.messages.at(-1)?.content ?? [];
    const rejected = last.some(
      (b) => b.type === 'tool_result' && b.isError && b.content.startsWith('Submission rejected'),
    );
    const call = (name: string, input: unknown): ContentBlock[] => [
      { type: 'tool_use', id: `scripted-${request.messages.length}-${name}`, name, input },
    ];

    if (!submit) return [{ type: 'text', text: '{"verdict":"approve","reason":"scripted reviewer"}' }];
    switch (submit) {
      case 'submit_plan':
        return call('submit_plan', { notes: 'Scripted lead: the seeded work covers this case.', done: true });
      case 'submit_answer':
        return call('submit_answer', { answer: 'Scripted explore: no answer.', citations: [] });
      case 'submit_recon':
        return call('submit_recon', scriptedRecon(prompt));
      case 'submit_findings': {
        if (/Work item: LOGIC_AUDIT/.test(prompt)) return call('submit_findings', scriptedLogicAudit(prompt));
        return call('submit_findings', {
          findings: [],
          notes: 'Scripted reviewer: no code analysis performed.',
          deferred: [],
          invariantResults: [],
          variantLog: [],
        });
      }
      case 'submit_triage': {
        const handle = field(prompt, 'Handle') ?? 'CF-1';
        if (tools.has('get_finding') && !used.has('get_finding')) return call('get_finding', { handle });
        const [path = '', line = '1'] = (field(prompt, 'Location') ?? '').split(/:(?=\d+$)/);
        const severity = field(prompt, 'Severity') ?? 'MEDIUM';
        const agentReported = /^Reported by: /m.test(prompt);
        if (/scripted:expect-false-positive/.test(prompt) && !rejected) {
          // Test fixture: a refutation without a cited contradiction, to exercise the host's rejection.
          return call('submit_triage', {
            handle,
            verdict: 'FALSE_POSITIVE',
            severity,
            confidence: 'HIGH',
            rationale: 'Scripted validator: there is no ownership check here but I think it is fine.',
            evidence: [],
            counterevidence: ['the framework probably handles it'],
            noiseReason: 'guess',
            missingEvidence: [],
          });
        }
        if (rejected) {
          return call('submit_triage', {
            handle,
            verdict: 'BLOCKED',
            severity,
            confidence: 'LOW',
            rationale: 'Scripted validator: the reported location could not be cited from this snapshot.',
            evidence: [],
            counterevidence: [],
            missingEvidence: [`${path}:${line} is not readable in this snapshot`],
          });
        }
        const high = severity === 'HIGH' || severity === 'CRITICAL';
        const links = ['reachability', 'input_control', 'sanitization', 'sink', 'authz', 'preconditions'] as const;
        return call('submit_triage', {
          handle,
          verdict: 'TRUE_POSITIVE',
          severity,
          confidence: 'MEDIUM',
          rationale: agentReported
            ? 'Scripted validator: re-derived the reported claim at the cited line; every link held (scripted).'
            : 'Scripted validator: accepts the scanner evidence at the reported line without further analysis.',
          evidence: [{ path, startLine: Number(line), endLine: Number(line), note: 'reported line' }],
          counterevidence: [],
          ...(agentReported
            ? {
                refutationAttempts: links.map((link) => ({
                  link,
                  result: 'held',
                  evidence: `${path}:${line} (scripted)`,
                })),
              }
            : {}),
          ...(high
            ? {
                attackPath: {
                  attacker: 'remote user',
                  entryPoint: 'not traced by the scripted provider',
                  source: 'request data',
                  sink: field(prompt, 'Title') ?? 'reported sink',
                  preconditions: [],
                  controls: [],
                },
              }
            : {}),
          missingEvidence: [],
        });
      }
      case 'submit_applicability': {
        const handle = field(prompt, 'Handle') ?? 'CF-1';
        const purl = field(prompt, 'Package') ?? '';
        const m = /^pkg:([^/]+)\/(.+)@[^@]+$/.exec(purl);
        const type = m?.[1] ?? 'npm';
        const name = decodeURIComponent(m?.[2] ?? '').replace(type === 'maven' ? '/' : '\0', ':');
        const ecosystem = type === 'pypi' ? 'PyPI' : type === 'maven' ? 'Maven' : type;
        const advisories = (field(prompt, 'Advisories') ?? '').split(/,\s*/).filter(Boolean);
        const symbols = [...new Set(advisories.flatMap((a) => KNOWN_SYMBOLS[a] ?? []))];
        if (tools.has('deps_reachability') && !used.has('deps_reachability')) {
          return call('deps_reachability', {
            ecosystem,
            name,
            ...(symbols.length ? { symbols, symbolSource: 'model' } : {}),
          });
        }
        const level = /"level":\s*"([A-Z_]+)"/.exec(textOf(last))?.[1] ?? 'UNKNOWN_TRANSITIVE';
        const notAffected = !rejected && (level === 'IMPORTED_ONLY' || level === 'NOT_IMPORTED');
        return call('submit_applicability', {
          handle,
          status: notAffected ? 'NOT_AFFECTED' : 'AFFECTED',
          ...(notAffected
            ? {
                justification:
                  level === 'NOT_IMPORTED' ? 'component_not_present' : 'vulnerable_code_not_in_execute_path',
              }
            : {}),
          vulnerableSymbols: symbols,
          symbolSource: symbols.length ? 'model' : 'none',
          severity: field(prompt, 'Severity') ?? 'MEDIUM',
          confidence: symbols.length ? 'MEDIUM' : 'LOW',
          rationale: `Scripted dependency review: the code index reports ${level} for ${name}${symbols.length ? ` (${symbols.join(', ')})` : ''}.`,
          evidence: [],
        });
      }
      case 'submit_poc': {
        const handle = field(prompt, 'Handle') ?? 'CF-1';
        const workspaceId = /Validation workspace: (ws-[a-z0-9-]+)/.exec(prompt)?.[1] ?? 'ws-unknown';
        const oracle = /Oracle: ([A-Z_]+)\./.exec(prompt)?.[1] ?? 'CANARY_READ';
        if (!used.has('harness_write')) {
          return call('harness_write', {
            workspaceId,
            path: 'poc.js',
            content:
              "// scripted harness\nconsole.log(process.env.SPX_MODE, process.env.SPX_NONCE ? 'nonce set' : '');\n",
          });
        }
        if (!used.has('validation_run')) {
          return call('validation_run', { handle, workspaceId, command: ['node', 'harness/poc.js'], oracle });
        }
        return call('submit_poc', {
          handle,
          workspaceId,
          oracle,
          summary: 'Scripted exploit: runs the generic harness once.',
        });
      }
      case 'submit_poc_review': {
        const handle = field(prompt, 'Handle') ?? 'CF-1';
        const confirmed = /Host oracle [A-Z_]+: CONFIRMED/.test(prompt);
        return call('submit_poc_review', {
          handle,
          approve: confirmed,
          reason: confirmed
            ? 'Scripted validator: the host oracle confirmed the attack run only.'
            : 'Scripted validator: nothing to approve.',
          concerns: [],
        });
      }
      case 'submit_fix_review':
        return call('submit_fix_review', {
          verdict: /rescan_passed|verified|"RESOLVED"/.test(prompt) ? 'approve' : 'request_changes',
          comments: 'Scripted verifier: accepts the host verification without reading the change.',
          risks: [],
        });
      default:
        return call(submit, {});
    }
  }
}

export function scriptedReviewProvider(): ScriptedReviewProvider {
  return new ScriptedReviewProvider();
}

interface ScriptedCensusRow {
  method: string;
  route: string;
  path: string;
  line: number;
  flagged: boolean;
}

/** Census rows parsed back from the rendered worksheet in the RECON item description. */
function censusRows(prompt: string): Array<{ group: string; rows: ScriptedCensusRow[] }> {
  const groups: Array<{ group: string; rows: ScriptedCensusRow[] }> = [];
  let current: (typeof groups)[number] | undefined;
  for (const line of prompt.split('\n')) {
    const g = /^### (.+?) \(\d+ operations/.exec(line);
    if (g) {
      current = { group: g[1] as string, rows: [] };
      groups.push(current);
      continue;
    }
    const r = /^- (\[!\] )?([A-Z]+) (\S+) \((\S+?):(\d+)\)/.exec(line);
    if (r && current) {
      current.rows.push({
        flagged: Boolean(r[1]),
        method: r[2] as string,
        route: r[3] as string,
        path: r[4] as string,
        line: Number(r[5]),
      });
    }
  }
  return groups;
}

/** Recon derived only from the census worksheet: flagged groups become families and invariants. */
function scriptedRecon(prompt: string) {
  const groups = censusRows(prompt).filter((g) => g.rows.some((r) => r.flagged) && g.rows.length >= 2);
  let inv = 0;
  const invariants: unknown[] = [];
  const baselines: unknown[] = [];
  const families = groups.map((g, i) => {
    const familyId = `FAM-${i + 1}`;
    const safe = g.rows.find((r) => !r.flagged);
    let baselineId: string | undefined;
    if (safe) {
      baselineId = `BL-${i + 1}`;
      baselines.push({
        baselineId,
        pattern: `${g.group}: scoped operation`,
        location: { path: safe.path, startLine: safe.line, endLine: safe.line },
        whyCorrect: `${safe.method} ${safe.route} carries the control its siblings lack (scripted).`,
      });
    }
    for (const r of g.rows.filter((x) => x.flagged)) {
      invariants.push({
        invariantId: `INV-${++inv}`,
        location: { path: r.path, startLine: r.line, endLine: r.line },
        expected: `${r.method} ${r.route} only acts on objects the caller owns`,
        howToCheck: 'Read the handler and the data access it reaches for an owner or tenant predicate.',
        packets: [],
        familyId,
      });
    }
    return {
      familyId,
      rootCause: `${g.group} operations that load an object by identifier`,
      ...(baselineId ? { baselineId } : {}),
      members: g.rows.map((r) => ({ path: r.path, startLine: r.line, label: `${r.method} ${r.route}` })),
    };
  });
  return {
    threatModel: {
      summary: `Scripted recon: ${groups.length} resource group(s) with an unscoped sibling.`,
      trustBoundaries: ['client -> API'],
      packets: [],
      notes: ['scripted stand-in derived from the census worksheet'],
    },
    groundTruth: {
      archetype: 'http_api',
      archetypeNote: 'scripted',
      trustClaims: [],
      invariants,
      baselines,
      families,
      carveouts: [],
      residualUnknowns: [],
      notes: ['scripted stand-in'],
    },
  };
}

/** Logic audit derived from the ground truth slice rendered in the item. */
function scriptedLogicAudit(prompt: string) {
  const invariants = [...prompt.matchAll(/^- (INV-\d+) @ (\S+?):(\d+)(?:-\d+)?:/gm)].map((m) => ({
    id: m[1] as string,
    path: m[2] as string,
    line: Number(m[3]),
  }));
  const baseline = /^- (BL-\d+) /m.exec(prompt)?.[1];
  const families: Array<{ id: string; members: Array<{ path: string; line: number; label: string }> }> = [];
  let current: (typeof families)[number] | undefined;
  for (const line of prompt.split('\n')) {
    const fam = /^- (FAM-\d+) /.exec(line);
    if (fam) {
      current = { id: fam[1] as string, members: [] };
      families.push(current);
      continue;
    }
    const member = /^ {2}- (\S+?):(\d+) (.*)$/.exec(line);
    if (member && current)
      current.members.push({ path: member[1] as string, line: Number(member[2]), label: member[3] as string });
    else if (line.startsWith('#')) current = undefined;
  }
  const flagged = new Set(invariants.map((i) => `${i.path}:${i.line}`));
  const findings = invariants.map((i) => {
    const family = families.find((f) => f.members.some((m) => m.path === i.path && m.line === i.line));
    const label = family?.members.find((m) => m.path === i.path && m.line === i.line)?.label ?? `${i.path}:${i.line}`;
    return {
      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
      cwe: ['CWE-639'],
      title: `Missing ownership check in ${label}`,
      summary: `${label} acts on an object by identifier without scoping the data access to the caller, unlike its sibling operations (scripted).`,
      confidence: 'MEDIUM',
      severity: 'HIGH',
      attacker: 'authenticated user',
      invariantViolated: 'callers may only act on objects they own',
      claim: `An authenticated user can act on any object through ${label} because the handler never checks ownership.`,
      preconditions: ['the caller holds a valid session'],
      capabilitiesGained: ['read or change records of other users'],
      proofObligations: [],
      threatModelClass: 'real_bug',
      invariantId: i.id,
      ...(family ? { familyId: family.id } : {}),
      ...(baseline ? { baselineReference: baseline } : {}),
      locations: [{ path: i.path, startLine: i.line, endLine: i.line, role: 'primary' }],
      evidence: [`${i.path}:${i.line} has no owner predicate on its data access (scripted)`],
      counterevidence: [],
      remediation: 'Scope the lookup by the authenticated principal or add an ownership guard.',
    };
  });
  return {
    findings,
    notes: 'Scripted logic audit derived from the ground-truth slice.',
    deferred: [],
    invariantResults: invariants.map((i) => ({
      invariantId: i.id,
      result: 'FAIL',
      evidence: [{ path: i.path, startLine: i.line, endLine: i.line }],
      note: 'scripted',
    })),
    variantLog: families.flatMap((f) =>
      f.members.map((m) => ({
        familyId: f.id,
        member: { path: m.path, startLine: m.line },
        verdict: flagged.has(`${m.path}:${m.line}`) ? 'VULNERABLE' : 'SAFE',
        note: 'scripted',
      })),
    ),
  };
}

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
 * Deterministic stand-in for the sharded roles (ADR-055) in CI and tests. The mapper turns every
 * SQL or census signal in the files it owns into one finding anchored at the signal's line; recon
 * returns an empty ground truth; the reducer keeps every ref and chains two refs that share a file.
 * It reads no code beyond the signal lines, so it exercises plan → recon → map → reduce, the
 * ownership rule, dedup and the gate without a model call. Production prompts forbid treating
 * signals as findings.
 */
const textOf = (blocks: readonly ContentBlock[]) => blocks.map((b) => (b.type === 'text' ? b.text : '')).join('\n');

export class ScriptedMapProvider implements LlmProvider {
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
    const call = (name: string, input: unknown): ContentBlock[] => [
      { type: 'tool_use', id: `scripted-${request.messages.length}-${name}`, name, input },
    ];
    if (tools.has('submit_recon'))
      return call('submit_recon', {
        threatModel: {
          summary: 'Scripted map provider: sharded review, no threat model.',
          trustBoundaries: [],
          packets: [],
          notes: ['scripted'],
        },
        groundTruth: {
          archetype: 'hybrid',
          archetypeNote: 'scripted',
          trustClaims: [],
          invariants: [],
          baselines: [],
          families: [],
          carveouts: [],
          residualUnknowns: [],
          notes: [],
        },
      });
    if (tools.has('submit_investigation')) {
      const owned = [...prompt.matchAll(/^- (\S+) \(\d+ signal\(s\)/gm)].map((m) => m[1] as string);
      const signals = [
        ...prompt.matchAll(
          /^(\S+?):(\d+) \[(lex\.sqli\.\S+|census\.flagged|ast\.sqli\S*|lex\.path\.open_concat)\] (.*)$/gm,
        ),
      ]
        .filter((m) => owned.includes(m[1] as string))
        .map((m) => ({ path: m[1] as string, line: Number(m[2]), selector: m[3] as string, evidence: m[4] as string }));
      const seen = new Set<string>();
      const findings = signals
        .filter((s) => !seen.has(`${s.path}:${s.line}`) && seen.add(`${s.path}:${s.line}`))
        .slice(0, 8)
        .map((s) => ({
          category: s.selector.startsWith('census')
            ? 'BROKEN_OBJECT_LEVEL_AUTHORIZATION'
            : s.selector.startsWith('lex.path')
              ? 'PATH_TRAVERSAL'
              : 'SQL_INJECTION',
          cwe: [s.selector.startsWith('census') ? 'CWE-639' : s.selector.startsWith('lex.path') ? 'CWE-22' : 'CWE-89'],
          title: `${
            s.selector.startsWith('census')
              ? 'Object access without ownership check'
              : s.selector.startsWith('lex.path')
                ? 'File path built from request data'
                : 'SQL built from request data'
          } in ${s.path}`,
          summary: `Scripted stand-in: signal ${s.selector} at ${s.path}:${s.line}.`,
          confidence: 'MEDIUM',
          severity: 'HIGH',
          attacker: 'authenticated user',
          invariantViolated: 'request data never reaches a sink unchecked',
          claim: `${s.path}:${s.line} lets request data reach a sensitive operation unchecked`,
          preconditions: [],
          capabilitiesGained: ['read or modify records of other users'],
          proofObligations: [],
          threatModelClass: 'real_bug',
          locations: [{ path: s.path, startLine: s.line, endLine: s.line, role: 'primary' }],
          evidence: [`${s.path}:${s.line} ${s.evidence.slice(0, 200)}`],
          counterevidence: [],
          remediation: 'Validate and scope the operation to the caller.',
        }));
      return call('submit_investigation', {
        findings,
        resolvedQuestions: [],
        reviewedFiles: owned,
        deferred: [],
        invariantResults: [],
        variantLog: [],
      });
    }
    if (tools.has('submit_reduction')) {
      const refs = [...prompt.matchAll(/^(F-\d+) \| \S+ \| \S+ \| \S+ \| (\S+?):\d+$/gm)].map((m) => ({
        ref: m[1] as string,
        path: m[2] as string,
      }));
      const byPath = new Map<string, string[]>();
      for (const r of refs) byPath.set(r.path, [...(byPath.get(r.path) ?? []), r.ref]);
      const pair = [...byPath.values()].find((v) => v.length >= 2);
      return call('submit_reduction', {
        findings: refs.map((r) => ({
          ref: r.ref,
          keep: true,
          severity: 'HIGH',
          confidence: 'MEDIUM',
          rationale: 'scripted: kept',
        })),
        chains: pair
          ? [
              {
                chainId: 'CH-1',
                members: pair.slice(0, 2),
                combinedSeverity: 'HIGH',
                narrative: 'Scripted: two findings in one file.',
                combinedPreconditions: [],
              },
            ]
          : [],
        ranking: refs.map((r) => r.ref),
        notes: ['scripted reducer'],
      });
    }
    return [{ type: 'text', text: 'Scripted map provider: nothing to submit.' }];
  }
}

export function scriptedMapProvider(): ScriptedMapProvider {
  return new ScriptedMapProvider();
}

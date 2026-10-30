import { ScriptedProvider } from './scripted';
import type { CompletionRequest } from './types';

/**
 * Deterministic stand-in for the model in CI and tests (ADR-027): reads the reported file once,
 * then submits a schema-valid explanation built from the finding context in the prompt. It
 * exercises the tool loop, citation checks, persistence and reporting without calling an API.
 */
export function scriptedExplainProvider(): ScriptedProvider {
  const context = (request: CompletionRequest) => {
    const first = request.messages[0]?.content[0];
    const text = first?.type === 'text' ? first.text : '';
    const match = /<finding_context>\n([\s\S]*?)\n<\/finding_context>/.exec(text);
    return match ? (JSON.parse(match[1] as string) as ExplainContext) : undefined;
  };
  return new ScriptedProvider([
    (request) => {
      const ctx = context(request);
      const loc = ctx?.locations[0];
      return loc
        ? {
            content: [
              {
                type: 'tool_use',
                id: 'scripted-read',
                name: 'read_file',
                input: { path: loc.path, start_line: loc.startLine },
              },
            ],
          }
        : { content: [{ type: 'text', text: 'No finding context.' }] };
    },
    (request) => {
      const ctx = context(request);
      if (!ctx) return { content: [{ type: 'text', text: 'Unable to explain.' }] };
      const loc = ctx.locations[0] ?? { path: '', startLine: 1, endLine: 1 };
      return {
        content: [
          {
            type: 'tool_use',
            id: 'scripted-submit',
            name: 'submit_explanation',
            input: {
              summary: `Scripted explanation of ${ctx.findingId}: ${ctx.title}.`,
              classification: 'POTENTIAL',
              severity: ctx.scannerSeverity ?? 'MEDIUM',
              severityRationale: 'Scripted provider keeps the scanner severity.',
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
              evidence: [
                { path: loc.path, startLine: loc.startLine, endLine: loc.endLine, explanation: 'Reported location.' },
              ],
              counterevidence: [],
              missingEvidence: ['Scripted provider does not analyse the code.'],
              remediation: {
                strategy: 'Apply the fix recommended by the rule.',
                steps: ['Follow the scanner recommendation.'],
              },
            },
          },
        ],
      };
    },
  ]);
}

interface ExplainContext {
  findingId: string;
  title: string;
  scannerSeverity?: string;
  locations: Array<{ path: string; startLine: number; endLine: number }>;
}

/**
 * Scripted investigation roles for CI: the planner submits an empty threat model and the auditor
 * reports nothing, so `--ai standard` exercises the pipeline without any model call. Tests inject
 * their own ScriptedProvider when they need findings.
 */
export function scriptedInvestigationProvider(): ScriptedProvider {
  return new ScriptedProvider([
    (request) => {
      const isPlanner = request.tools.some((t) => t.name === 'submit_threat_model');
      return isPlanner
        ? {
            content: [
              {
                type: 'tool_use',
                id: 'scripted-plan',
                name: 'submit_threat_model',
                input: {
                  summary: 'Scripted provider: no threat model.',
                  trustBoundaries: [],
                  packets: [],
                  notes: ['scripted'],
                },
              },
            ],
          }
        : {
            content: [
              {
                type: 'tool_use',
                id: 'scripted-audit',
                name: 'submit_investigation',
                input: {
                  findings: [],
                  resolvedQuestions: [],
                  reviewedFiles: [],
                  deferred: ['scripted provider does not analyse code'],
                },
              },
            ],
          };
    },
    (request) => ({
      content: [
        {
          type: 'tool_use',
          id: `scripted-${request.messages.length}`,
          name: 'submit_investigation',
          input: {
            findings: [],
            resolvedQuestions: [],
            reviewedFiles: [],
            deferred: ['scripted provider does not analyse code'],
          },
        },
      ],
    }),
  ]);
}

/**
 * Scripted remediation for tests: replaces the reported line with the text given by the test (a
 * closure over the fixture), so the host-side apply/re-scan/test pipeline runs without a model.
 */
export function scriptedRemediationProvider(edit: { replacement: string; lines?: number }): ScriptedProvider {
  return new ScriptedProvider([
    (request) => {
      const first = request.messages[0]?.content[0];
      const text = first?.type === 'text' ? first.text : '';
      const match = /<finding_context>\n([\s\S]*?)\n<\/finding_context>/.exec(text);
      const ctx = match
        ? (JSON.parse(match[1] as string) as { locations: Array<{ path: string; startLine: number; endLine: number }> })
        : undefined;
      const loc = ctx?.locations[0];
      if (!loc) return { content: [{ type: 'text', text: 'no context' }] };
      return {
        content: [
          {
            type: 'tool_use',
            id: 'scripted-patch',
            name: 'submit_patch',
            input: {
              summary: 'Scripted patch for tests.',
              edits: [
                {
                  path: loc.path,
                  startLine: loc.startLine,
                  endLine: loc.startLine + (edit.lines ?? 1) - 1,
                  replacement: edit.replacement,
                  rationale: 'scripted',
                },
              ],
              behaviourPreserved: 'n/a (scripted)',
              tests: [],
              residualRisk: [],
            },
          },
        ],
      };
    },
  ]);
}

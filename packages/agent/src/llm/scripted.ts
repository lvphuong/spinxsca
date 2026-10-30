import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  type LlmProvider,
  type ProviderCapabilities,
  type StopReason,
  type Usage,
  ZERO_USAGE,
} from './types';

export interface ScriptedResponse {
  content: ContentBlock[];
  stopReason?: StopReason;
  refusal?: CompletionResult['refusal'];
  usage?: Partial<Usage>;
}

export type ScriptedTurn = ScriptedResponse | ((request: CompletionRequest) => ScriptedResponse);

/**
 * Deterministic provider replaying a fixed script. Used by unit tests and by CI evals so no model is
 * called (ADR-027). Every request is recorded for assertions.
 */
export class ScriptedProvider implements LlmProvider {
  readonly id = 'scripted';
  readonly model = 'scripted';
  readonly requests: CompletionRequest[] = [];
  private index = 0;

  constructor(private readonly turns: ScriptedTurn[]) {}

  capabilities(): ProviderCapabilities {
    return { tools: true, thinking: false, promptCaching: false, refusalFallback: false };
  }

  async complete(request: CompletionRequest): Promise<CompletionResult> {
    this.requests.push(structuredClone(request) as CompletionRequest);
    const turn = this.turns[this.index++];
    if (!turn) throw new Error(`scripted provider exhausted after ${this.turns.length} turns`);
    const result = typeof turn === 'function' ? turn(request) : turn;
    const content = result.content;
    const stopReason = result.stopReason ?? (content.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn');
    return {
      content,
      stopReason,
      usage: { ...ZERO_USAGE, inputTokens: 100, outputTokens: 20, ...result.usage },
      model: this.model,
      fallbacks: [],
      ...(result.refusal ? { refusal: result.refusal } : {}),
    };
  }
}

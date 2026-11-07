import {
  type CompletionRequest,
  contextBudgetFor,
  type DetectedProfile,
  detectModelProfile,
  type LlmProvider,
  OllamaProvider,
  OpenAICompatibleProvider,
  originOf,
  resolveProfile,
  runStructured,
  type ToolMode,
  withPromptedTools,
} from '@spinxsca/agent';
import type { AiModelConfig } from '@spinxsca/schemas';
import pc from 'picocolors';
import { stringify as toYaml } from 'yaml';
import { z } from 'zod';
import { loadConfig } from '../config';
import { CliError, EXIT } from '../ui';

export interface DoctorOptions {
  provider?: string;
  baseUrl?: string;
  model?: string;
  apiKeyEnv?: string;
  /** Alias from `ai.models` to check instead of flags. */
  alias?: string;
  config?: string;
  json?: boolean;
}

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
  /** Milliseconds the check took. */
  ms?: number;
}

export interface DoctorReport {
  provider: string;
  model: string;
  baseUrl?: string;
  checks: DoctorCheck[];
  detected: DetectedProfile;
  contextWindow: number;
  effectiveWindow: number;
  compactThreshold: number;
  toolMode: ToolMode | 'unsupported';
  tokensPerSecond?: { generate?: number; prefill?: number };
  recommendation: { yaml: string; warnings: string[] };
  ok: boolean;
}

export interface DoctorDeps {
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
}

const Probe = z.strictObject({ verdict: z.enum(['ok']), reason: z.string().min(1).max(200) });

/**
 * `spinxsca ai doctor` (ADR-054): checks that a self-hosted endpoint can do what the agent needs
 * (tool calls, structured JSON, a known context window, acceptable throughput) and prints the
 * `ai.models` configuration to use. Runs before the first scan, so a weak setup fails here with a
 * named cause instead of inside a review.
 */
export async function runDoctor(target: AiModelConfig, deps: DoctorDeps = {}): Promise<DoctorReport> {
  const env = deps.env ?? process.env;
  const now = deps.now ?? (() => Date.now());
  const checks: DoctorCheck[] = [];
  const apiKey = target.api_key_env ? env[target.api_key_env] : undefined;
  const baseUrl = target.base_url ?? 'http://localhost:11434';
  const timed = async <T>(name: string, fn: () => Promise<{ ok: boolean; detail: string; value?: T }>) => {
    const started = now();
    try {
      const r = await fn();
      checks.push({ name, ok: r.ok, detail: r.detail, ms: now() - started });
      return r.value;
    } catch (err) {
      checks.push({ name, ok: false, detail: err instanceof Error ? err.message : String(err), ms: now() - started });
      return undefined;
    }
  };
  const http = deps.fetch ?? fetch;
  const headers = { ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) };

  // 1. Endpoint and model list.
  await timed('endpoint', async () => {
    const origin = originOf(baseUrl);
    const url = target.provider === 'ollama' ? `${origin}/api/tags` : `${origin}/v1/models`;
    const res = await http(url, { headers, signal: AbortSignal.timeout(5_000) });
    if (!res.ok) return { ok: false, detail: `${url} answered ${res.status}` };
    const body = (await res.json()) as {
      data?: Array<{ id: string }>;
      models?: Array<{ name: string; model?: string }>;
    };
    const ids = body.data?.map((m) => m.id) ?? body.models?.map((m) => m.name) ?? [];
    const present = ids.some((id) => id === target.model || id.split(':')[0] === target.model.split(':')[0]);
    return {
      ok: present || ids.length === 0,
      detail: `${ids.length} model(s) listed${ids.length ? `: ${ids.slice(0, 20).join(', ')}` : ''}${present ? '' : ids.length ? ` — ${target.model} not among them` : ''}`,
    };
  });

  // 2. Context window.
  const detected =
    (await timed<DetectedProfile>('context', async () => {
      const d = await detectModelProfile({ baseUrl, model: target.model, ...(apiKey ? { apiKey } : {}), fetch: http });
      const catalog = resolveProfile(target.model);
      const window = target.context_window ?? target.num_ctx ?? d.numCtx ?? d.contextWindow ?? catalog.contextWindow;
      const source = target.context_window
        ? 'config'
        : d.numCtx
          ? 'num_ctx of the loaded model'
          : d.contextWindow
            ? d.source
            : 'catalog';
      return { ok: true, detail: `${window.toLocaleString()} tokens (${source})`, value: d };
    })) ?? ({ source: 'none' } as DetectedProfile);
  const catalog = resolveProfile(target.model, {
    ...(target.context_window ? { contextWindow: target.context_window } : {}),
    ...(target.max_output ? { maxOutput: target.max_output } : {}),
  });
  const contextWindow =
    target.context_window ?? target.num_ctx ?? detected.numCtx ?? detected.contextWindow ?? catalog.contextWindow;
  const budget = contextBudgetFor(
    { maxContext: contextWindow, maxOutput: catalog.maxOutput },
    { maxOutputTokens: 32_000 },
  );

  const base: LlmProvider =
    target.provider === 'ollama'
      ? new OllamaProvider({
          baseUrl,
          model: target.model,
          numCtx: target.num_ctx ?? contextWindow,
          profile: { contextWindow, toolMode: 'native' },
          fetch: http,
          timeoutMs: 120_000,
        })
      : new OpenAICompatibleProvider({
          baseUrl,
          model: target.model,
          ...(apiKey ? { apiKey } : {}),
          profile: { contextWindow, toolMode: 'native' },
          fetch: http,
          timeoutMs: 120_000,
          maxRetries: 0,
        });
  const probeTool = {
    name: 'echo_probe',
    description: 'Echo the value back to the caller.',
    inputSchema: {
      type: 'object',
      properties: { value: { type: 'string' } },
      required: ['value'],
      additionalProperties: false,
    },
  };
  const request = (over: Partial<CompletionRequest>): CompletionRequest => ({
    system: 'You are a test harness. Follow the instruction exactly.',
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'Call the tool echo_probe with value "ok". Do nothing else.' }] },
    ],
    tools: [probeTool],
    maxTokens: 200,
    toolChoice: 'required',
    metadata: { role: 'doctor' },
    ...over,
  });
  const echoed = (r: Awaited<ReturnType<LlmProvider['complete']>>) =>
    r.content.some(
      (b) => b.type === 'tool_use' && b.name === 'echo_probe' && (b.input as { value?: string })?.value === 'ok',
    );

  // 3. Native tool call.
  const native = await timed<boolean>('native tool call', async () => {
    const r = await base.complete(request({}));
    const ok = echoed(r);
    return {
      ok,
      detail: ok ? 'tool_use echo_probe{value:"ok"} received' : `no usable tool call (stop ${r.stopReason})`,
      value: ok,
    };
  });

  // 4. Prompted tool call.
  const prompted = await timed<boolean>('prompted tool call', async () => {
    const r = await withPromptedTools(base).complete(request({}));
    const ok = echoed(r);
    return { ok, detail: ok ? '<tool_call> parsed from text' : 'reply contained no parseable tool call', value: ok };
  });

  // 5. Structured JSON.
  const json = await timed<boolean>('json submit', async () => {
    const r = await runStructured({
      provider: base,
      role: 'doctor',
      system: 'You are a test harness. Follow the instruction exactly.',
      prompt: 'Answer with verdict "ok" and a one-sentence reason.',
      schema: Probe,
      maxAttempts: 2,
      maxOutputTokens: 200,
    });
    return {
      ok: r.status === 'COMPLETED',
      detail: r.status === 'COMPLETED' ? `valid JSON after ${r.steps.length} attempt(s)` : (r.error ?? r.status),
      value: r.status === 'COMPLETED',
    };
  });

  // 6. Throughput.
  const tokensPerSecond: DoctorReport['tokensPerSecond'] = {};
  await timed('throughput', async () => {
    const started = now();
    const gen = await base.complete(
      request({
        tools: [],
        toolChoice: 'auto',
        maxTokens: 256,
        messages: [
          {
            role: 'user',
            content: [{ type: 'text', text: 'Write about 200 words describing how HTTP caching works.' }],
          },
        ],
      }),
    );
    const genMs = Math.max(1, now() - started);
    tokensPerSecond.generate = Math.round((gen.usage.outputTokens / genMs) * 1000 * 10) / 10;
    const filler = 'The quick brown fox jumps over the lazy dog. '.repeat(360);
    const started2 = now();
    const pre = await base.complete(
      request({
        tools: [],
        toolChoice: 'auto',
        maxTokens: 8,
        messages: [{ role: 'user', content: [{ type: 'text', text: `${filler}\nReply with the single word: done.` }] }],
      }),
    );
    const preMs = Math.max(1, now() - started2);
    tokensPerSecond.prefill = Math.round((pre.usage.inputTokens / preMs) * 1000);
    return {
      ok: true,
      detail: `${tokensPerSecond.generate} tok/s generation, ~${tokensPerSecond.prefill} tok/s prefill`,
    };
  });

  const toolMode: DoctorReport['toolMode'] = native ? 'native' : prompted ? 'prompted' : json ? 'none' : 'unsupported';
  const warnings: string[] = [];
  if (toolMode === 'none')
    warnings.push(
      'no tool calling: only single-shot shard investigation (tool_mode none) works; standard roles need tools',
    );
  if (toolMode === 'unsupported')
    warnings.push('neither tool calls nor structured JSON work: this model cannot drive the agent');
  if (contextWindow < 16_000)
    warnings.push(`context window ${contextWindow} is very small; expect heavy compaction and lite deliverables`);
  if ((tokensPerSecond.generate ?? 0) > 0 && (tokensPerSecond.generate as number) < 15)
    warnings.push(
      'generation below 15 tok/s: a large repository will take hours; keep map_workers at 1 and shards small',
    );
  const alias = target.provider === 'ollama' ? 'local' : 'local';
  const recommendation = {
    ai: {
      models: {
        [alias]: {
          provider: target.provider,
          model: target.model,
          ...(target.base_url ? { base_url: target.base_url } : {}),
          ...(target.api_key_env ? { api_key_env: target.api_key_env } : {}),
          context_window: contextWindow,
          ...(target.provider === 'ollama' ? { num_ctx: target.num_ctx ?? contextWindow } : {}),
          max_output: catalog.maxOutput,
          tool_mode: toolMode === 'unsupported' ? 'none' : toolMode,
          temperature: 0,
        },
      },
      routing: { deep: alias, fast: alias, judge: alias, map: alias, reduce: alias, summarize: alias },
      parallel: { map_workers: target.provider === 'ollama' ? 1 : 2 },
      sharding: { enabled: 'auto' },
    },
  };
  return {
    provider: target.provider,
    model: target.model,
    ...(target.base_url ? { baseUrl: target.base_url } : {}),
    checks,
    detected,
    contextWindow,
    effectiveWindow: budget.effective,
    compactThreshold: budget.compactThreshold,
    toolMode,
    tokensPerSecond,
    recommendation: { yaml: toYaml(recommendation), warnings },
    ok:
      toolMode !== 'unsupported' &&
      checks.filter((c) => c.name !== 'throughput').every((c) => c.ok || c.name === 'endpoint'),
  };
}

export function doctorTarget(options: DoctorOptions): AiModelConfig {
  if (options.alias) {
    const loaded = loadConfig(options.config);
    const m = loaded.config.ai?.models?.[options.alias];
    if (!m) throw new CliError(`ai.models.${options.alias} is not defined in the configuration`);
    return m;
  }
  const loaded = options.provider || options.model ? undefined : loadConfig(options.config);
  const provider = (options.provider ?? loaded?.config.ai?.provider ?? 'ollama') as AiModelConfig['provider'];
  if (!['anthropic', 'openai-compatible', 'ollama', 'scripted'].includes(provider))
    throw new CliError(`unknown provider "${provider}"`);
  if (provider === 'anthropic' || provider === 'scripted')
    throw new CliError('ai doctor checks self-hosted endpoints (openai-compatible or ollama)');
  const model = options.model ?? loaded?.config.ai?.model;
  if (!model) throw new CliError('--model is required (or ai.model in the configuration)');
  const baseUrl =
    options.baseUrl ?? loaded?.config.ai?.base_url ?? (provider === 'ollama' ? 'http://localhost:11434' : undefined);
  if (!baseUrl) throw new CliError('--base-url is required for openai-compatible endpoints');
  return {
    provider,
    model,
    base_url: baseUrl,
    api_key_env: options.apiKeyEnv ?? loaded?.config.ai?.api_key_env ?? 'SPINXSCA_LLM_API_KEY',
    tool_mode: 'auto',
  };
}

export async function aiDoctorCommand(options: DoctorOptions): Promise<number> {
  const report = await runDoctor(doctorTarget(options));
  if (options.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.ok ? EXIT.OK : EXIT.ERROR;
  }
  const lines = [
    `${pc.bold('spinxsca ai doctor')} · ${report.provider} ${report.model}${report.baseUrl ? ` @ ${report.baseUrl}` : ''}`,
    ...report.checks.map(
      (c) =>
        `${c.ok ? pc.green('ok  ') : pc.red('FAIL')} ${c.name.padEnd(20)} ${c.detail}${c.ms !== undefined ? pc.dim(` (${c.ms} ms)`) : ''}`,
    ),
    '',
    `${pc.dim('context')}   ${report.contextWindow.toLocaleString()} tokens · effective ${report.effectiveWindow.toLocaleString()} · compaction from ${report.compactThreshold.toLocaleString()}`,
    `${pc.dim('tool mode')} ${report.toolMode}`,
    ...report.recommendation.warnings.map((w) => pc.yellow(`warning: ${w}`)),
    '',
    pc.bold('Recommended configuration (spinxsca.yaml):'),
    report.recommendation.yaml.trimEnd(),
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
  return report.ok ? EXIT.OK : EXIT.ERROR;
}

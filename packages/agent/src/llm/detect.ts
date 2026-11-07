/**
 * Endpoint probing for self-hosted models (ADR-053). Ollama, vLLM and LM Studio all know the context
 * length of the model they serve; asking them beats guessing from the model name. Every probe is
 * best effort: it never throws and gives up after a short timeout.
 */

export interface DetectedProfile {
  contextWindow?: number;
  maxOutput?: number;
  /** Ollama `num_ctx` parameter of the loaded model (the window actually used). */
  numCtx?: number;
  source: 'ollama-show' | 'vllm-models' | 'lmstudio-models' | 'none';
  raw?: unknown;
}

export interface DetectOptions {
  /** Base URL as configured (with or without a trailing `/v1`). */
  baseUrl: string;
  model: string;
  apiKey?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/** `http://host:11434/v1` -> `http://host:11434` */
export function originOf(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '').replace(/\/v1$/, '');
}

export async function detectModelProfile(options: DetectOptions): Promise<DetectedProfile> {
  const http = options.fetch ?? fetch;
  const timeout = options.timeoutMs ?? 2_000;
  const origin = originOf(options.baseUrl);
  const headers = {
    'content-type': 'application/json',
    ...(options.apiKey ? { authorization: `Bearer ${options.apiKey}` } : {}),
  };
  const get = async (url: string, init: RequestInit = {}): Promise<unknown> => {
    try {
      const res = await http(url, { ...init, headers, signal: AbortSignal.timeout(timeout) });
      if (!res.ok) return undefined;
      return await res.json();
    } catch {
      return undefined;
    }
  };

  const show = (await get(`${origin}/api/show`, { method: 'POST', body: JSON.stringify({ model: options.model }) })) as
    | { model_info?: Record<string, unknown>; parameters?: string }
    | undefined;
  if (show && (show.model_info || show.parameters)) {
    const info = show.model_info ?? {};
    const key = Object.keys(info).find((k) => k.endsWith('.context_length'));
    const contextWindow = key ? asInt(info[key]) : undefined;
    const numCtx = /(?:^|\n)\s*num_ctx\s+(\d+)/.exec(show.parameters ?? '')?.[1];
    return {
      ...(contextWindow !== undefined ? { contextWindow } : {}),
      ...(numCtx ? { numCtx: Number(numCtx) } : {}),
      source: 'ollama-show',
      raw: show,
    };
  }

  const models = (await get(`${origin}/v1/models`)) as { data?: Array<Record<string, unknown>> } | undefined;
  const entry = models?.data?.find((m) => m.id === options.model) ?? models?.data?.[0];
  if (entry && entry.max_model_len !== undefined) {
    const contextWindow = asInt(entry.max_model_len);
    return { ...(contextWindow !== undefined ? { contextWindow } : {}), source: 'vllm-models', raw: entry };
  }

  const lm = (await get(`${origin}/api/v0/models`)) as { data?: Array<Record<string, unknown>> } | undefined;
  const lmEntry = lm?.data?.find((m) => m.id === options.model);
  if (lmEntry && lmEntry.max_context_length !== undefined) {
    const contextWindow = asInt(lmEntry.max_context_length);
    return { ...(contextWindow !== undefined ? { contextWindow } : {}), source: 'lmstudio-models', raw: lmEntry };
  }
  return { source: 'none' };
}

function asInt(value: unknown): number | undefined {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

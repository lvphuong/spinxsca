import { z } from 'zod';
import { Digest } from './common';

/**
 * Sharded investigation of large repositories (ADR-055). A deterministic planner turns signals
 * (endpoints, controls, census rows, scanner hits, selector matches) into shards sized by the map
 * model's token budget; each shard is investigated by one worker and checkpointed on its own.
 */
export const ShardSignal = z.strictObject({
  path: z.string(),
  line: z.number().int().positive().optional(),
  /** `index.endpoint` | `index.control` | `census.flagged` | `census.data_access` | `scanner.<category>` | `lex.<id>` | `ast.<id>` */
  selectorId: z.string().min(1).max(80),
  weight: z.number().int().min(1).max(10),
  /** One redacted line of evidence. */
  evidence: z.string().max(200),
});
export type ShardSignal = z.infer<typeof ShardSignal>;

export const ShardFile = z.strictObject({
  path: z.string(),
  digest: Digest,
  bytes: z.number().int().nonnegative(),
  /** Estimated tokens (bytes / 4). */
  tokens: z.number().int().nonnegative(),
  /** Sum of signal weights. */
  score: z.number().int().nonnegative(),
  signals: z.number().int().nonnegative(),
  language: z.string().optional(),
});
export type ShardFile = z.infer<typeof ShardFile>;

export const Shard = z.strictObject({
  shardId: z.string().regex(/^shard-\d{4}$/),
  /** sha256 of the selector version and every owned file's path and content digest. */
  digest: Digest,
  /** Group key the shard was packed from (directory prefix). */
  module: z.string(),
  files: z.array(ShardFile).min(1),
  tokens: z.number().int().nonnegative(),
  score: z.number().int().nonnegative(),
  /** Rank by score; 0 is investigated first. */
  priority: z.number().int().nonnegative(),
  /** Paths the owned files import or call into; readable context, never owned. */
  neighbors: z.array(z.string()).max(40),
  /** One file larger than the budget on its own. */
  oversized: z.boolean().default(false),
  signals: z.array(ShardSignal).max(400),
});
export type Shard = z.infer<typeof Shard>;

export const ShardPlan = z.strictObject({
  version: z.literal(1),
  selectorVersion: z.string(),
  contentManifestDigest: Digest,
  tokenBudget: z.number().int().positive(),
  mapModel: z.string(),
  shards: z.array(Shard),
  excluded: z.strictObject({
    zeroSignal: z.number().int().nonnegative(),
    /** Files dropped because the plan hit `max_shards`; reported as not investigated. */
    overCap: z.array(z.string()).max(5000),
    binaryOrLarge: z.number().int().nonnegative(),
  }),
  stats: z.strictObject({
    files: z.number().int().nonnegative(),
    candidateFiles: z.number().int().nonnegative(),
    totalTokens: z.number().int().nonnegative(),
    maxShardTokens: z.number().int().nonnegative(),
    modules: z.number().int().nonnegative(),
    signals: z.number().int().nonnegative(),
  }),
});
export type ShardPlan = z.infer<typeof ShardPlan>;

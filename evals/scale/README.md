# Scale evaluation suite (Phase 7)

Measures the sharded investigation (ADR-055) on a repository too large for one review: the case is
generated on the fly by `apps/cli/src/eval/scale-fixture.ts` (deterministic for a seed), so the
suite runs offline and the numbers are comparable between runs. Ground truth is `detectable_by:
[ai]` and counts only with `--ai standard`.

```
pnpm spinxsca eval --suite scale --ai standard --ai-provider scripted          # CI size (300 files)
pnpm spinxsca eval --suite scale --ai standard --ai-provider scripted-weak     # prompted-tool double
pnpm tsx scripts/gen-scale-fixture.ts --files 2000 --loc 300000 --planted 40 --out /tmp/scale
pnpm spinxsca scan /tmp/scale --ai standard --ai-provider scripted --shards on --map-workers 4 --json
```

The scripted map provider turns SQL and census signals in the files a shard owns into findings and
keeps everything in the reducer, so recall measures the planner (did every planted file get a shard
and a signal) and the pipeline (ownership rule, dedup, reconciliation), not model quality. With a
real model (`--ai-provider anthropic`, or `ai.models` routed to a local endpoint) the same suite
measures recall, tokens per shard and wall time of the actual review.

Reported per run: `ai.shards` (planned, completed, failed, reused, overCap), duration, peak RSS.

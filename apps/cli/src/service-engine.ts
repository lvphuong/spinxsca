import type { Logger } from '@spinxsca/core';
import type { EngineFactory } from '@spinxsca/server';
import { autonomyConfig, createReviewer, reviewPorts } from './autonomy';
import type { LoadedConfig } from './config';
import { aiOptions } from './context';
import { openEngine, scanDeps } from './engine';

/**
 * Engines for service jobs (control plane worker and remote workers, ADR-047). AI settings and
 * provider credentials come from the configuration of the machine running the job, so a remote
 * worker's keys never leave it; reviews are always unattended (asks park in the inbox).
 */
export function serviceEngineFactory(loaded: LoadedConfig, logger: Logger, kbDir: string): EngineFactory {
  const ai = loaded.config.ai?.level && loaded.config.ai.level !== 'off' ? aiOptions(loaded, {}) : null;
  return ({ sourceDir, stateDir, repo, artifacts, cases }) => {
    const engine = openEngine({
      scanRoot: sourceDir,
      stateDir,
      config: loaded,
      kbDir,
      logger,
      ...(ai ? { ai } : {}),
      ...(repo ? { repo } : {}),
      ...(artifacts ? { artifacts } : {}),
      ...(cases ? { cases } : {}),
    });
    return {
      deps: scanDeps(engine),
      close: () => engine.close(),
      ...(ai
        ? {
            ai: { level: ai.level, maxFindings: ai.maxFindings, maxCostUsd: ai.maxCostUsd },
            review: (input: { goal?: string; objectives?: readonly string[] }) => ({
              reviewer: createReviewer({
                ai,
                loaded,
                config: autonomyConfig(loaded, { unattended: true }, ai.maxCostUsd),
                ...(input.goal ? { goal: input.goal } : {}),
                ...(input.objectives?.length ? { objectives: input.objectives } : {}),
                onEvent: (e) => logger.info(`[${e.type}] ${e.message}`, { caseId: e.caseId }),
              }),
              ports: reviewPorts(engine, loaded),
            }),
          }
        : {}),
    };
  };
}

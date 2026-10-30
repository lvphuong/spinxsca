import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { type SpinxscaConfig, SpinxscaConfig as SpinxscaConfigSchema } from '@spinxsca/schemas';
import { parse } from 'yaml';
import { CliError } from './ui';

export const CONFIG_FILENAME = 'spinxsca.yaml';

export interface LoadedConfig {
  config: SpinxscaConfig;
  /** Absolute path of the file, or undefined when defaults are used. */
  path?: string;
}

/**
 * Loads operator configuration (ADR-025). Only an explicit `--config` path or `spinxsca.yaml` in the
 * current working directory is read; a config file inside the scanned repository is never
 * auto-discovered, so a repository cannot change how it is scanned.
 */
export function loadConfig(explicitPath: string | undefined, cwd = process.cwd()): LoadedConfig {
  const path = explicitPath ? resolve(cwd, explicitPath) : resolve(cwd, CONFIG_FILENAME);
  if (!existsSync(path)) {
    if (explicitPath) throw new CliError(`config file not found: ${path}`, 2);
    return { config: SpinxscaConfigSchema.parse({ version: 1 }) };
  }
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new CliError(`invalid YAML in ${path}: ${(err as Error).message}`, 2);
  }
  const parsed = SpinxscaConfigSchema.safeParse(raw ?? {});
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n');
    throw new CliError(`invalid configuration in ${path}:\n${issues}`, 2);
  }
  return { config: parsed.data, path };
}

/** Extra rule directories from config, resolved relative to the config file. */
export function configRuleDirs(loaded: LoadedConfig): string[] {
  const dirs = loaded.config.scan?.scanners?.semgrep?.rule_dirs ?? [];
  const base = loaded.path ? dirname(loaded.path) : process.cwd();
  return dirs.map((d) => resolve(base, d));
}

export const DEFAULT_CONFIG_YAML = `# spinxsca configuration (docs/architecture/05-cli-va-tich-hop.md section 3).
# Unknown keys are rejected. This file is read from the current directory or via --config;
# it is never picked up from inside the repository being scanned.
version: 1

scan:
  # Glob patterns excluded from the snapshot and from every scanner.
  exclude:
    - "**/*.min.js"
  scanners:
    semgrep:
      enabled: true
      # Extra local Semgrep rule directories (relative to this file).
      rule_dirs: []
    osv:
      enabled: true      # dependency advisories from the local knowledge base (spinxsca kb sync)
    gitleaks:
      enabled: true      # hardcoded secrets
    trivy:
      enabled: true      # Dockerfile / Kubernetes / Terraform misconfigurations
      min_severity: medium

# knowledge_base:
#   dir: ~/.spinxsca/kb   # default; shared by all projects on this machine

ai:
  # off | explain. With explain, new code findings are validated by the model and redacted
  # code excerpts are sent to the provider. Requires ANTHROPIC_API_KEY or 'ant auth login'.
  level: off
  provider: anthropic
  # model: claude-opus-5-5
  effort: high
  refusal_fallback: default
  max_cost_usd_per_scan: 5
  max_findings: 20
  send_source_snippets: true

policy:
  # Exit with code 1 when a finding at or above this severity is present.
  # fail_on_severity: high
  # Gate only on findings that are new relative to the baseline.
  new_findings_only: true

output:
  formats: [sarif, md, json]
`;

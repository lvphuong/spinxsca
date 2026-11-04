import type { PocOracle, PocResult } from '@spinxsca/schemas';

/** What one sandboxed harness run left behind. */
export interface RunEvidence {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Files the run wrote into the oracle directory (name → content). */
  oracleFiles: Record<string, string>;
}

/**
 * Markers the host plants per run (ADR-045). The attack run gets the nonce, the control run a
 * different token; both runs use the same harness and only `SPX_MODE` / `SPX_NONCE` differ. The
 * marker of a run can only appear when the vulnerable path processed that run's input.
 */
export function marker(oracle: PocOracle, token: string): string {
  switch (oracle) {
    case 'CANARY_READ':
      return `SPX-CANARY-${token}`;
    case 'COMMAND_MARKER':
      return `spx-cmd-${token}`;
    case 'UNESCAPED_REFLECTION':
      return `<spx-${token}>`;
    case 'DATA_DIFFERENTIAL':
      return `SPX-ROW-${token}`;
  }
}

export function oracleTriggered(oracle: PocOracle, token: string, run: RunEvidence): boolean {
  const m = marker(oracle, token);
  const channels = [run.stdout, run.stderr, ...Object.values(run.oracleFiles)];
  if (oracle === 'COMMAND_MARKER') {
    return (
      Object.keys(run.oracleFiles).some((name) => name.includes(m)) || channels.slice(2).some((c) => c.includes(m))
    );
  }
  return channels.some((c) => c.includes(m));
}

const MISSING_DEPENDENCY =
  /Cannot find module|ERR_MODULE_NOT_FOUND|ModuleNotFoundError|No module named|ClassNotFoundException/;

/**
 * Host decision on a PoC (ADR-045): CONFIRMED only when the attack run shows its own marker and the
 * control run does not show its own; both showing means the harness produces the marker itself.
 * The decision is provisional until an independent validator reviews the harness.
 */
export function decidePoc(input: {
  oracle: PocOracle;
  nonce: string;
  controlToken: string;
  attack: RunEvidence;
  control: RunEvidence;
}): Pick<PocResult, 'outcome' | 'attackTriggered' | 'controlTriggered' | 'detail'> {
  const attackTriggered = oracleTriggered(input.oracle, input.nonce, input.attack);
  const controlTriggered = oracleTriggered(input.oracle, input.controlToken, input.control);
  if (attackTriggered && controlTriggered) {
    return {
      outcome: 'INVALID_HARNESS',
      attackTriggered,
      controlTriggered,
      detail: 'the control run also produced its marker: the harness does not depend on the vulnerability',
    };
  }
  if (attackTriggered)
    return {
      outcome: 'CONFIRMED',
      attackTriggered,
      controlTriggered,
      detail: 'the attack run produced its marker and the control run did not',
    };
  if (MISSING_DEPENDENCY.test(input.attack.stderr) || MISSING_DEPENDENCY.test(input.attack.stdout)) {
    return {
      outcome: 'BLOCKED',
      attackTriggered,
      controlTriggered,
      detail: 'the code under test needs dependencies that are not installed in the workspace',
    };
  }
  if (input.attack.timedOut)
    return { outcome: 'ERROR', attackTriggered, controlTriggered, detail: 'the attack run timed out' };
  return {
    outcome: 'NOT_CONFIRMED',
    attackTriggered,
    controlTriggered,
    detail: 'the attack run did not produce its marker',
  };
}

/**
 * Static checks of harness files: no direct references to the oracle or canary locations or to the
 * marker formats, so the harness has to go through the code under test. The independent review of
 * the harness by a validator remains the main safeguard.
 */
export function lintHarness(files: Readonly<Record<string, string>>): string[] {
  const problems: string[] = [];
  const forbidden: Array<[RegExp, string]> = [
    [/\/oracle\b/, 'refers to the oracle directory; use the code under test to reach it'],
    [/\/canary\b/, 'refers to the canary location; use SPX_CANARY_PATH only as attack input'],
    [/SPX-CANARY-/, 'writes the canary marker itself'],
    [/spx-cmd-/, 'writes the command marker itself'],
    [/SPX_ORACLE_DIR/, 'reads the oracle directory'],
  ];
  for (const [path, content] of Object.entries(files)) {
    for (const [re, why] of forbidden) if (re.test(content)) problems.push(`${path}: ${why}`);
  }
  if (
    Object.keys(files).length &&
    !Object.values(files).some((c) => /SPX_NONCE|SPX_CANARY_PATH|SPX_COMMAND_MARKER/.test(c))
  ) {
    problems.push(
      'build the attack input from SPX_NONCE, SPX_CANARY_PATH or SPX_COMMAND_MARKER (environment variables)',
    );
  }
  if (Object.keys(files).length === 0) problems.push('no harness files were written');
  return problems;
}

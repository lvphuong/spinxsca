import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSecretScrubber, type SourceTree } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import { DockerSandboxRunner, localValidationPort } from '../src/index';

const nodeImagePresent = (() => {
  try {
    execFileSync('docker', ['image', 'inspect', 'node:22-alpine'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

const VULNERABLE = [
  "const fs = require('fs');",
  "const path = require('path');",
  "const base = path.join(__dirname, 'public');",
  'exports.read = (name) => fs.readFileSync(path.join(base, name), "utf8");',
].join('\n');
const FIXED = [
  "const fs = require('fs');",
  "const path = require('path');",
  "const base = path.join(__dirname, 'public');",
  'exports.read = (name) => {',
  '  const target = path.resolve(base, name);',
  "  if (!target.startsWith(base + path.sep)) throw new Error('outside public');",
  '  return fs.readFileSync(target, "utf8");',
  '};',
].join('\n');
const HARNESS = [
  "const path = require('path');",
  "const { read } = require('../src/files.js');",
  "const publicDir = path.join(__dirname, '..', 'src', 'public');",
  "const input = process.env.SPX_MODE === 'attack' ? path.relative(publicDir, process.env.SPX_CANARY_PATH) : 'index.html';",
  'try { console.log(read(input)); } catch (e) { console.log("refused: " + e.message); }',
].join('\n');
const CHEATING = "console.log(require('fs').readFileSync(process.env.SPX_CANARY_PATH, 'utf8'));";

function tree(files: Record<string, string>): SourceTree {
  return {
    root: '/nonexistent',
    listFiles: async () => [],
    readText: async (p) => files[p],
    gitInfo: async () => undefined,
  };
}

describe.runIf(nodeImagePresent)('L3 validation in the sandbox (docker)', () => {
  async function poc(code: string, harness: string) {
    const root = mkdtempSync(join(tmpdir(), 'spx-poc-'));
    try {
      const files = { 'src/files.js': code, 'src/public/index.html': '<h1>hello</h1>' };
      const port = localValidationPort({
        sandbox: new DockerSandboxRunner(),
        source: tree(Object.fromEntries(Object.entries(files).map(([k, v]) => [k.replace(/^src\//, ''), v]))),
        paths: ['files.js', 'public/index.html'],
        root,
        scrubber: createSecretScrubber(),
        timeoutSec: 60,
      });
      const ws = await port.open('CF-1');
      expect(port.workspaces()).toEqual([ws.workspaceId]);
      await port.writeHarness(ws.workspaceId, 'poc.js', harness);
      await expect(port.writeHarness(ws.workspaceId, '../escape.js', 'x')).rejects.toThrow('inside harness');
      const result = await port.run({
        workspaceId: ws.workspaceId,
        handle: 'CF-1',
        command: ['node', 'harness/poc.js'],
        oracle: 'CANARY_READ',
      });
      expect(await port.lastRun(ws.workspaceId, 'CF-1')).toEqual(result);
      return result;
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  it('confirms a real path traversal and not its fix', async () => {
    const vulnerable = await poc(VULNERABLE, HARNESS);
    expect(vulnerable).toMatchObject({ outcome: 'CONFIRMED', attackTriggered: true, controlTriggered: false });
    expect(vulnerable.attackLog).toContain('SPX-CANARY-<NONCE>');
    const fixed = await poc(FIXED, HARNESS);
    expect(fixed).toMatchObject({ outcome: 'NOT_CONFIRMED', attackTriggered: false });
    expect(fixed.attackLog).toContain('refused: outside public');
  }, 120_000);

  it('rejects a harness that reads the canary itself', async () => {
    const result = await poc(VULNERABLE, CHEATING);
    expect(result).toMatchObject({ outcome: 'INVALID_HARNESS', attackTriggered: true, controlTriggered: true });
  }, 120_000);

  it('refuses interpreters and paths outside the allow-list', async () => {
    const root = mkdtempSync(join(tmpdir(), 'spx-poc-'));
    try {
      const port = localValidationPort({
        sandbox: new DockerSandboxRunner(),
        source: tree({ 'a.js': '' }),
        paths: ['a.js'],
        root,
        scrubber: createSecretScrubber(),
      });
      const ws = await port.open('CF-2');
      await expect(
        port.run({
          workspaceId: ws.workspaceId,
          handle: 'CF-2',
          command: ['bash', '-c', 'id'],
          oracle: 'COMMAND_MARKER',
        }),
      ).rejects.toThrow('interpreter');
      await expect(
        port.run({
          workspaceId: ws.workspaceId,
          handle: 'CF-2',
          command: ['node', '/etc/passwd'],
          oracle: 'COMMAND_MARKER',
        }),
      ).rejects.toThrow('relative');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

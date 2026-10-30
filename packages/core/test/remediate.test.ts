import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { unifiedDiff } from '../src/diff';
import { applyPatchEdits } from '../src/use-cases/remediate';

describe('unifiedDiff', () => {
  it('produces hunks with context and no output for identical text', () => {
    const a = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].join('\n');
    const b = ['a', 'b', 'c', 'D', 'e', 'f', 'g', 'h'].join('\n');
    const diff = unifiedDiff(a, b, 'x.js');
    expect(diff.split('\n')).toEqual([
      '--- a/x.js',
      '+++ b/x.js',
      '@@ -1,7 +1,7 @@',
      ' a',
      ' b',
      ' c',
      '-d',
      '+D',
      ' e',
      ' f',
      ' g',
    ]);
    expect(unifiedDiff(a, a, 'x.js')).toBe('');
  });
});

describe('applyPatchEdits', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const workspace = (text: string) => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-edit-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'a.js'), text);
    return dir;
  };
  const proposal = (edits: Array<{ path: string; startLine: number; endLine: number; replacement: string }>) => ({
    summary: 's',
    edits: edits.map((e) => ({ ...e, rationale: 'r' })),
    behaviourPreserved: 'b',
    tests: [],
    residualRisk: [],
  });

  it('replaces inclusive line ranges, applying bottom-up', () => {
    const dir = workspace('1\n2\n3\n4\n5\n');
    const originals = new Map<string, string>();
    applyPatchEdits(
      dir,
      proposal([
        { path: 'a.js', startLine: 2, endLine: 2, replacement: 'two\n2b' },
        { path: 'a.js', startLine: 4, endLine: 5, replacement: '' },
      ]),
      ['a.js'],
      originals,
    );
    expect(readFileSync(join(dir, 'a.js'), 'utf8')).toBe('1\ntwo\n2b\n3\n');
    expect(originals.get('a.js')).toBe('1\n2\n3\n4\n5\n');
  });

  it('rejects edits outside the snapshot, overlapping or past the end of file', () => {
    const dir = workspace('1\n2\n3\n');
    expect(() =>
      applyPatchEdits(
        dir,
        proposal([{ path: 'b.js', startLine: 1, endLine: 1, replacement: 'x' }]),
        ['a.js'],
        new Map(),
      ),
    ).toThrow('not a file of the snapshot');
    expect(() =>
      applyPatchEdits(
        dir,
        proposal([
          { path: 'a.js', startLine: 1, endLine: 2, replacement: 'x' },
          { path: 'a.js', startLine: 2, endLine: 3, replacement: 'y' },
        ]),
        ['a.js'],
        new Map(),
      ),
    ).toThrow('overlapping');
    expect(() =>
      applyPatchEdits(
        dir,
        proposal([{ path: 'a.js', startLine: 3, endLine: 9, replacement: 'x' }]),
        ['a.js'],
        new Map(),
      ),
    ).toThrow('has 4 lines');
  });
});

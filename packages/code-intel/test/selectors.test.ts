import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '@spinxsca/core';
import { afterAll, describe, expect, it } from 'vitest';
import { SignalCache, scanAst } from '../src/index';

const dir = mkdtempSync(join(tmpdir(), 'spinxsca-selectors-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('AST selectors (ADR-055)', () => {
  it('matches call nodes but not the same text in comments or strings', async () => {
    const py = await scanAst(
      'views.py',
      '# os.system("x")\ndef h(cmd):\n    s = "os.system(cmd)"\n    os.system(cmd)\n',
    );
    expect(py.map((s) => [s.selectorId, s.line])).toEqual([['ast.rce.py_call', 4]]);
    const js = await scanAst(
      'run.js',
      "const { exec } = require('child_process');\nexec(cmd);\ndb.query(`select * from t where id = ${id}`);\n",
    );
    expect(js.map((s) => s.selectorId)).toEqual(expect.arrayContaining(['ast.rce.js_call', 'ast.sqli.js_query']));
    expect(await scanAst('notes.md', 'os.system(x)')).toEqual([]);
  });

  it('caches signals per file content', async () => {
    const cache = new SignalCache(join(dir, 'code-intel.db'));
    let reads = 0;
    const input = {
      files: [{ path: 'views.py', digest: sha256('v1'), size: 40 }],
      readText: async () => {
        reads++;
        return 'def h(cmd):\n    os.system(cmd)\n';
      },
    };
    const first = await cache.signals(input);
    const second = await cache.signals(input);
    cache.close();
    expect(first).toEqual(second);
    expect(first).toHaveLength(1);
    expect(reads).toBe(1);
  });
});

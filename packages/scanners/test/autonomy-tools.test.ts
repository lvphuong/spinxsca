import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SourceTree } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import { gitHistorySecrets, PINNED_IMAGES, parseLockfiles, reproducesSeed, validateAgentRules } from '../src/index';

function tree(files: Record<string, string>): SourceTree {
  return { root: '/', listFiles: async () => [], readText: async (p) => files[p], gitInfo: async () => undefined };
}

describe('lockfile inventory', () => {
  it('reads npm lockfiles with direct and development scope (case 005)', async () => {
    const lock = readFileSync(
      join(import.meta.dirname, '../../../evals/internal/005-dep-cve-npm/package-lock.json'),
      'utf8',
    );
    const deps = await parseLockfiles(tree({ 'package-lock.json': lock }), ['package-lock.json']);
    expect(deps.find((d) => d.name === 'lodash')).toMatchObject({
      ecosystem: 'npm',
      version: '4.17.15',
      direct: true,
      scope: 'runtime',
      purl: 'pkg:npm/lodash@4.17.15',
    });
  });

  it('distinguishes runtime, development and transitive packages', async () => {
    const npm = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { express: '^4' }, devDependencies: { jest: '^29' } },
        'node_modules/express': { version: '4.18.0' },
        'node_modules/qs': { version: '6.0.0' },
        'node_modules/jest': { version: '29.0.0', dev: true },
        'node_modules/@babel/core': { version: '7.0.0', dev: true },
      },
    });
    const pnpm = [
      'lockfileVersion: "9.0"',
      'importers:',
      '  .:',
      '    dependencies:',
      '      express: { specifier: ^4, version: 4.18.0 }',
      '    devDependencies:',
      '      vitest: { specifier: ^1, version: 1.0.0 }',
      'packages:',
      '  express@4.18.0: {}',
      '  qs@6.0.0: {}',
      '  vitest@1.0.0: {}',
      '  chai@4.0.0: {}',
      'snapshots:',
      '  express@4.18.0:',
      '    dependencies: { qs: 6.0.0 }',
      '  qs@6.0.0: {}',
      '  vitest@1.0.0:',
      '    dependencies: { chai: 4.0.0 }',
      '  chai@4.0.0: {}',
    ].join('\n');
    const poetry =
      '[[package]]\nname = "Requests"\nversion = "2.19.0"\ncategory = "main"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ncategory = "dev"\n';
    const pyproject =
      '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2"\n\n[tool.poetry.group.dev.dependencies]\npytest = "^7"\n';
    const pom =
      '<project><properties><log4j.version>2.14.1</log4j.version></properties><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency></dependencies></project>';
    const deps = await parseLockfiles(
      tree({
        'package-lock.json': npm,
        'web/pnpm-lock.yaml': pnpm,
        'api/poetry.lock': poetry,
        'api/pyproject.toml': pyproject,
        'requirements-dev.txt': 'flake8==6.0.0\n# comment\nrequests[security]==2.31.0\n',
        'java/pom.xml': pom,
      }),
      [
        'package-lock.json',
        'web/pnpm-lock.yaml',
        'api/poetry.lock',
        'requirements-dev.txt',
        'java/pom.xml',
        'README.md',
      ],
    );
    const find = (name: string, path?: string) =>
      deps.find((d) => d.name === name && (!path || d.manifestPath === path));
    expect(find('express', 'package-lock.json')).toMatchObject({ direct: true, scope: 'runtime' });
    expect(find('qs', 'package-lock.json')).toMatchObject({ direct: false, scope: 'runtime' });
    expect(find('@babel/core')).toMatchObject({
      direct: false,
      scope: 'development',
      purl: 'pkg:npm/%40babel/core@7.0.0',
    });
    expect(find('qs', 'web/pnpm-lock.yaml')).toMatchObject({ direct: false, scope: 'runtime' });
    expect(find('chai')).toMatchObject({ direct: false, scope: 'development' });
    expect(find('requests', 'api/poetry.lock')).toMatchObject({ ecosystem: 'PyPI', direct: true, scope: 'runtime' });
    expect(find('pytest')).toMatchObject({ direct: true, scope: 'development' });
    expect(find('flake8')).toMatchObject({ scope: 'development', direct: true });
    expect(find('org.apache.logging.log4j:log4j-core')).toMatchObject({ version: '2.14.1', scope: 'runtime' });
    expect(find('junit:junit')).toMatchObject({ scope: 'test' });
  });
});

describe('agent semgrep rules', () => {
  const rule = (extra = '') =>
    `rules:\n  - id: sqli-variant\n    message: SQL built from input\n    severity: ERROR\n    languages: [javascript]\n    pattern: db.query("..." + $X)\n${extra}`;

  it('accepts the closed subset and namespaces ids', () => {
    const check = validateAgentRules(rule());
    expect(check.ok).toBe(true);
    expect(check.ruleIds).toEqual(['ai-probe.sqli-variant']);
    expect(check.yaml).toContain('id: ai-probe.sqli-variant');
    expect(check.yaml).toContain('source: agent');
  });

  it('rejects autofix, path filters, unknown operators and too many rules', () => {
    expect(validateAgentRules(rule('    fix: safe()\n')).problems.join()).toContain('"fix" is not allowed');
    expect(validateAgentRules(rule('    paths: { include: ["/etc"] }\n')).problems.join()).toContain(
      '"paths" is not allowed',
    );
    expect(
      validateAgentRules(
        rule('    patterns:\n      - pattern: x\n      - r2c-internal-project-depends-on: y\n'),
      ).problems.join(),
    ).toContain('r2c-internal-project-depends-on');
    const many = `rules:\n${Array.from({ length: 6 }, (_, i) => `  - id: r${i}xx\n    message: m\n    severity: INFO\n    languages: [python]\n    pattern: x\n`).join('')}`;
    expect(validateAgentRules(many).problems.join()).toContain('at most 5');
    expect(validateAgentRules('rules: nope').ok).toBe(false);
    expect(validateAgentRules('{{{').ok).toBe(false);
  });

  it('requires the seed to be reproduced within two lines', () => {
    const drafts = [{ locations: [{ path: 'src/db.js', startLine: 12 }] }];
    expect(reproducesSeed(drafts, { path: 'src/db.js', line: 10 })).toBe(true);
    expect(reproducesSeed(drafts, { path: 'src/db.js', line: 9 })).toBe(false);
    expect(reproducesSeed(drafts, { path: 'src/other.js', line: 12 })).toBe(false);
  });
});

describe('git history secrets (docker)', () => {
  const gitleaksPresent = (() => {
    try {
      execFileSync('docker', ['image', 'inspect', 'zricethezav/gitleaks:v8.30.1'], { stdio: 'pipe' });
      return true;
    } catch {
      try {
        execFileSync('docker', ['image', 'inspect', `zricethezav/gitleaks@${PINNED_IMAGES.gitleaks.digest}`], {
          stdio: 'pipe',
        });
        return true;
      } catch {
        return false;
      }
    }
  })();

  it.runIf(gitleaksPresent)(
    'finds a secret removed from the worktree without revealing it',
    async () => {
      const { DockerSandboxRunner } = await import('@spinxsca/sandbox');
      const repo = mkdtempSync(join(tmpdir(), 'spx-hist-'));
      const value = ['q8Zr4Kx2', 'Lm9Tv7Wn', '3Bd6Fg1J', 'h5Qs0Uy'].join('');
      const git = (...args: string[]) =>
        execFileSync(
          'git',
          ['-c', 'user.email=t@example.invalid', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args],
          { cwd: repo, stdio: 'pipe' },
        );
      try {
        git('init', '-q');
        writeFileSync(join(repo, 'settings.js'), `const settings = {\n  apiKey: "${value}",\n};\n`);
        git('add', '.');
        git('commit', '-q', '-m', 'add settings');
        writeFileSync(join(repo, 'settings.js'), 'const settings = { apiKey: process.env.API_KEY };\n');
        git('commit', '-qam', 'use env');
        const port = gitHistorySecrets({
          sandbox: new DockerSandboxRunner(),
          repoRoot: repo,
          workDir: join(repo, '..', `${repo.split('/').pop()}-work`),
        });
        const result = await port.scan();
        expect(result.outcome).toBe('RAN');
        expect(result.secrets.length).toBeGreaterThan(0);
        expect(result.secrets[0]).toMatchObject({ path: 'settings.js', line: 2 });
        expect(JSON.stringify(result)).not.toContain(value);
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    },
    120_000,
  );

  it('reports NOT_RUN outside a git repository', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-nogit-'));
    try {
      const result = await gitHistorySecrets({ sandbox: {} as never, repoRoot: dir, workDir: join(dir, 'w') }).scan();
      expect(result).toMatchObject({ outcome: 'NOT_RUN', reason: 'not a git repository' });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

import { describe, expect, it } from 'vitest';
import { cycloneDx, GITLEAKS_CONFIG, locatePackage, manifestEcosystem, secretSpan } from '../src/index';

describe('locatePackage', () => {
  it('points at the npm lockfile entry', () => {
    const lock = [
      '{',
      '  "packages": {',
      '    "node_modules/lodash": {',
      '      "version": "4.17.15",',
      '      "resolved": "x"',
      '    }',
      '  }',
      '}',
    ].join('\n');
    expect(locatePackage(lock, 'package-lock.json', 'lodash', '4.17.15')).toEqual({ startLine: 3, endLine: 6 });
  });

  it('handles requirements files with PEP 503 name variants', () => {
    expect(
      locatePackage('flask==2.3.3\nPython_Dateutil==2.8.0\n', 'requirements.txt', 'python-dateutil', '2.8.0'),
    ).toEqual({
      startLine: 2,
      endLine: 2,
    });
  });

  it('spans the Maven dependency block from groupId to version', () => {
    const pom = [
      '<dependencies>',
      '  <dependency>',
      '    <groupId>org.apache.logging.log4j</groupId>',
      '    <artifactId>log4j-core</artifactId>',
      '    <version>2.14.1</version>',
      '  </dependency>',
      '</dependencies>',
    ].join('\n');
    expect(locatePackage(pom, 'pom.xml', 'org.apache.logging.log4j:log4j-core', '2.14.1')).toEqual({
      startLine: 3,
      endLine: 5,
    });
  });

  it('falls back to line 1 for unknown formats', () => {
    expect(locatePackage('nothing here', 'weird.lock', 'pkg', '1')).toEqual({ startLine: 1, endLine: 1 });
  });
});

describe('manifestEcosystem', () => {
  it('recognises lockfiles and manifests', () => {
    expect(manifestEcosystem('a/package-lock.json')).toBe('npm');
    expect(manifestEcosystem('requirements-dev.txt')).toBe('PyPI');
    expect(manifestEcosystem('svc/pom.xml')).toBe('Maven');
    expect(manifestEcosystem('go.mod')).toBe('Go');
    expect(manifestEcosystem('src/index.js')).toBeUndefined();
  });
});

describe('secretSpan', () => {
  it('locates the quoted token without returning anything but its position', () => {
    const line = '  apiKey: "q8Zr4Kx2Lm9Tv7Wn3Bd6Fg1Jh5Qs0Uy",';
    const span = secretSpan(line);
    expect(span && line.slice(span.startColumn - 1, span.endColumn - 1)).toBe('q8Zr4Kx2Lm9Tv7Wn3Bd6Fg1Jh5Qs0Uy');
  });

  it('falls back to a long bare token', () => {
    const line = 'TOKEN=Zx9Kq2Lm7Rt4Vb8Nc3Jd6Hf1Gp5Ws0Ya';
    const span = secretSpan(line);
    expect(span?.startColumn).toBe(1);
  });
});

describe('gitleaks configuration', () => {
  it('extends the default rules and excludes spinxsca state', () => {
    expect(GITLEAKS_CONFIG).toContain('useDefault = true');
    expect(GITLEAKS_CONFIG).toContain('\\.spinxsca/');
  });
});

describe('cycloneDx', () => {
  const inventory = [
    {
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.14.1',
      ecosystem: 'Maven',
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      path: 'pom.xml',
    },
    { name: 'lodash', version: '4.17.15', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.15', path: 'package-lock.json' },
    {
      name: 'lodash',
      version: '4.17.15',
      ecosystem: 'npm',
      purl: 'pkg:npm/lodash@4.17.15',
      path: 'web/package-lock.json',
    },
  ];

  it('is deterministic for a snapshot and merges duplicate components', () => {
    const a = cycloneDx(inventory, '2026-10-29T00:00:00Z', 'sha256:abc');
    expect(cycloneDx(inventory, '2026-10-29T00:00:00Z', 'sha256:abc')).toEqual(a);
    expect(a.specVersion).toBe('1.6');
    const components = a.components as Array<Record<string, unknown>>;
    expect(components.map((c) => c['bom-ref'])).toEqual([
      'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      'pkg:npm/lodash@4.17.15',
    ]);
    expect(components[0]).toMatchObject({ group: 'org.apache.logging.log4j', name: 'log4j-core' });
    expect(components[1]?.properties).toHaveLength(3);
    expect(String(a.serialNumber)).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });
});

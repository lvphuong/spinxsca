/**
 * Finds the line of a dependency in its manifest or lockfile so findings point at something a
 * developer can edit. Falls back to line 1 when the format is not recognised.
 */
export function locatePackage(
  text: string,
  manifestPath: string,
  name: string,
  version: string,
): { startLine: number; endLine: number } {
  const lines = text.split(/\r?\n/);
  const file = manifestPath.split('/').pop() ?? manifestPath;
  const find = (predicate: (line: string, index: number) => boolean): number => lines.findIndex(predicate);
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let index = -1;
  let end = -1;
  if (file === 'package-lock.json' || file === 'npm-shrinkwrap.json') {
    index = find((l) => new RegExp(`"(?:[^"]*/)?node_modules/${esc(name)}"\\s*:`).test(l));
    if (index < 0) index = find((l) => new RegExp(`^\\s*"${esc(name)}"\\s*:\\s*\\{`).test(l));
    if (index >= 0) {
      const v = lines.slice(index, index + 8).findIndex((l) => l.includes(`"${version}"`));
      if (v > 0) end = index + v;
      const close = lines.slice(index).findIndex((l) => /^\s*}/.test(l));
      if (close > 0) end = index + close;
    }
  } else if (file === 'yarn.lock') {
    index = find((l) => new RegExp(`^"?${esc(name)}@`).test(l));
  } else if (file === 'pnpm-lock.yaml') {
    index = find((l) => new RegExp(`^\\s*['"]?/?${esc(name)}@${esc(version)}`).test(l));
  } else if (/^requirements.*\.txt$/.test(file)) {
    const norm = name.toLowerCase().replace(/[-_.]+/g, '[-_.]+');
    index = find((l) => new RegExp(`^\\s*${norm}\\s*(\\[[^\\]]*\\])?\\s*(==|>=|<=|~=|!=|>|<|$)`, 'i').test(l));
  } else if (file === 'poetry.lock' || file === 'uv.lock' || file === 'pdm.lock') {
    index = find((l) => new RegExp(`^name\\s*=\\s*"${esc(name)}"`, 'i').test(l));
  } else if (file === 'pom.xml') {
    const [group, artifact] = name.split(':');
    index = find(
      (l, i) =>
        l.includes(`<artifactId>${artifact}</artifactId>`) &&
        lines.slice(Math.max(0, i - 3), i + 4).some((x) => x.includes(`<groupId>${group}</groupId>`)),
    );
    if (index >= 0) {
      const v = lines.slice(index, index + 4).findIndex((l) => l.includes(`<version>${version}</version>`));
      if (v > 0) end = index + v;
      const g = lines.slice(Math.max(0, index - 3), index).findIndex((l) => l.includes(`<groupId>${group}</groupId>`));
      if (g >= 0) index = Math.max(0, index - 3) + g;
    }
  } else if (file.endsWith('gradle.lockfile')) {
    index = find((l) => l.startsWith(`${name}:${version}`));
  } else if (file === 'go.mod') {
    index = find((l) => new RegExp(`(^|\\s)${esc(name)}\\s+v?${esc(version.replace(/^v/, ''))}`).test(l));
  }
  if (index < 0) index = find((l) => l.includes(name));
  if (index < 0) return { startLine: 1, endLine: 1 };
  return { startLine: index + 1, endLine: Math.max(index, end) + 1 };
}

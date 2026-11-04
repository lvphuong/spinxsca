export interface DiffLine {
  kind: 'context' | 'add' | 'remove';
  text: string;
  oldLine?: number;
  newLine?: number;
}

export interface DiffHunk {
  header: string;
  lines: DiffLine[];
}

export interface DiffFile {
  oldPath: string;
  newPath: string;
  hunks: DiffHunk[];
  added: number;
  removed: number;
}

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$/;

/** Parses a unified diff (as produced by the host for patches and harnesses) into files and hunks. */
export function parseUnifiedDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  let file: DiffFile | undefined;
  let hunk: DiffHunk | undefined;
  let oldNo = 0;
  let newNo = 0;
  for (const raw of text.split('\n')) {
    if (raw.startsWith('--- ')) {
      file = { oldPath: raw.slice(4).replace(/^a\//, ''), newPath: '', hunks: [], added: 0, removed: 0 };
      files.push(file);
      hunk = undefined;
      continue;
    }
    if (raw.startsWith('+++ ') && file && !file.newPath) {
      file.newPath = raw.slice(4).replace(/^b\//, '');
      continue;
    }
    const h = HUNK.exec(raw);
    if (h) {
      if (!file) {
        file = { oldPath: '', newPath: '', hunks: [], added: 0, removed: 0 };
        files.push(file);
      }
      oldNo = Number(h[1]);
      newNo = Number(h[3]);
      hunk = { header: raw, lines: [] };
      file.hunks.push(hunk);
      continue;
    }
    if (!hunk || !file) continue;
    if (raw.startsWith('+')) {
      hunk.lines.push({ kind: 'add', text: raw.slice(1), newLine: newNo++ });
      file.added++;
    } else if (raw.startsWith('-')) {
      hunk.lines.push({ kind: 'remove', text: raw.slice(1), oldLine: oldNo++ });
      file.removed++;
    } else if (raw.startsWith(' ') || raw === '') {
      hunk.lines.push({ kind: 'context', text: raw.slice(1), oldLine: oldNo++, newLine: newNo++ });
    }
  }
  // A preview of new content without hunk headers ("+line" lines) becomes one added hunk.
  if (files.length === 0 && text.split('\n').every((l) => l.startsWith('+') || l === '')) {
    const lines = text
      .split('\n')
      .filter(Boolean)
      .map((l, i) => ({ kind: 'add' as const, text: l.slice(1), newLine: i + 1 }));
    return lines.length
      ? [{ oldPath: '', newPath: '', hunks: [{ header: '', lines }], added: lines.length, removed: 0 }]
      : [];
  }
  return files;
}

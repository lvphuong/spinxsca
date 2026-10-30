/** Minimal unified diff (LCS over lines) for patch review output; not a full git diff. */
export function unifiedDiff(original: string, patched: string, path: string, context = 3): string {
  const a = original.split('\n');
  const b = patched.split('\n');
  const ops = lcsOps(a, b);
  const hunks: string[][] = [];
  let i = 0;
  while (i < ops.length) {
    if (ops[i]?.type === 'equal') {
      i++;
      continue;
    }
    const start = Math.max(0, i - context);
    let end = i;
    while (end < ops.length) {
      if (ops[end]?.type !== 'equal') {
        end++;
        continue;
      }
      let run = 0;
      while (end + run < ops.length && ops[end + run]?.type === 'equal') run++;
      if (run > context * 2 || end + run >= ops.length) {
        end += Math.min(run, context);
        break;
      }
      end += run;
    }
    const slice = ops.slice(start, end);
    const aStart = (ops[start]?.a ?? a.length) + 1;
    const bStart = (ops[start]?.b ?? b.length) + 1;
    const aCount = slice.filter((o) => o.type !== 'insert').length;
    const bCount = slice.filter((o) => o.type !== 'delete').length;
    hunks.push([
      `@@ -${aStart},${aCount} +${bStart},${bCount} @@`,
      ...slice.map((o) => (o.type === 'equal' ? ` ${o.text}` : o.type === 'delete' ? `-${o.text}` : `+${o.text}`)),
    ]);
    i = end;
  }
  if (hunks.length === 0) return '';
  return [`--- a/${path}`, `+++ b/${path}`, ...hunks.flat()].join('\n');
}

interface Op {
  type: 'equal' | 'delete' | 'insert';
  text: string;
  a: number;
  b: number;
}

function lcsOps(a: string[], b: string[]): Op[] {
  const n = a.length;
  const m = b.length;
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      (dp[i] as Uint32Array)[j] =
        a[i] === b[j]
          ? ((dp[i + 1] as Uint32Array)[j + 1] as number) + 1
          : Math.max((dp[i + 1] as Uint32Array)[j] as number, (dp[i] as Uint32Array)[j + 1] as number);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ type: 'equal', text: a[i] as string, a: i, b: j });
      i++;
      j++;
    } else if (((dp[i + 1] as Uint32Array)[j] as number) >= ((dp[i] as Uint32Array)[j + 1] as number)) {
      ops.push({ type: 'delete', text: a[i] as string, a: i, b: j });
      i++;
    } else {
      ops.push({ type: 'insert', text: b[j] as string, a: i, b: j });
      j++;
    }
  }
  while (i < n) ops.push({ type: 'delete', text: a[i] as string, a: i++, b: j });
  while (j < m) ops.push({ type: 'insert', text: b[j] as string, a: i, b: j++ });
  return ops;
}

import { parseUnifiedDiff } from '../lib/diff';
import { Icon } from './icons';

/** Side-annotated unified diff: what an approval would change, line by line. */
export function DiffView({ diff }: { diff: string }) {
  const files = parseUnifiedDiff(diff);
  if (files.length === 0) return <pre className="code-block">{diff}</pre>;
  return (
    <div className="diff">
      {files.map((f, fi) => (
        <section key={`${f.newPath}-${fi}`} className="diff-file">
          <header>
            <span className="diff-path">
              <Icon name="file" size={13} />
              {f.newPath || f.oldPath || 'New file'}
            </span>
            <span className="diff-stat">
              <span className="add">+{f.added}</span> <span className="remove">−{f.removed}</span>
            </span>
          </header>
          <div className="diff-scroll">
            <table>
              <tbody>
                {f.hunks.flatMap((h, hi) => [
                  ...(h.header
                    ? [
                        <tr key={`h${hi}`} className="hunk">
                          <td colSpan={3}>{h.header}</td>
                        </tr>,
                      ]
                    : []),
                  ...h.lines.map((l, li) => (
                    <tr key={`${hi}-${li}`} className={l.kind} data-kind={l.kind}>
                      <td className="ln">{l.oldLine ?? ''}</td>
                      <td className="ln">{l.newLine ?? ''}</td>
                      <td className="code">
                        <span className="sign">{l.kind === 'add' ? '+' : l.kind === 'remove' ? '−' : ' '}</span>
                        {l.text}
                      </td>
                    </tr>
                  )),
                ])}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
}

import { describe, expect, it } from 'vitest';
import { ApiClient } from '../src/api/client';
import { parseUnifiedDiff } from '../src/lib/diff';
import { SseParser } from '../src/lib/sse';

describe('SSE parser', () => {
  it('handles split chunks, multi-line data, comments and CRLF', () => {
    const p = new SseParser();
    expect(p.push('event: audit\nid: a1\nda')).toEqual([]);
    expect(p.push('ta: {"seq":1}\n\n: keep-alive\r\nevent: journal\r\ndata: line1\r\ndata: line2\r\n\r\n')).toEqual([
      { event: 'audit', data: '{"seq":1}', id: 'a1' },
      { event: 'journal', data: 'line1\nline2', id: 'a1' },
    ]);
  });
});

describe('unified diff parser', () => {
  it('numbers lines and counts changes per file', () => {
    const files = parseUnifiedDiff(
      [
        '--- a/src/db.js',
        '+++ b/src/db.js',
        '@@ -2,3 +2,3 @@',
        ' const x = 1;',
        '-db.query("..." + id);',
        '+db.query("... ?", [id]);',
        ' end();',
      ].join('\n'),
    );
    expect(files).toHaveLength(1);
    expect(files[0]).toMatchObject({ oldPath: 'src/db.js', newPath: 'src/db.js', added: 1, removed: 1 });
    expect(files[0]?.hunks[0]?.lines.map((l) => `${l.kind}:${l.oldLine ?? ''}:${l.newLine ?? ''}`)).toEqual([
      'context:2:2',
      'remove:3:',
      'add::3',
      'context:4:4',
    ]);
  });

  it('shows new-file previews as additions', () => {
    expect(parseUnifiedDiff('+const a = 1;\n+run(a);')[0]?.added).toBe(2);
  });
});

describe('API client', () => {
  it('sends the launch token and parses the event stream', async () => {
    const seen: Array<{ url: string; auth: string | null }> = [];
    const fake: typeof fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({ url: String(input), auth: headers.get('authorization') });
      if (String(input).includes('/events')) {
        const body = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('event: audit\ndata: {"seq":0,"stage":"case.started"}\n\n'));
            controller.enqueue(new TextEncoder().encode('event: case\ndata: {"status":"CONVERGED"}\n\n'));
            controller.close();
          },
        });
        return new Response(body, { status: 200 });
      }
      return new Response(JSON.stringify({ approvals: [{ approvalId: 'apr_1' }] }), { status: 200 });
    };
    const client = new ApiClient({ baseUrl: 'http://127.0.0.1:5000', token: 't0k' }, fake);
    expect((await client.inbox())[0]?.approvalId).toBe('apr_1');
    const events: string[] = [];
    await client.events('prj', 'case_1', (e) => events.push(`${e.event}:${JSON.stringify(e.data)}`));
    expect(events).toEqual(['audit:{"seq":0,"stage":"case.started"}', 'case:{"status":"CONVERGED"}']);
    expect(seen.every((s) => s.auth === 'Bearer t0k')).toBe(true);
  });
});

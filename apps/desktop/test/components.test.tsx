import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApprovalRecord } from '../src/api/types';
import { ApprovalCard } from '../src/components/ApprovalCard';
import { DiffView } from '../src/components/DiffView';
import { Markdown } from '../src/components/Markdown';
import { isolatedDocument, ReportFrame } from '../src/components/ReportFrame';

afterEach(cleanup);

const approval = (o: Partial<ApprovalRecord> = {}): ApprovalRecord => ({
  approvalId: 'apr_1',
  projectId: 'prj',
  caseId: 'case_1',
  toolCallId: 'call_1',
  tool: 'harness_write',
  risk: 'WRITE_WORKSPACE',
  humanOnly: false,
  title: 'Write the PoC harness file poc.js',
  summary: 'Stays in a sandbox workspace copy.',
  effect: 'workspace',
  targets: [{ kind: 'workspace_path', value: 'ws-cf-1/harness/poc.js' }],
  argsPreview: '{"path":"poc.js"}',
  diff: '+const a = 1;\n+run(a);',
  offeredGrants: ['once', 'case', 'standing'],
  status: 'PENDING',
  requestedAt: '2026-11-01T00:00:00Z',
  ...o,
});

describe('ApprovalCard', () => {
  it('offers the allowed grants and reports the decision', () => {
    const onDecide = vi.fn();
    render(<ApprovalCard approval={approval()} onDecide={onDecide} />);
    expect(screen.getByText('Writes to a workspace copy, not your repository')).toBeTruthy();
    fireEvent.click(screen.getByText('Approve for this review'));
    expect(onDecide).toHaveBeenCalledWith({ decision: 'approve', grant: 'case' });
    fireEvent.click(screen.getByText('Deny'));
    expect(onDecide).toHaveBeenLastCalledWith({ decision: 'deny' });
  });

  it('only allows a one-time human decision for repository changes', () => {
    render(
      <ApprovalCard
        approval={approval({ tool: 'request_apply', risk: 'WRITE_REPO', humanOnly: true, effect: 'repository', offeredGrants: ['once', 'standing'] })}
        onDecide={() => undefined}
      />,
    );
    expect(screen.getByText('Changes your repository')).toBeTruthy();
    expect(screen.getByText('human decision')).toBeTruthy();
    expect(screen.queryByText('Always allow this target')).toBeNull();
    expect(screen.getByText('Approve once')).toBeTruthy();
  });
});

describe('DiffView', () => {
  it('renders added and removed lines with line numbers', () => {
    const { container } = render(<DiffView diff={'--- a/x.js\n+++ b/x.js\n@@ -1,2 +1,2 @@\n-old();\n+safe();\n keep();'} />);
    expect(container.querySelectorAll('tr[data-kind="add"]').length).toBe(1);
    expect(container.querySelectorAll('tr[data-kind="remove"]').length).toBe(1);
    expect(container.textContent).toContain('x.js');
  });
});

describe('Markdown', () => {
  it('drops raw HTML, images and non-https links', () => {
    const { container } = render(
      <Markdown text={'**bold** <script>alert(1)</script> <img src=x onerror=alert(1)> [bad](javascript:alert(1)) [good](https://example.com) ![i](https://example.com/a.png)'} />,
    );
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    const links = [...container.querySelectorAll('a')].map((a) => a.getAttribute('href'));
    expect(links).toEqual([null, 'https://example.com']);
    expect(container.querySelector('strong')?.textContent).toBe('bold');
  });
});

describe('ReportFrame', () => {
  it('renders reports in a fully sandboxed frame with a network-blocking CSP', () => {
    const { container } = render(<ReportFrame title="report" html="<html><head><title>r</title></head><body><script>x()</script></body></html>" />);
    const frame = container.querySelector('iframe');
    expect(frame?.getAttribute('sandbox')).toBe('');
    expect(isolatedDocument('<p>x</p>')).toContain("default-src 'none'");
    expect(frame?.getAttribute('srcdoc')).toContain('Content-Security-Policy');
  });
});

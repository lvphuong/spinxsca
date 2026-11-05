import { expect, type Page, test } from '@playwright/test';

const API = 'http://127.0.0.1:5999';
const TOKEN = 'test-launch-token';
const now = '2026-11-01T00:00:00Z';

const project = {
  projectId: 'srvprj_1',
  name: 'shop-api',
  source: { kind: 'local', path: '/code/shop-api' },
  defaultBranch: 'main',
};
const approvals = [
  {
    approvalId: 'apr_poc',
    projectId: 'srvprj_1',
    caseId: 'case_1',
    toolCallId: 'call_1',
    tool: 'validation_run',
    risk: 'EXEC_REPO_CODE',
    humanOnly: false,
    title: 'Run a proof of concept for CF-1 in the sandbox',
    summary: 'node harness/poc.js · oracle CANARY_READ',
    effect: 'sandbox',
    targets: [{ kind: 'handle', value: 'CF-1' }],
    argsPreview: '{"handle":"CF-1"}',
    offeredGrants: ['once', 'case'],
    status: 'PENDING',
    requestedAt: now,
    project: { projectId: 'srvprj_1', name: 'shop-api' },
  },
  {
    approvalId: 'apr_apply',
    projectId: 'srvprj_1',
    caseId: 'case_1',
    toolCallId: 'apply_1',
    tool: 'request_apply',
    risk: 'WRITE_REPO',
    humanOnly: true,
    title: 'Apply the verified fix for SPX-000001 to your repository',
    summary: 'Re-scan resolved, tests passed.',
    effect: 'repository',
    targets: [{ kind: 'repo_path', value: 'src/db.js' }],
    argsPreview: '{"patchId":"patch_1"}',
    diff: '--- a/src/db.js\n+++ b/src/db.js\n@@ -3,1 +3,1 @@\n-  db.query("SELECT * FROM users WHERE id = " + id);\n+  db.query("SELECT * FROM users WHERE id = ?", [id]);',
    offeredGrants: ['once'],
    status: 'PENDING',
    requestedAt: now,
    project: { projectId: 'srvprj_1', name: 'shop-api' },
  },
];

async function mockApi(page: Page) {
  const decisions: Array<{ url: string; body: unknown; auth: string | undefined }> = [];
  await page.route(`${API}/v1/**`, async (route) => {
    const req = route.request();
    const auth = req.headers().authorization;
    if (auth !== `Bearer ${TOKEN}`) return route.fulfill({ status: 401, json: { error: 'authentication required' } });
    const url = new URL(req.url());
    if (url.pathname === '/v1/health') return route.fulfill({ json: { status: 'ok' } });
    // The real server answers with a bare array.
    if (url.pathname === '/v1/projects') return route.fulfill({ json: [project] });
    if (url.pathname === '/v1/inbox')
      return route.fulfill({
        json: { approvals: approvals.filter((a) => !decisions.some((d) => d.url.endsWith(a.approvalId))) },
      });
    if (req.method() === 'POST' && url.pathname.includes('/approvals/')) {
      decisions.push({ url: url.pathname, body: req.postDataJSON(), auth });
      return route.fulfill({ json: { approval: { status: 'APPROVED' } } });
    }
    if (url.pathname.endsWith('/jobs')) return route.fulfill({ json: [] });
    if (url.pathname.endsWith('/cases')) {
      return route.fulfill({
        json: {
          cases: [
            {
              caseId: 'case_1',
              scanId: 'scan_1',
              goal: 'g',
              mode: 'supervised',
              attended: false,
              status: 'PARKED',
              round: 2,
              createdAt: now,
            },
          ],
        },
      });
    }
    if (url.pathname.endsWith('/events')) {
      const body = [
        `event: audit\ndata: ${JSON.stringify({ seq: 0, stage: 'case.started', at: now, actor: 'host', data: {} })}\n\n`,
        `event: audit\ndata: ${JSON.stringify({ seq: 1, stage: 'policy.decided', at: now, actor: 'agent:exploit/run_1', data: { tool: 'validation_run', outcome: 'ask' } })}\n\n`,
        `event: case\ndata: ${JSON.stringify({ status: 'PARKED' })}\n\n`,
      ].join('');
      return route.fulfill({ status: 200, headers: { 'content-type': 'text/event-stream' }, body });
    }
    if (url.pathname.endsWith('/cases/case_1')) {
      return route.fulfill({
        json: {
          case: {
            caseId: 'case_1',
            scanId: 'scan_1',
            goal: 'g',
            mode: 'supervised',
            attended: false,
            status: 'PARKED',
            stopReason: '1 item(s) wait for a human',
            round: 2,
            createdAt: now,
          },
          objectives: [
            {
              objectiveId: 'o1',
              kind: 'ALL_TRIAGED',
              title: 'Every finding has a verdict',
              status: 'MET',
              reason: 'all findings triaged',
            },
          ],
          items: [],
          handles: [
            {
              handle: 'CF-1',
              title: 'File path built from request data',
              category: 'PATH_TRAVERSAL',
              severity: 'HIGH',
              path: 'src/files.js',
              startLine: 4,
            },
          ],
          verdicts: [
            {
              handle: 'CF-1',
              verdict: 'TRUE_POSITIVE',
              severity: 'HIGH',
              verificationLevel: 'L2_CONTEXT',
              rationale: 'User input reaches `fs.readFile` <script>alert(1)</script>',
            },
          ],
          checks: [{ checkId: 'secrets-history', outcome: 'DEGRADED', reason: 'shallow clone' }],
          ledger: { costUsd: 0.42, modelCalls: 12, sandboxRuns: 3 },
          approvals: [approvals[0]],
        },
      });
    }
    return route.fulfill({ status: 404, json: { error: 'not mocked' } });
  });
  return decisions;
}

test('approvals: sandbox actions offer grants, repository changes are human-only and shown as a diff', async ({
  page,
}) => {
  const decisions = await mockApi(page);
  await page.goto(`/?api=${encodeURIComponent(API)}&token=${TOKEN}`);
  await expect(page.getByRole('button', { name: 'Continue' })).toBeEnabled();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: /Inbox/ }).click();
  const apply = page.getByRole('article', { name: /Apply the verified fix/ });
  await expect(apply.getByText('Changes your repository')).toBeVisible();
  await expect(apply.getByText('human decision')).toBeVisible();
  await expect(apply.getByRole('button', { name: 'Always allow this target' })).toHaveCount(0);
  await expect(apply.locator('tr[data-kind="add"]')).toHaveCount(1);
  const poc = page.getByRole('article', { name: /proof of concept/ });
  await expect(poc.getByText('Stays in the sandbox (no network, copy of your code)')).toBeVisible();
  await poc.getByRole('button', { name: 'Approve for this review' }).click();
  await expect.poll(() => decisions.length).toBe(1);
  expect(decisions[0]).toMatchObject({
    url: '/v1/projects/srvprj_1/approvals/apr_poc',
    body: { decision: 'approve', grant: 'case' },
    auth: `Bearer ${TOKEN}`,
  });
});

test('case view: timeline from the event stream, objectives, coverage and sanitized rationale', async ({ page }) => {
  await mockApi(page);
  await page.goto(`/?api=${encodeURIComponent(API)}&token=${TOKEN}`);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: /shop-api/ }).click();
  // The newest review opens on its own.
  await expect(page.getByRole('button', { name: /case_1/ })).toHaveAttribute('aria-current', 'true');
  await expect(page.getByText('Waiting for your decision')).toBeVisible();
  await page.getByRole('button', { name: /File path built from request data/ }).click();
  await expect(page.locator('.rationale code')).toHaveText('fs.readFile');
  await expect(page.locator('.rationale script')).toHaveCount(0);
  await page.getByRole('tab', { name: /Objectives/ }).click();
  await expect(page.getByText('Every finding has a verdict')).toBeVisible();
  await expect(page.getByText('shallow clone')).toBeVisible();
  await page.getByRole('tab', { name: /Activity/ }).click();
  await expect(page.locator('.timeline li')).toHaveCount(2);
});

test('inbox links each request to its review', async ({ page }) => {
  await mockApi(page);
  await page.goto(`/?api=${encodeURIComponent(API)}&token=${TOKEN}`);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: /Inbox/ }).click();
  const poc = page.getByRole('article', { name: /proof of concept/ });
  await poc.getByRole('button', { name: /Open review/ }).click();
  await expect(page.getByRole('heading', { name: 'shop-api' })).toBeVisible();
  await expect(page.getByRole('button', { name: /case_1/ })).toHaveAttribute('aria-current', 'true');
});

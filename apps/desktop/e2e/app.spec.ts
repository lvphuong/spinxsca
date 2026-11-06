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

const reviewDefaults = {
  available: true,
  mode: 'supervised',
  maxCostUsd: 10,
  maxRounds: 6,
  maxWallClockMin: 90,
  l3: false,
  recon: true,
  criticPasses: 1,
  scanners: ['semgrep', 'osv-scanner', 'gitleaks', 'trivy'],
  provider: 'anthropic',
};

async function mockApi(page: Page, options: { status?: string; jobs?: unknown[] } = {}) {
  const decisions: Array<{ url: string; body: unknown; auth: string | undefined }> = [];
  // The case's status follows control requests, as the service would report it.
  const state = { status: options.status ?? 'PARKED', jobs: options.jobs ?? [] };
  await page.route(`${API}/v1/**`, async (route) => {
    const req = route.request();
    const auth = req.headers().authorization;
    if (auth !== `Bearer ${TOKEN}`) return route.fulfill({ status: 401, json: { error: 'authentication required' } });
    const url = new URL(req.url());
    if (url.pathname === '/v1/health') return route.fulfill({ json: { status: 'ok' } });
    if (url.pathname === '/v1/review-options') return route.fulfill({ json: reviewDefaults });
    if (req.method() === 'POST' && url.pathname.endsWith('/reviews')) {
      decisions.push({ url: url.pathname, body: req.postDataJSON(), auth });
      return route.fulfill({ status: 201, json: { job: { jobId: 'job_new' } } });
    }
    if (req.method() === 'POST' && url.pathname.endsWith('/control')) {
      const body = req.postDataJSON() as { action: string };
      decisions.push({ url: url.pathname, body, auth });
      state.status = body.action === 'pause' ? 'PAUSED' : body.action === 'resume' ? 'RUNNING' : 'CANCELLED';
      return route.fulfill({ status: body.action === 'resume' ? 201 : 200, json: { stoppedNow: true } });
    }
    if (req.method() === 'POST' && url.pathname.endsWith('/cancel')) {
      decisions.push({ url: url.pathname, body: null, auth });
      state.jobs = [];
      return route.fulfill({ json: { job: { status: 'CANCELLED' }, stoppedNow: true } });
    }
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
    if (url.pathname.endsWith('/jobs')) return route.fulfill({ json: state.jobs });
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
              status: state.status,
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
            status: state.status,
            stopReason: state.status === 'PAUSED' ? 'paused by you' : '1 item(s) wait for a human',
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
  await page.getByRole('button', { name: 'shop-api /code/shop-api' }).click();
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

test('start a review with run options: only changed options are sent', async ({ page }) => {
  const decisions = await mockApi(page);
  await page.goto(`/?api=${encodeURIComponent(API)}&token=${TOKEN}`);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'shop-api /code/shop-api' }).click();
  await page.getByRole('button', { name: 'New review' }).click();
  await page.getByLabel('Objectives (optional, one per line)').fill('Every admin route checks the admin role');
  const toggle = page.getByRole('button', { name: /Run options/ });
  await expect(toggle).toContainText('Supervised · up to $10 · 6 rounds · 90 min · all scanners · logic analysis');
  await toggle.click();
  await page.getByLabel('Budget (USD)').fill('2');
  await page.getByRole('checkbox', { name: /Trivy/ }).uncheck();
  await page.getByRole('radio', { name: /Observe/ }).check();
  await expect(page.getByRole('radio', { name: /Autonomous/ })).toHaveCount(0);
  await expect(toggle).toContainText('Changed');
  await page.getByLabel('Budget (USD)').fill('50');
  await page.getByRole('button', { name: 'Start review' }).click();
  await expect(page.getByText('At most 10 USD on this service.')).toBeVisible();
  expect(decisions).toHaveLength(0);
  await page.getByLabel('Budget (USD)').fill('2');
  await page.getByRole('button', { name: 'Start review' }).click();
  await expect.poll(() => decisions.length).toBe(1);
  expect(decisions[0]).toMatchObject({
    url: '/v1/projects/srvprj_1/reviews',
    body: {
      branch: 'main',
      objectives: ['Every admin route checks the admin role'],
      options: { mode: 'observe', maxCostUsd: 2, scanners: ['semgrep', 'osv-scanner', 'gitleaks'] },
    },
  });
});

test('pause a running review, resume it, and stop it after a confirmation', async ({ page }) => {
  const decisions = await mockApi(page, { status: 'RUNNING' });
  await page.goto(`/?api=${encodeURIComponent(API)}&token=${TOKEN}`);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'shop-api /code/shop-api' }).click();
  const controls = page.getByRole('group', { name: 'Review controls' }).last();
  await expect(page.getByText('Review in progress')).toBeVisible();
  await controls.getByRole('button', { name: 'Pause' }).click();
  await expect
    .poll(() => decisions.at(-1))
    .toMatchObject({ url: '/v1/projects/srvprj_1/cases/case_1/control', body: { action: 'pause' } });
  await expect(page.getByText('Work in progress is kept; resume to continue where it stopped.')).toBeVisible();
  await page.getByRole('group', { name: 'Review controls' }).last().getByRole('button', { name: 'Resume' }).click();
  await expect.poll(() => decisions.at(-1)).toMatchObject({ body: { action: 'resume' } });
  await expect(page.getByText('Review in progress')).toBeVisible();
  await page.getByRole('group', { name: 'Review controls' }).last().getByRole('button', { name: 'Stop' }).click();
  const confirm = page.getByRole('group', { name: 'Confirm stopping the review' }).last();
  await expect(confirm).toContainText('cannot be resumed');
  const before = decisions.length;
  await confirm.getByRole('button', { name: 'Keep it' }).click();
  expect(decisions).toHaveLength(before);
  await page.getByRole('group', { name: 'Review controls' }).last().getByRole('button', { name: 'Stop' }).click();
  await page
    .getByRole('group', { name: 'Confirm stopping the review' })
    .last()
    .getByRole('button', { name: 'Stop review' })
    .click();
  await expect.poll(() => decisions.at(-1)).toMatchObject({ body: { action: 'cancel' } });
  await expect(page.getByText('Cancelled').first()).toBeVisible();
});

test('projects page lists active reviews with controls, including one still scanning', async ({ page }) => {
  const decisions = await mockApi(page, {
    status: 'RUNNING',
    jobs: [
      {
        jobId: 'job_scan',
        kind: 'REVIEW',
        projectId: 'srvprj_1',
        payload: { branch: 'main', goal: 'Check the payment flow' },
        status: 'RUNNING',
        attempts: 1,
        maxAttempts: 3,
        createdAt: '2026-11-02T00:00:00Z',
        updatedAt: '2026-11-02T00:00:00Z',
      },
    ],
  });
  await page.goto(`/?api=${encodeURIComponent(API)}&token=${TOKEN}`);
  await page.getByRole('button', { name: 'Continue' }).click();
  const active = page.locator('.active-reviews');
  await expect(active.getByText('Check the payment flow')).toBeVisible();
  await expect(active.getByText('Scanning')).toBeVisible();
  await active.getByRole('button', { name: 'Pause' }).click();
  await expect.poll(() => decisions.at(-1)).toMatchObject({ body: { action: 'pause' } });
  await expect(active.getByRole('button', { name: 'Resume' })).toBeVisible();
  await active.getByRole('button', { name: 'Cancel', exact: true }).click();
  await active.getByRole('button', { name: 'Cancel review' }).click();
  await expect.poll(() => decisions.at(-1)).toMatchObject({ url: '/v1/projects/srvprj_1/jobs/job_scan/cancel' });
  await expect(active.getByText('Check the payment flow')).toHaveCount(0);
});

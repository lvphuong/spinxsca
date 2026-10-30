import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppContext, Env } from './app';
import type { TokenEntry } from './registry';
import { findingDetail, gateFor, projectOverview } from './views';

export const SESSION_COOKIE = 'spx_session';

const esc = (value: unknown): string =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch] as string,
  );
const url = (strings: TemplateStringsArray, ...values: string[]) =>
  strings.reduce((out, s, i) => out + s + (i < values.length ? encodeURIComponent(values[i] as string) : ''), '');

const STYLE = `
:root{--bg:#f7f7f8;--fg:#1d1d22;--muted:#6b6b76;--line:#e2e2e8;--card:#fff;--open:#b42318;--fixed:#067647;--warn:#b54708;--chip:#eef0f4}
@media (prefers-color-scheme:dark){:root{--bg:#141418;--fg:#ececf1;--muted:#9b9ba7;--line:#2b2b33;--card:#1c1c22;--open:#f97066;--fixed:#47cd89;--warn:#fdb022;--chip:#26262e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{display:flex;gap:16px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--card)}
header a{color:inherit;text-decoration:none}header .brand{font-weight:700}header form{margin-left:auto}
main{max-width:1200px;margin:0 auto;padding:20px 16px}h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;background:var(--chip);font-size:12px;white-space:nowrap}
.OPEN,.FAILED,.CRITICAL,.HIGH{color:var(--open)}.FIXED,.PASSED,.SUCCEEDED{color:var(--fixed)}.NOT_REEVALUATED,.MEDIUM,.QUEUED,.RUNNING{color:var(--warn)}.SUPPRESSED{color:var(--muted)}
pre{background:var(--chip);padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}a{color:inherit}
input,button,select{font:inherit;padding:6px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg)}button{cursor:pointer}
nav.branches a{margin-right:8px}.kev{font-weight:700;color:var(--open)}`;

function page(title: string, body: string, actor?: TokenEntry): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · spinxsca</title><style>${STYLE}</style></head><body>
<header><a class="brand" href="/ui">spinxsca</a><a href="/ui">Projects</a><a href="/ui/jobs">Jobs</a>${
    actor
      ? `<form method="post" action="/ui/logout"><span class="muted">${esc(actor.name)} · ${esc(actor.role)}</span> <button type="submit">Sign out</button></form>`
      : ''
  }</header><main>${body}</main></body></html>`;
}

const stateChip = (state: string, extra = '') =>
  `<span class="chip ${esc(state)}">${esc(state.toLowerCase().replace(/_/g, ' '))}${extra}</span>`;

export function mountUi(app: Hono<Env>, ctx: AppContext): void {
  const { registry, states, clock } = ctx;
  const actorOf = (c: Context<Env>): TokenEntry | undefined => {
    const session = getCookie(c, SESSION_COOKIE);
    return session ? registry.sessionToken(session, clock.now()) : undefined;
  };

  app.get('/ui/login', (c) =>
    c.html(
      page(
        'Sign in',
        `<h1>Sign in</h1><p class="muted">Use an API token created with <code>spinxsca server init</code> or <code>POST /v1/tokens</code>.</p>
<form method="post" action="/ui/login" class="card"><label>Token <input type="password" name="token" autocomplete="off" required size="50"></label> <button type="submit">Sign in</button></form>`,
      ),
    ),
  );
  app.post('/ui/login', async (c) => {
    const form = await c.req.parseBody();
    const actor = typeof form.token === 'string' ? registry.authenticate(form.token.trim(), clock.now()) : undefined;
    if (!actor)
      return c.html(
        page(
          'Sign in',
          '<h1>Sign in</h1><p class="OPEN">Invalid or revoked token.</p><p><a href="/ui/login">Try again</a></p>',
        ),
        401,
      );
    setCookie(c, SESSION_COOKIE, registry.createSession(actor.tokenId, clock.now()), {
      httpOnly: true,
      sameSite: 'Strict',
      secure: Boolean(ctx.secureCookies),
      path: '/',
      maxAge: 12 * 3600,
    });
    registry.audit(`${actor.name} (${actor.tokenId})`, 'ui.login', undefined, undefined, clock.now());
    return c.redirect('/ui');
  });
  app.post('/ui/logout', (c) => {
    const session = getCookie(c, SESSION_COOKIE);
    if (session) registry.deleteSession(session);
    deleteCookie(c, SESSION_COOKIE, { path: '/' });
    return c.redirect('/ui/login');
  });

  app.get('/ui', async (c) => {
    const actor = actorOf(c);
    if (!actor) return c.redirect('/ui/login');
    const rows: string[] = [];
    for (const project of registry.projects()) {
      const state = states.get(project.projectId);
      const overview = await projectOverview(state, project, clock);
      const gate = await gateFor(state, project.defaultBranch, ctx.gatePolicy, clock);
      rows.push(
        `<tr><td><a href="${url`/ui/projects/${project.projectId}`}">${esc(project.name)}</a><div class="muted">${esc(project.source.kind === 'git' ? project.source.url : project.source.path)}</div></td>
<td>${overview.branches.map((b) => `<span class="chip">${esc(b.branch)}: <span class="${b.open ? 'OPEN' : 'FIXED'}">${b.open} open</span></span>`).join(' ') || '<span class="muted">never scanned</span>'}</td>
<td>${esc(project.defaultBranch)} ${stateChip(gate.passed ? 'PASSED' : 'FAILED')}</td></tr>`,
      );
    }
    return c.html(
      page(
        'Projects',
        `<h1>Projects</h1><div class="card scroll"><table><tr><th>Project</th><th>Branches</th><th>Release gate</th></tr>${rows.join('') || '<tr><td colspan="3" class="muted">No projects. Create one with POST /v1/projects.</td></tr>'}</table></div>`,
        actor,
      ),
    );
  });

  app.get('/ui/projects/:id', async (c) => {
    const actor = actorOf(c);
    if (!actor) return c.redirect('/ui/login');
    const project = registry.project(c.req.param('id'));
    if (!project) return c.html(page('Not found', '<h1>Project not found</h1>', actor), 404);
    const state = states.get(project.projectId);
    const overview = await projectOverview(state, project, clock);
    const branch = c.req.query('branch') ?? project.defaultBranch;
    const gate = await gateFor(state, branch, ctx.gatePolicy, clock);
    const names = overview.branches.map((b) => b.branch);
    const branchRows = overview.branches
      .map(
        (b) =>
          `<tr><td><a href="${url`/ui/projects/${project.projectId}`}?branch=${encodeURIComponent(b.branch)}">${esc(b.branch)}</a></td><td>${esc(b.scanId)}</td><td>${esc(b.mode.toLowerCase().replace(/_/g, ' '))}</td><td>${stateChip(b.status)}</td><td>${esc(b.completedAt ?? '-')}</td><td class="OPEN">${b.open}</td><td class="FIXED">${b.fixed}</td></tr>`,
      )
      .join('');
    const matrix = overview.findings
      .map(
        (f) =>
          `<tr><td><a href="${url`/ui/projects/${project.projectId}/findings/${f.findingId}`}">${esc(f.findingId)}</a></td><td>${esc(f.title)}<div class="muted">${esc(f.category)} ${esc(f.cwe.join(', '))}</div></td>${names
            .map((n) => {
              const cell = f.branches[n];
              if (!cell) return '<td class="muted">–</td>';
              const intel = `${cell.kev ? ' <span class="kev">KEV</span>' : ''}${cell.epss !== undefined ? ` <span class="muted">EPSS ${cell.epss.toFixed(2)}</span>` : ''}`;
              return `<td>${stateChip(cell.state)} <span class="${esc(cell.severity)}">${esc(cell.severity.toLowerCase())}</span>${intel}</td>`;
            })
            .join('')}</tr>`,
      )
      .join('');
    const jobs = registry
      .jobs({ projectId: project.projectId, limit: 10 })
      .map(
        (j) =>
          `<tr><td>${esc(j.jobId)}</td><td>${esc(j.kind)}</td><td>${esc(String(j.payload.branch ?? ''))}</td><td>${stateChip(j.status)}</td><td>${esc(j.updatedAt)}</td><td class="muted">${esc(j.error ?? '')}</td></tr>`,
      )
      .join('');
    const body = `<h1>${esc(project.name)}</h1><p class="muted">${esc(project.source.kind === 'git' ? project.source.url : project.source.path)} · default branch ${esc(project.defaultBranch)}</p>
<h2>Release gate · ${esc(branch)} ${stateChip(gate.passed ? 'PASSED' : 'FAILED')}</h2>
<div class="card"><ul>${gate.checks.map((ch) => `<li class="${ch.passed ? 'PASSED' : 'FAILED'}">${ch.passed ? '✓' : '✗'} <span style="color:var(--fg)">${esc(ch.message)}</span></li>`).join('')}</ul>${
      gate.blocking.length
        ? `<table><tr><th>Finding</th><th>Severity</th><th>Why it blocks</th></tr>${gate.blocking.map((b) => `<tr><td><a href="${url`/ui/projects/${project.projectId}/findings/${b.findingId}`}">${esc(b.findingId)}</a> ${esc(b.title)}</td><td class="${esc(b.severity)}">${esc(b.severity)}</td><td>${esc(b.reasons.join('; '))}</td></tr>`).join('')}</table>`
        : ''
    }</div>
<h2>Branches</h2><div class="card scroll"><table><tr><th>Branch</th><th>Latest scan</th><th>Mode</th><th>Status</th><th>Completed</th><th>Open</th><th>Fixed</th></tr>${branchRows || '<tr><td colspan="7" class="muted">No completed scans yet.</td></tr>'}</table></div>
<h2>Findings by branch</h2><div class="card scroll"><table><tr><th>ID</th><th>Finding</th>${names.map((n) => `<th>${esc(n)}</th>`).join('')}</tr>${matrix || `<tr><td colspan="${2 + names.length}" class="muted">No findings.</td></tr>`}</table></div>
<h2>Recent jobs</h2><div class="card scroll"><table><tr><th>Job</th><th>Kind</th><th>Branch</th><th>Status</th><th>Updated</th><th>Error</th></tr>${jobs || '<tr><td colspan="6" class="muted">No jobs.</td></tr>'}</table></div>`;
    return c.html(page(project.name, body, actor));
  });

  app.get('/ui/projects/:id/findings/:findingId', async (c) => {
    const actor = actorOf(c);
    if (!actor) return c.redirect('/ui/login');
    const project = registry.project(c.req.param('id'));
    const detail = project
      ? await findingDetail(states.get(project.projectId), c.req.param('findingId'), clock)
      : undefined;
    if (!project || !detail) return c.html(page('Not found', '<h1>Finding not found</h1>', actor), 404);
    const { finding, latest } = detail;
    const branches = Object.entries(detail.branches)
      .map(
        ([b, cell]) =>
          `<tr><td>${esc(b)}</td><td>${stateChip(cell.state)}</td><td class="${esc(cell.severity)}">${esc(cell.severity)}</td><td>${esc(cell.scanId)}${cell.carriedThrough ? ` <span class="muted">(not re-evaluated by ${esc(cell.carriedThrough)})</span>` : ''}</td></tr>`,
      )
      .join('');
    const intel = detail.history.find((h) => h.intel)?.intel;
    const latestAssessment = detail.history[0];
    const attack = latestAssessment?.attackPath;
    const ai = detail.explanation?.output as { summary?: string; remediation?: { strategy?: string } } | undefined;
    const body = `<p><a href="${url`/ui/projects/${project.projectId}`}">← ${esc(project.name)}</a></p>
<h1>${esc(finding.findingId)} · ${esc(finding.title)}</h1><p class="muted">${esc(finding.category)} ${esc(finding.cwe.join(', '))} · first seen ${esc(finding.firstSeenScanId)}</p>
<h2>Status by branch</h2><div class="card scroll"><table><tr><th>Branch</th><th>State</th><th>Severity</th><th>Decided by scan</th></tr>${branches || '<tr><td colspan="4" class="muted">No branch data.</td></tr>'}</table></div>
${
  intel
    ? `<h2>Exploitation intelligence</h2><div class="card">${intel.kev ? `<p class="kev">Listed in CISA KEV since ${esc(intel.kev.dateAdded)}${intel.kev.ransomware ? ' · known ransomware use' : ''}</p>` : '<p>Not in CISA KEV.</p>'}${intel.epss ? `<p>EPSS ${esc(intel.epss.score.toFixed(3))} (percentile ${esc((intel.epss.percentile * 100).toFixed(0))}, ${esc(intel.epss.date.slice(0, 10))})</p>` : ''}${intel.cvss ? `<p>CVSS ${esc(intel.cvss.version)} ${esc(intel.cvss.baseScore)} <code>${esc(intel.cvss.vector)}</code></p>` : ''}<p class="muted">${esc(intel.cves.join(', '))}</p></div>`
    : ''
}
${
  latest
    ? `<h2>Location and evidence</h2><div class="card">${latest.occurrence.locations.map((l) => `<div><code>${esc(l.path)}:${esc(l.startLine)}</code> <span class="muted">${esc(l.role)}${l.symbolKey ? ` · ${esc(l.symbolKey)}` : ''}</span></div>`).join('')}<p class="muted">rules: ${esc(latest.occurrence.ruleIds.join(', '))}</p>${latest.evidence.map((e) => `<pre>${esc(e.excerpt ?? e.summary)}</pre>`).join('')}</div>`
    : ''
}
${
  attack && (attack.source || attack.sink || attack.entryPoint)
    ? `<h2>Attack path</h2><div class="card"><p>${[attack.attacker, attack.entryPoint, attack.source, attack.sink].filter(Boolean).map(esc).join(' → ')}</p>${attack.controls?.length ? `<p class="muted">controls: ${esc(attack.controls.join('; '))}</p>` : ''}</div>`
    : ''
}
${ai?.summary ? `<h2>AI assessment</h2><div class="card"><p>${esc(ai.summary)}</p>${ai.remediation?.strategy ? `<p><strong>Fix:</strong> ${esc(ai.remediation.strategy)}</p>` : ''}</div>` : ''}
<h2>Dispositions</h2><div class="card">${detail.dispositions.map((d) => `<p>${esc(d.kind)} by ${esc(d.decidedBy)} on ${esc(d.decidedAt)}${d.expiresAt ? `, expires ${esc(d.expiresAt)}` : ''}: ${esc(d.reason)}</p>`).join('') || '<p class="muted">None.</p>'}</div>
<h2>History</h2><div class="card scroll"><table><tr><th>When</th><th>Branch</th><th>Scan</th><th>State</th><th>Severity</th><th>Why</th></tr>${detail.history
      .map(
        (h) =>
          `<tr><td>${esc(h.assessedAt)}</td><td>${esc(h.branch ?? '-')}</td><td>${esc(h.scanId)} <span class="muted">${esc((h.mode ?? '').toLowerCase().replace(/_/g, ' '))}</span></td><td>${stateChip(h.reconciliationState)}</td><td class="${esc(h.severity)}">${esc(h.severity)}</td><td class="muted">${esc(h.changeCauses.join(', ').toLowerCase().replace(/_/g, ' '))}</td></tr>`,
      )
      .join('')}</table></div>`;
    return c.html(page(finding.findingId, body, actor));
  });

  app.get('/ui/jobs', (c) => {
    const actor = actorOf(c);
    if (!actor) return c.redirect('/ui/login');
    const names = new Map(registry.projects().map((p) => [p.projectId, p.name]));
    const rows = registry
      .jobs({ limit: 100 })
      .map(
        (j) =>
          `<tr><td>${esc(j.jobId)}</td><td>${esc(j.kind)}</td><td>${j.projectId ? `<a href="${url`/ui/projects/${j.projectId}`}">${esc(names.get(j.projectId) ?? j.projectId)}</a>` : '-'}</td><td>${esc(String(j.payload.branch ?? ''))}</td><td>${stateChip(j.status)}</td><td>${esc(j.attempts)}/${esc(j.maxAttempts)}</td><td>${esc(j.updatedAt)}</td><td class="muted">${esc(j.error ?? (j.result?.scanId as string | undefined) ?? '')}</td></tr>`,
      )
      .join('');
    return c.html(
      page(
        'Jobs',
        `<h1>Jobs</h1><div class="card scroll"><table><tr><th>Job</th><th>Kind</th><th>Project</th><th>Branch</th><th>Status</th><th>Attempts</th><th>Updated</th><th>Result</th></tr>${rows || '<tr><td colspan="8" class="muted">No jobs.</td></tr>'}</table></div>`,
        actor,
      ),
    );
  });
}

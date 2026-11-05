import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { caseReport } from '@spinxsca/agent';
import {
  applyPatchToRepository,
  type CaseRepository,
  evaluatePolicy,
  fixFindingIteratively,
  isContextQuestion,
  latestVerdicts,
  newId,
  runScan,
  scrubberFromSpans,
  verifyChain,
} from '@spinxsca/core';
import { GroundTruth, MemoryKind, type ReviewCase, SEVERITY_RANK, type Severity } from '@spinxsca/schemas';
import pc from 'picocolors';
import { ttyApprover } from '../approval-prompt';
import { autonomyConfig, createReviewer, type ReviewFlags, reviewPorts } from '../autonomy';
import { loadConfig } from '../config';
import { type AiFlags, aiOptions, type CommonOptions, currentUser, withEngine } from '../context';
import { type Engine, scanDeps, writeReports } from '../engine';
import { CliError, EXIT, status, table } from '../ui';
import { remediationDeps } from './fix';

export interface ReviewCommandOptions extends CommonOptions, AiFlags, ReviewFlags {
  case?: string;
  exclude?: string[];
  out?: string;
  failOn?: string;
}

/**
 * `spinxsca review`: a full scan followed by an autonomous, governed review case (ADR-044). Attended
 * runs ask on the terminal; unattended runs park asks in the inbox and stop as PARKED.
 */
export async function reviewCommand(path: string | undefined, options: ReviewCommandOptions): Promise<number> {
  const loaded = loadConfig(options.config);
  const ai = aiOptions(loaded, { ...options, ai: 'deep' }, true);
  if (!ai) throw new CliError('review needs an AI provider');
  const config = {
    ...autonomyConfig(loaded, options, ai.maxCostUsd),
    ...(ai.context ? { context: ai.context } : {}),
  };
  return withEngine(path, { ...options, aiConfig: ai }, async (engine) => {
    if (!options.json) {
      status(
        `autonomous review: mode ${config.mode}${config.attended ? ', attended' : ', unattended'}, reviewer ${config.mode === 'autonomous' && config.attended ? config.reviewer : 'not used'}, L3 ${config.l3 ? 'on' : 'off'}, budget $${config.maxCostUsd}, ${config.maxRounds} rounds`,
      );
    }
    const reviewer = createReviewer({
      ai,
      loaded,
      config,
      ...(options.goal ? { goal: options.goal } : {}),
      ...(options.objectives?.length ? { objectives: options.objectives } : {}),
      ...(config.attended ? { human: ttyApprover() } : {}),
      onEvent: (e) => {
        if (!options.json) status(`${pc.dim(`[${e.type}]`)} ${e.message}`);
      },
    });
    const controller = new AbortController();
    const onSignal = () => {
      status('cancelling review…');
      controller.abort();
    };
    process.once('SIGINT', onSignal);
    try {
      const outcome = await runScan(scanDeps(engine, { reviewer, ports: reviewPorts(engine, loaded) }), {
        projectName: loaded.config.project?.name ?? engine.projectName,
        mode: 'FULL',
        exclude: [...(loaded.config.scan?.exclude ?? []), ...(options.exclude ?? [])],
        baseline: { kind: 'auto' },
        reuseCache: true,
        ai: {
          level: 'deep',
          maxFindings: ai.maxFindings,
          maxCostUsd: config.maxCostUsd,
          ...(ai.context ? { context: ai.context } : {}),
        },
        ...(options.case ? { reviewCaseId: options.case } : {}),
        signal: controller.signal,
        onProgress: (event) => {
          if (!options.json) status(event.message);
        },
      });
      const reports = await writeReports(
        engine,
        outcome.scan.scanId,
        loaded.config.output?.formats ?? ['sarif', 'md', 'json'],
        options.out,
      );
      const review = outcome.ai?.review;
      const cases = engine.cases as CaseRepository;
      let rc = review ? await cases.getCase(review.caseId) : undefined;
      if (rc && config.remediation && engine.remediator) {
        const min = (loaded.config.ai?.remediation?.min_severity ?? 'HIGH') as Severity;
        const targets = [];
        for (const a of outcome.assessments) {
          const finding = await engine.repo.getFinding(a.findingId);
          if (!finding || a.classification === 'UNLIKELY' || SEVERITY_RANK[a.severity] < SEVERITY_RANK[min]) continue;
          if (['VULNERABLE_DEPENDENCY', 'HARDCODED_SECRET', 'INSECURE_CONFIGURATION'].includes(finding.category))
            continue;
          const occurrence = (await engine.repo.listOccurrences(outcome.scan.scanId)).find(
            (o) => o.findingId === a.findingId,
          );
          const loc = occurrence?.locations[0];
          targets.push({
            findingId: a.findingId,
            title: finding.title,
            severity: a.severity,
            location: loc ? `${loc.path}:${loc.startLine}` : '',
          });
        }
        if (targets.length && !options.json)
          status(`proposing fixes for ${targets.length} finding(s); applying any of them needs your approval`);
        const patchesDir = join(engine.stateDir, 'patches');
        mkdirSync(patchesDir, { recursive: true });
        const files = (await engine.repo.getSnapshot(outcome.scan.snapshotId))?.fileListDigest;
        const snapshotPaths = files
          ? (JSON.parse(await engine.artifacts.getText(files)) as Array<{ path: string }>).map((f) => f.path)
          : [];
        const candidates = await engine.repo.listCandidates(outcome.scan.scanId);
        const redactions = candidates.filter((c) => c.category === 'HARDCODED_SECRET').flatMap((c) => c.locations);
        const remediated = await reviewer.remediate({
          cases,
          caseId: rc.caseId,
          source: engine.source,
          snapshotPaths,
          redactions,
          scrubber: await scrubberFromSpans((p) => engine.source.readText(p), redactions),
          targets,
          fix: (findingId, feedback) =>
            fixFindingIteratively(remediationDeps(engine, loaded, patchesDir), findingId, {
              maxIterations: loaded.config.ai?.remediation?.max_iterations ?? 3,
              ...(feedback ? { feedback } : {}),
              signal: controller.signal,
            }),
          apply: async (patchId) => applyPatchToRepository(engine.source, patchesDir, patchId).files,
          signal: controller.signal,
        });
        for (const r of remediated)
          if (!options.json)
            status(`fix ${r.findingId}: ${r.status}${r.patchId ? ` (${r.patchId})` : ''} — ${r.reason}`);
        rc = await cases.getCase(rc.caseId);
      }
      let casePath: string | undefined;
      if (rc) {
        const dir = resolve(options.out ?? join(engine.stateDir, 'reports', outcome.scan.scanId));
        mkdirSync(dir, { recursive: true });
        casePath = join(dir, 'case.md');
        writeFileSync(casePath, await renderCase(cases, rc));
      }
      const failOn = options.failOn?.toUpperCase() ?? loaded.config.policy?.fail_on_severity;
      const policy = evaluatePolicy(outcome.assessments, {
        ...(failOn ? { failOnSeverity: failOn as never } : {}),
        newFindingsOnly: loaded.config.policy?.new_findings_only ?? true,
        trustAiDowngrades: loaded.config.gate?.trust_ai_downgrades ?? false,
        aiDiscoveredMinClassification: loaded.config.gate?.ai_discovered_min_classification ?? 'CONFIRMED',
      });
      if (options.json) {
        console.log(
          JSON.stringify(
            {
              scan: outcome.scan,
              review: review ?? null,
              case: rc ?? null,
              reports,
              casePath: casePath ?? null,
              policy: { passed: policy.passed },
            },
            null,
            2,
          ),
        );
      } else {
        status(`scan ${outcome.scan.scanId}: ${outcome.scan.status}`);
        if (rc && review) {
          const pending = (await cases.listApprovals({ caseId: rc.caseId, status: 'PENDING' })).length;
          status(
            `case ${rc.caseId}: ${rc.status}${rc.stopReason ? ` (${rc.stopReason})` : ''}; ${review.applied} assessment(s) updated${pending ? `, ${pending} approval(s) waiting: spinxsca inbox list` : ''}`,
          );
        }
        if (casePath) status(`case report: ${casePath}`);
      }
      if (outcome.scan.status === 'FAILED') return EXIT.ERROR;
      return policy.evaluated && !policy.passed ? EXIT.POLICY_FAILED : EXIT.OK;
    } finally {
      process.removeListener('SIGINT', onSignal);
    }
  });
}

async function renderCase(cases: CaseRepository, rc: ReviewCase): Promise<string> {
  const items = await cases.listWorkItems(rc.caseId);
  const pending = await cases.listApprovals({ caseId: rc.caseId, status: 'PENDING' });
  const recon = GroundTruth.safeParse(
    (items.find((i) => i.kind === 'RECON')?.result as { groundTruth?: unknown } | undefined)?.groundTruth,
  );
  return caseReport({
    rc,
    objectives: await cases.listObjectives(rc.caseId),
    items,
    handles: await cases.listHandles(rc.caseId),
    verdicts: await cases.listVerdicts(rc.caseId),
    checks: await cases.listChecks(rc.caseId),
    ledger: await cases.getLedger(rc.caseId),
    pendingApprovals: pending.length,
    ...(recon.success ? { groundTruth: recon.data } : {}),
    openQuestions: pending.filter(isContextQuestion).map((a) => ({ id: a.approvalId, question: a.title })),
  });
}

function requireCases(engine: Engine): CaseRepository {
  if (!engine.cases) throw new CliError('no case store in this state directory');
  return engine.cases;
}

export async function caseListCommand(path: string | undefined, options: CommonOptions): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const project = await engine.repo.getProject();
    const list = project ? await requireCases(engine).listCases({ projectId: project.project.projectId }) : [];
    if (options.json) console.log(JSON.stringify(list, null, 2));
    else if (list.length === 0) status('no review cases yet: run `spinxsca review`');
    else
      console.log(
        table(
          ['Case', 'Status', 'Mode', 'Rounds', 'Scan', 'Created'],
          list.map((c) => [c.caseId, c.status, c.mode, String(c.round), c.scanId, c.createdAt]),
        ),
      );
    return EXIT.OK;
  });
}

export async function caseShowCommand(
  path: string | undefined,
  caseId: string,
  options: CommonOptions & { journal?: boolean; audit?: boolean; verifyChain?: boolean },
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const cases = requireCases(engine);
    const rc = await cases.getCase(caseId);
    if (!rc) throw new CliError(`case ${caseId} not found`);
    const journal = await cases.listJournal(caseId);
    const audit = await cases.listAudit(caseId);
    const checks = { journal: verifyChain(journal), audit: verifyChain(audit) };
    if (options.json) {
      console.log(
        JSON.stringify(
          {
            case: rc,
            objectives: await cases.listObjectives(caseId),
            verdicts: [...latestVerdicts(await cases.listVerdicts(caseId)).values()],
            chains: checks,
            ...(options.journal ? { journal } : {}),
            ...(options.audit ? { audit } : {}),
          },
          null,
          2,
        ),
      );
    } else {
      console.log(await renderCase(cases, rc));
      if (options.journal) {
        console.log('\n## Journal');
        for (const e of journal)
          console.log(
            `[${e.seq}] ${e.at} ${e.kind} ${e.author}${e.handles.length ? ` (${e.handles.join(', ')})` : ''}: ${e.text}`,
          );
      }
      if (options.audit) {
        console.log('\n## Audit');
        for (const a of audit)
          console.log(
            `[${a.seq}] ${a.at} ${a.stage} ${a.actor}${a.toolCallId ? ` ${a.toolCallId}` : ''} ${JSON.stringify(a.data)}`,
          );
      }
      if (options.verifyChain || options.journal || options.audit) {
        for (const [name, r] of Object.entries(checks)) {
          console.log(
            r.ok
              ? pc.green(`${name} chain ok (${r.length} records, head ${r.head.slice(7, 19)})`)
              : pc.red(`${name} chain BROKEN at seq ${r.seq}: ${r.reason}`),
          );
        }
      }
    }
    return options.verifyChain && (!checks.journal.ok || !checks.audit.ok) ? EXIT.ERROR : EXIT.OK;
  });
}

export async function memoryCommand(
  action: 'list' | 'add' | 'promote' | 'forget',
  path: string | undefined,
  options: CommonOptions & {
    status?: string;
    kind?: string;
    key?: string;
    text?: string;
    id?: string;
    reason?: string;
  },
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const cases = requireCases(engine);
    const project = await engine.repo.getProject();
    if (!project) throw new CliError('no project in this state directory: run a scan first');
    const projectId = project.project.projectId;
    const now = new Date().toISOString();
    const by = `human:${currentUser()}`;
    if (action === 'list') {
      const entries = await cases.listMemory({
        projectId,
        ...(options.status ? { status: options.status as never } : {}),
        ...(options.kind ? { kind: options.kind.toUpperCase() as never } : {}),
      });
      if (options.json) console.log(JSON.stringify(entries, null, 2));
      else
        console.log(
          table(
            ['Id', 'Kind', 'Status', 'Key', 'Text'],
            entries.map((m) => [m.memoryId, m.kind, m.status, m.key, m.text.slice(0, 80)]),
          ),
        );
      return EXIT.OK;
    }
    if (action === 'add') {
      const kind = MemoryKind.safeParse(options.kind?.toUpperCase());
      if (!kind.success || kind.data === 'VERDICT_CACHE')
        throw new CliError('--kind must be architecture, convention, lesson or disposition');
      if (!options.key || !options.text) throw new CliError('--key and --text are required');
      const id = newId('mem');
      await cases.saveMemory({
        memoryId: id,
        projectId,
        kind: kind.data,
        status: 'active',
        key: options.key,
        text: options.text,
        createdBy: by,
        createdAt: now,
        updatedAt: now,
      });
      status(`memory ${id} added`);
      return EXIT.OK;
    }
    if (!options.id) throw new CliError('--id is required');
    const ok = await cases.updateMemoryStatus(
      options.id,
      action === 'promote' ? 'active' : 'invalidated',
      `${action === 'promote' ? 'promoted' : 'forgotten'} by ${by}${options.reason ? `: ${options.reason}` : ''}`,
      now,
    );
    if (!ok) throw new CliError(`memory ${options.id} not found`);
    status(`memory ${options.id} ${action === 'promote' ? 'promoted' : 'forgotten'}`);
    return EXIT.OK;
  });
}

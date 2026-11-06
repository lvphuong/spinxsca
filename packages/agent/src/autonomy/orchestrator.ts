import {
  type AutonomousReviewer,
  applyRedactions,
  askContextQuestions,
  buildResourceMatrix,
  type CandidateDraft,
  type CaseRepository,
  checkIndependence,
  controlOf,
  type DependencyInfo,
  digestOf,
  evaluateObjectives,
  HandleTable,
  initialMemoryStatus,
  moveItem,
  quotaOf,
  type ResourceMatrix,
  type ReviewOutcome,
  type ReviewSubject,
  readyItems,
  redactSecrets,
  renderJournal,
  renderMemory,
  type SecretScrubber,
  type SourceTree,
  sha256Hex,
} from '@spinxsca/core';
import {
  buildApprovalRequest,
  ConsecutiveBreaker,
  evaluate,
  type PermissionRequest,
  type PolicyContext,
  resolutionAudit,
  resolveApproval,
} from '@spinxsca/governance';
import type {
  AgentRunRecord,
  AiContextConfig,
  AutonomyMode,
  CaseHandle,
  CaseStatus,
  CaseVerdict,
  Digest,
  Location,
  PatchResult,
  ReviewCase,
  ReviewerMode,
  RiskClass,
  RunRef,
  WorkItem,
  WorkItemKind,
} from '@spinxsca/schemas';
import { GroundTruth } from '@spinxsca/schemas';

import { acceptedRisksVar, coverageOf, mergeOperatorContext, renderOperatorContext } from '../ground-truth';
import { providerJudge } from '../llm/judge';
import { costOf } from '../llm/pricing';
import type { Effort, LlmProvider, Usage } from '../llm/types';
import { loadPersonas, type Persona } from '../personas/loader';
import { checkManifest } from '../personas/manifest';
import { costWithOverrides, type PriceOverride } from '../runtime/budget';
import { DEFAULT_COMPACTION } from '../runtime/compaction';
import { runLimited, Semaphore } from '../runtime/concurrency';
import { GovernedToolExecutor } from '../runtime/governed-executor';
import { runAgentSession, type SessionResult } from '../runtime/session';
import type { AgentTool } from '../runtime/tools';
import { caseSessionStore } from '../runtime/transcript';
import { loadSkills, type SkillBundle } from '../skills/bundle';
import { createSkillTool } from '../skills/tools';
import { createCodeTools } from '../tools/code-tools';
import { createExploreTool } from '../tools/explore-tool';
import { createGraphTools } from '../tools/graph-tools';
import { createSecurityTools } from '../tools/security-tools';
import { createValidationTools } from '../tools/validation-tools';
import { approverChain, type HumanApprover } from './approvers';
import { createBoardTools, summarizeBoard } from './board-tools';
import { isIacFile, logicItemSlug, RECON_ITEM, seedBoard } from './conductor';
import { itemPrompt, leadPrompt, ORACLE_FOR_CATEGORY, ORACLE_GUIDE, sliceForItem } from './context';
import { decideStop } from './convergence';
import { duplicateGroups } from './dedupe';
import {
  type ApplicabilityDeliverable,
  type FindingsDeliverable,
  PlanDeliverable,
  type PocDeliverable,
  type PocReviewDeliverable,
  submitFor,
  type TriageDeliverable,
} from './deliverables';
import { FixReviewDeliverable, fixReviewPrompt, type RemediationOutcome, type RemediationTarget } from './remediation';
import { applicabilityVerdict, consistencyIssue, triageVerdict } from './verdicts';

export const AUTONOMY_POLICY_VERSION = 'autonomy-v1';

export interface AutonomyConfig {
  mode: AutonomyMode;
  reviewer: ReviewerMode;
  /** A human is present to answer asks (TTY, desktop); unattended runs park asks in the inbox. */
  attended: boolean;
  autoAllow: readonly string[];
  denyTools: readonly string[];
  extraProtected: readonly string[];
  riskOverrides: Readonly<Record<string, RiskClass>>;
  maxRounds: number;
  maxCostUsd: number;
  maxSandboxRuns: number;
  maxSandboxCpuSec: number;
  maxWallClockMin: number;
  maxParallel: number;
  allowUnpriced: boolean;
  l3: boolean;
  maxRunsPerFinding: number;
  remediation: boolean;
  dataPolicyExclude: readonly string[];
  allowedProviders?: readonly string[];
  pricing?: Readonly<Record<string, PriceOverride>>;
  /** Operator-owned host paths (config file, knowledge base, rule dirs, prompts). */
  protectedRoots: readonly string[];
  /** Recon-first flow (ADR-049). Absent: Phase 5 board without RECON, LOGIC_AUDIT or critics. */
  recon?: { enabled: boolean; criticPasses: number; maxLogicItems: number; census: boolean };
  /** Operator context pack (ADR-051). */
  context?: AiContextConfig;
}

export interface CaseEvent {
  type: 'case' | 'item' | 'approval' | 'verdict' | 'reviewer';
  caseId: string;
  message: string;
  data?: Record<string, unknown>;
}

export interface AgentAutonomousReviewerOptions {
  provider: () => LlmProvider;
  /** Fast tier for explore sub-agents (defaults to `provider`). */
  fastProvider?: () => LlmProvider;
  /** Reviewer model (defaults to `fastProvider`). */
  judgeProvider?: () => LlmProvider;
  promptsDir: string;
  playbooksDir: string;
  config: AutonomyConfig;
  goal: string;
  objectives?: readonly string[];
  human?: HumanApprover;
  effort?: Effort;
  onEvent?: (event: CaseEvent) => void;
  now?: () => Date;
  /**
   * Options the operator chose for this review (ADR-052), recorded in the `case.started` audit
   * entry so that a resumed case runs with the same budget, mode and scope.
   */
  runOptions?: Record<string, unknown>;
}

/** Kinds handled by the orchestrator in this milestone (PoC and fixes join with L3/remediation). */
const WORKER_KINDS: ReadonlySet<WorkItemKind> = new Set([
  'TRIAGE_FINDING',
  'DEPENDENCY_APPLICABILITY',
  'SECRETS_SWEEP',
  'IAC_REVIEW',
  'THREAT_PACKET',
  'BASELINE_AUDIT',
  'HYPOTHESIS',
  'VARIANT_HUNT',
  'EXPLOIT_POC',
  'REVIEW_POC',
  'RECON',
  'LOGIC_AUDIT',
  'COMPLETENESS_CRITIC',
]);

/** Kinds whose deliverable is a FindingsDeliverable and that get a completeness critic (ADR-049). */
const CRITIQUED_KINDS: ReadonlySet<WorkItemKind> = new Set([
  'THREAT_PACKET',
  'LOGIC_AUDIT',
  'HYPOTHESIS',
  'VARIANT_HUNT',
]);
const FINDINGS_KINDS: ReadonlySet<WorkItemKind> = new Set([
  ...CRITIQUED_KINDS,
  'COMPLETENESS_CRITIC',
  'BASELINE_AUDIT',
  'SECRETS_SWEEP',
  'IAC_REVIEW',
]);

interface CaseRuntime {
  rc: ReviewCase;
  subject: ReviewSubject;
  source: SourceTree;
  cases: CaseRepository;
  handles: HandleTable;
  snapshot: Set<string>;
  signal?: AbortSignal;
  deadline: number;
  maxCostUsd: number;
  onRun?: (run: AgentRunRecord) => Promise<void>;
  runIds: string[];
  deferred: string[];
  reviewerBreaker: ConsecutiveBreaker;
  exploreLimit: Semaphore;
  historySummary?: string;
  /** Ground truth once the RECON item is done (merged with the operator context). */
  groundTruth?: GroundTruth;
  matrix?: ResourceMatrix;
  /** Item that produced each agent handle (not persisted; a resumed case lists every agent handle). */
  handleItems: Map<string, string>;
}

/**
 * Autonomous, governed security review (ADR-044). The host conductor seeds mandatory work; a lead
 * persona plans optional work with board tools only; worker personas investigate through governed
 * tools; the host completes items, checks independence and records verdicts. The case stops on
 * convergence, stagnation, budget, cancellation or when it waits for a human.
 */
export class AgentAutonomousReviewer implements AutonomousReviewer {
  readonly info: AutonomousReviewer['info'];
  readonly policyDigest: Digest;
  private readonly personas: Map<string, Persona>;
  private readonly skills: SkillBundle;
  private readonly now: () => Date;
  private readonly costOf: (usage: Usage, model: string) => number | undefined;

  constructor(private readonly o: AgentAutonomousReviewerOptions) {
    this.personas = loadPersonas(o.promptsDir);
    for (const p of this.personas.values()) {
      const problems = checkManifest(p.manifest);
      if (problems.length) throw new Error(problems.join('\n'));
    }
    this.skills = loadSkills(o.playbooksDir);
    this.now = o.now ?? (() => new Date());
    this.costOf = costWithOverrides(costOf, o.config.pricing ?? {});
    const provider = o.provider();
    const promptDigest = digestOf([...this.personas.values()].map((p) => [p.manifest, p.prompt]));
    this.policyDigest = digestOf({
      version: AUTONOMY_POLICY_VERSION,
      prompts: promptDigest,
      skills: this.skills.digest,
      config: { ...o.config, protectedRoots: o.config.protectedRoots.length },
    });
    this.info = {
      provider: provider.id,
      model: provider.model,
      promptBundleDigest: promptDigest,
      policyVersion: AUTONOMY_POLICY_VERSION,
    };
  }

  async review(
    subject: ReviewSubject,
    source: SourceTree,
    options: {
      maxCostUsd: number;
      signal?: AbortSignal;
      onRun?: (run: AgentRunRecord) => Promise<void>;
      caseId?: string;
    },
  ): Promise<ReviewOutcome> {
    const cases = subject.ports.cases;
    const caseId = options.caseId ?? `case_${subject.scan.scanId.replace(/^scan_/, '')}`;
    const at = this.now().toISOString();
    let rc = await cases.getCase(caseId);
    if (!rc) {
      rc = {
        caseId,
        projectId: subject.scan.projectId,
        scanId: subject.scan.scanId,
        snapshotId: subject.scan.snapshotId,
        goal: this.o.goal,
        mode: this.o.config.mode,
        attended: this.o.config.attended,
        status: 'RUNNING',
        round: 0,
        policyDigest: this.policyDigest,
        createdAt: at,
        updatedAt: at,
      };
      await cases.createCase(rc);
      await this.audit(cases, caseId, 'case.started', {
        goal: this.o.goal,
        mode: rc.mode,
        attended: rc.attended,
        reviewer: this.o.config.reviewer,
        l3: this.o.config.l3,
        policyDigest: this.policyDigest,
        ...(this.o.runOptions ? { runOptions: this.o.runOptions } : {}),
      });
    } else {
      rc = await cases.updateCase(caseId, { status: 'RUNNING', attended: this.o.config.attended });
      await this.audit(cases, caseId, 'case.resumed', { round: rc.round });
    }
    this.emit({ type: 'case', caseId, message: `review case ${caseId} ${rc.round ? 'resumed' : 'started'}` });

    const rt: CaseRuntime = {
      rc,
      subject,
      source,
      cases,
      handles: new HandleTable(caseId, await cases.listHandles(caseId)),
      snapshot: new Set(subject.snapshotPaths),
      ...(options.signal ? { signal: options.signal } : {}),
      deadline: Date.now() + this.o.config.maxWallClockMin * 60_000,
      maxCostUsd: Math.min(options.maxCostUsd, this.o.config.maxCostUsd),
      ...(options.onRun ? { onRun: options.onRun } : {}),
      runIds: [],
      deferred: [],
      reviewerBreaker: new ConsecutiveBreaker(5),
      exploreLimit: new Semaphore(3),
      handleItems: new Map(),
    };
    const recon = this.o.config.recon;
    if (recon?.enabled && recon.census && subject.graph) {
      rt.matrix = await buildResourceMatrix(subject.graph, source, subject.snapshotPaths);
    }
    rt.groundTruth = await this.loadGroundTruth(rt);

    const created: CaseHandle[] = [];
    for (const draft of subject.scannerDrafts) {
      const r = rt.handles.assign(draft, 'scanner');
      if (r.created) created.push(r.handle);
    }
    await this.historySweep(rt, created);
    await cases.saveHandles(created);

    if ((await cases.listWorkItems(caseId)).length === 0) {
      const { items, objectives } = seedBoard({
        caseId,
        now: this.now(),
        handles: rt.handles.all(),
        endpoints: (subject.graph?.endpoints() ?? []).map((e) => ({
          id: e.id,
          method: e.method,
          route: e.route,
          path: e.path,
          line: e.line,
        })),
        iacFiles: subject.snapshotPaths.filter(isIacFile),
        l3: this.o.config.l3,
        objectives: this.o.objectives ?? [],
        ...(recon?.enabled
          ? {
              recon: true,
              maxLogicItems: recon.maxLogicItems,
              ...(rt.matrix ? { matrix: rt.matrix } : {}),
              operatorContext: renderOperatorContext(this.o.config.context),
            }
          : {}),
      });
      for (const item of items) await cases.saveWorkItem(item);
      await cases.saveObjectives(objectives);
      await cases.appendJournal({
        caseId,
        kind: 'DECISION',
        author: 'host',
        handles: [],
        refs: [],
        text: `Seeded ${items.length} work items (${items.filter((i) => i.kind === 'TRIAGE_FINDING').length} triage, ${items.filter((i) => i.kind === 'DEPENDENCY_APPLICABILITY').length} dependency, ${items.filter((i) => i.kind === 'THREAT_PACKET').length} threat packets) and ${objectives.length} objectives.`,
      });
    }

    const stop = await this.rounds(rt);
    return this.finish(rt, stop.stop, stop.reason);
  }

  // Rounds

  private async rounds(rt: CaseRuntime): Promise<{ stop: Exclude<CaseStatus, 'RUNNING' | 'FAILED'>; reason: string }> {
    let stall = 0;
    const parked = new Set<string>();
    while (true) {
      await this.housekeeping(rt);
      const items = await rt.cases.listWorkItems(rt.rc.caseId);
      const ledger = await rt.cases.getLedger(rt.rc.caseId);
      const budgetReason =
        ledger.costUsd >= rt.maxCostUsd
          ? `cost budget $${rt.maxCostUsd} reached`
          : Date.now() > rt.deadline
            ? 'wall-clock budget reached'
            : undefined;
      const control = controlOf(rt.signal);
      const by = (rt.signal?.reason as { by?: string } | undefined)?.by;
      const decided = decideStop({
        items,
        round: rt.rc.round,
        maxRounds: this.o.config.maxRounds,
        roundsWithoutProgress: stall,
        parkedItems: parked,
        cancelled: control === 'cancel',
        paused: control === 'pause',
        ...(by ? { by } : {}),
        ...(budgetReason ? { budgetReason } : {}),
      });
      if (decided) return decided;

      await this.runLead(rt, items);
      const fresh = await rt.cases.listWorkItems(rt.rc.caseId);
      const runnable = [
        ...fresh.filter((i) => i.status === 'in_progress' && !parked.has(i.itemId) && WORKER_KINDS.has(i.kind)),
        ...readyItems(fresh).filter((i) => i.persona !== 'host' && WORKER_KINDS.has(i.kind)),
      ];
      const outcomes = await runLimited(
        runnable.map((item) => () => this.runItem(rt, item)),
        this.o.config.maxParallel,
      );
      let progress = 0;
      outcomes.forEach((outcome, i) => {
        const item = runnable[i] as WorkItem;
        if (outcome === 'parked') parked.add(item.itemId);
        else parked.delete(item.itemId);
        if (outcome === 'done') progress++;
      });
      stall = progress > 0 ? 0 : stall + 1;
      rt.rc = await rt.cases.updateCase(rt.rc.caseId, { round: rt.rc.round + 1 });
      const objectives = evaluateObjectives(
        await rt.cases.listObjectives(rt.rc.caseId),
        await this.state(rt),
        false,
        this.now(),
      );
      await rt.cases.saveObjectives(objectives);
    }
  }

  /** Host duties between rounds: retry blocked items once, complete the report when its inputs are done. */
  private async housekeeping(rt: CaseRuntime): Promise<void> {
    for (const item of await rt.cases.listWorkItems(rt.rc.caseId)) {
      if (item.status === 'blocked' && item.attempts < 2 && item.mandatory) {
        await this.transition(rt, item, 'todo', { kind: 'host' }, { blockedReason: undefined });
      }
    }
    const items = await rt.cases.listWorkItems(rt.rc.caseId);
    for (const report of readyItems(items).filter((i) => i.kind === 'REPORT')) {
      const inProgress = await this.transition(rt, report, 'in_progress', { kind: 'host' });
      const review = await this.transition(rt, inProgress, 'review', { kind: 'host' }, { result: { assembled: true } });
      await this.transition(rt, review, 'done', { kind: 'host' });
    }
  }

  private async runLead(rt: CaseRuntime, items: readonly WorkItem[]): Promise<void> {
    const persona = this.personas.get('lead');
    if (!persona) return;
    const runId = `run_lead_${sha256Hex(rt.rc.caseId).slice(0, 12)}_r${rt.rc.round}`;
    const creatable: WorkItemKind[] = [
      'HYPOTHESIS',
      'VARIANT_HUNT',
      ...(this.o.config.recon?.enabled ? (['LOGIC_AUDIT'] as const) : []),
      ...(this.o.config.l3 ? (['EXPLOIT_POC'] as const) : []),
      ...(this.o.config.remediation ? (['FIX'] as const) : []),
    ];
    const tools = this.forPersona(persona, [
      ...createBoardTools({
        caseId: rt.rc.caseId,
        runId,
        round: rt.rc.round,
        cases: rt.cases,
        handles: rt.handles,
        creatable,
        now: this.now,
      }),
      ...this.securityTools(rt, persona.manifest.id, runId),
    ]);
    const board = summarizeBoard(
      items,
      await rt.cases.listVerdicts(rt.rc.caseId),
      await rt.cases.listObjectives(rt.rc.caseId),
    );
    const ledger = await rt.cases.getLedger(rt.rc.caseId);
    const result = await this.session(rt, {
      persona,
      runId,
      tools,
      submit: { name: 'submit_plan', description: 'Finish planning for this round.', output: PlanDeliverable },
      prompt: leadPrompt({
        goal: this.o.goal,
        round: rt.rc.round,
        board,
        journal: renderJournal(await rt.cases.listJournal(rt.rc.caseId), { limit: 25, maxChars: 6000 }),
        budget: `$${(rt.maxCostUsd - ledger.costUsd).toFixed(2)} and ${this.o.config.maxRounds - rt.rc.round} round(s) left`,
      }),
    });
    if (result.output && !result.resumed) {
      await rt.cases.appendJournal({
        caseId: rt.rc.caseId,
        kind: 'DECISION',
        author: `lead/${runId}`,
        handles: [],
        refs: [],
        text: subjectScrub(rt, (result.output as { notes: string }).notes || 'No additional work planned.'),
      });
    }
  }

  // Items

  private async runItem(rt: CaseRuntime, item: WorkItem): Promise<'done' | 'parked' | 'blocked' | 'paused'> {
    const persona = this.personas.get(item.persona);
    if (!persona) {
      await this.transition(rt, item, 'blocked', { kind: 'host' }, { blockedReason: `no persona ${item.persona}` });
      return 'blocked';
    }
    const runId = `run_${sha256Hex(item.itemId).slice(0, 16)}_a${item.attempts}`;
    const worker = { kind: 'worker' as const, persona: persona.manifest.id, runId };
    let current = item;
    if (current.status === 'todo') {
      current = await this.transition(rt, current, 'in_progress', worker, {
        producer: { persona: persona.manifest.id, runId },
      });
    }
    this.emit({
      type: 'item',
      caseId: rt.rc.caseId,
      message: `${persona.manifest.id}: ${item.title}`,
      data: { itemId: item.itemId },
    });
    const itemHandles = item.handles.map((h) => rt.handles.get(h));
    const triagedClaim = (itemHandles[0]?.draft as CandidateDraft | undefined)?.claim;
    const submit = submitFor(item.kind, {
      source: rt.source,
      paths: rt.subject.snapshotPaths,
      ...(rt.subject.ports.dependencies ? { dependencies: rt.subject.ports.dependencies } : {}),
      packageOf: (h) => this.packageOf(rt.handles.get(h)),
      ...(rt.subject.ports.validation ? { validation: rt.subject.ports.validation } : {}),
      ...(rt.groundTruth
        ? { groundTruth: rt.groundTruth, slice: sliceForItem(rt.groundTruth, item, itemHandles) }
        : {}),
      ...(item.kind === 'TRIAGE_FINDING' && triagedClaim ? { claim: triagedClaim } : {}),
    });
    let extra = '';
    if (item.kind === 'EXPLOIT_POC') {
      const port = rt.subject.ports.validation;
      const handle = rt.handles.get(item.handles[0] ?? '');
      const oracle = handle ? ORACLE_FOR_CATEGORY[handle.category] : undefined;
      if (!port || !handle || !oracle) {
        await this.transition(rt, current, 'blocked', worker, {
          blockedReason: !port ? 'no validation sandbox in this runtime' : 'the finding is not runtime-verifiable',
        });
        return 'blocked';
      }
      const ws = await port.open(handle.handle);
      extra = [
        `Validation workspace: ${ws.workspaceId}. The code under test is at ../src relative to harness/ (working directory /work). Interpreters: ${ws.interpreters.join(', ')}.`,
        `Oracle: ${oracle}. ${ORACLE_GUIDE[oracle]}`,
        'In control mode (SPX_MODE=control) send a benign input that exercises the same code path. Write the harness with harness_write, run it with validation_run, then submit.',
      ].join('\n');
    }
    if (item.kind === 'REVIEW_POC') extra = await this.pocReviewContext(rt, item);
    if (!submit) {
      await this.transition(rt, current, 'blocked', worker, {
        blockedReason: `${item.kind} is not handled by this orchestrator`,
      });
      return 'blocked';
    }
    const tools = this.forPersona(persona, this.workerTools(rt, persona, runId, item));
    const result = await this.session(rt, {
      persona,
      runId,
      itemId: item.itemId,
      tools,
      submit,
      prompt: `${await itemPrompt(item, await this.promptContext(rt))}${extra ? `\n\n${extra}` : ''}`,
    });
    if (result.status === 'SUSPENDED') {
      this.emit({
        type: 'approval',
        caseId: rt.rc.caseId,
        message: `${item.title}: waiting for a human`,
        data: { approvals: result.suspendedOn?.approvalIds },
      });
      return 'parked';
    }
    current = (await rt.cases.getWorkItem(item.itemId)) ?? current;
    // A pause interrupts the session between turns: the item stays in progress and its durable
    // session resumes from the last checkpoint when the case is resumed (ADR-042, ADR-052).
    if (result.status === 'CANCELLED' && controlOf(rt.signal) === 'pause') return 'paused';
    if (result.status !== 'COMPLETED' || result.output === undefined) {
      const reason = `${result.status.toLowerCase()}${result.error ? `: ${result.error}` : ''}`;
      await this.transition(rt, current, 'blocked', worker, {
        blockedReason: reason.slice(0, 500),
        attempts: current.attempts + 1,
      });
      rt.deferred.push(`${item.title}: ${reason}`);
      return 'blocked';
    }
    const output = JSON.parse(rt.subject.scrubber.scrub(JSON.stringify(result.output)));
    const inReview = await this.transition(rt, current, 'review', worker, { result: output });
    try {
      const accepted = await this.accept(rt, inReview, output, { persona: persona.manifest.id, runId });
      // A confirmed PoC stays in review until an independent validator has checked the harness.
      if (accepted?.hold) return 'done';
      await this.transition(rt, inReview, 'done', { kind: 'host' }, accepted?.patch ?? {});
      return 'done';
    } catch (err) {
      await this.transition(rt, inReview, 'in_progress', { kind: 'host' });
      const blocked = (await rt.cases.getWorkItem(item.itemId)) as WorkItem;
      await this.transition(
        rt,
        blocked,
        'blocked',
        { kind: 'host' },
        { blockedReason: (err as Error).message.slice(0, 500), attempts: blocked.attempts + 1 },
      );
      return 'blocked';
    }
  }

  /** Host acceptance of a deliverable: independence, verdicts, new agent findings. */
  private async accept(
    rt: CaseRuntime,
    item: WorkItem,
    output: unknown,
    by: RunRef,
  ): Promise<{ hold?: boolean; patch?: Partial<WorkItem> } | undefined> {
    const at = this.now().toISOString();
    if (item.kind === 'EXPLOIT_POC') return this.acceptPoc(rt, item, output as PocDeliverable);
    if (item.kind === 'REVIEW_POC') {
      await this.acceptPocReview(rt, item, output as PocReviewDeliverable, by);
      return undefined;
    }
    if (item.kind === 'TRIAGE_FINDING') {
      let d = output as TriageDeliverable;
      if (!item.handles.includes(d.handle))
        throw new Error(`the deliverable is about ${d.handle}, not ${item.handles.join(', ')}`);
      checkIndependence(rt.handles.get(d.handle)?.producer, by);
      // Downgrade-don't-delete backstop (ADR-050): a self-contradicting verdict is held, never flipped.
      const issue = consistencyIssue(d);
      if (issue) {
        const original = d.verdict;
        d = {
          ...d,
          verdict: 'BLOCKED',
          confidence: 'LOW',
          missingEvidence: [`host consistency check: ${issue}`, ...d.missingEvidence].slice(0, 8),
        };
        await this.audit(rt.cases, rt.rc.caseId, 'verdict.overridden', {
          handle: d.handle,
          from: original,
          to: 'BLOCKED',
          reason: issue,
          validator: by,
        });
        await rt.cases.appendJournal({
          caseId: rt.rc.caseId,
          kind: 'DECISION',
          author: 'host',
          itemId: item.itemId,
          handles: [d.handle],
          refs: [],
          text: `Verdict ${original} for ${d.handle} held as BLOCKED by the host: ${issue}`,
        });
      }
      await this.recordVerdict(rt, triageVerdict(rt.rc.caseId, d, by, at), item);
      if (d.verdict === 'FALSE_POSITIVE' && d.noiseReason) await this.rememberNoise(rt, d, by);
      return undefined;
    }
    if (item.kind === 'RECON') {
      await this.acceptRecon(rt, item, output as ReconDeliverableLike, by);
      return undefined;
    }
    if (item.kind === 'COMPLETENESS_CRITIC' && item.subjectItemId) {
      const subject = await rt.cases.getWorkItem(item.subjectItemId);
      checkIndependence(subject?.producer, by);
    }
    if (item.kind === 'DEPENDENCY_APPLICABILITY') {
      const d = output as ApplicabilityDeliverable;
      if (!item.handles.includes(d.handle))
        throw new Error(`the deliverable is about ${d.handle}, not ${item.handles.join(', ')}`);
      const handle = rt.handles.get(d.handle);
      const pkg = this.packageOf(handle);
      const usage =
        pkg && rt.subject.ports.dependencies
          ? await rt.subject.ports.dependencies.reachability({
              ...pkg,
              ...(d.vulnerableSymbols.length ? { symbols: d.vulnerableSymbols } : {}),
              ...(d.symbolSource !== 'none' ? { symbolSource: d.symbolSource } : {}),
            })
          : undefined;
      const records =
        pkg && rt.subject.ports.dependencies
          ? (await rt.subject.ports.dependencies.inventory()).filter((r) => r.name === pkg.name)
          : [];
      const devOnly = records.length > 0 && records.every((r) => r.scope === 'development' || r.scope === 'test');
      await this.recordVerdict(
        rt,
        applicabilityVerdict(rt.rc.caseId, d, by, at, { devOnly, ...(usage ? { reachability: usage.level } : {}) }),
        item,
      );
      return undefined;
    }
    const d = output as FindingsDeliverable;
    const drafts: CandidateDraft[] = d.findings.map((f) => ({
      scanner: 'ai-review',
      ruleId: `ai-review.${f.category.toLowerCase()}`,
      ruleFamily: f.category.toLowerCase(),
      category: f.category,
      cwe: f.cwe,
      title: f.title,
      message: `${f.summary} Claim: ${f.claim}${f.proofObligations.length ? ` Proof obligations: ${f.proofObligations.join('; ')}` : ''}`,
      severityHint: f.severity,
      confidenceHint: f.confidence,
      locations: f.locations.map((l) => ({ ...l, role: l.role })),
      claim: {
        claim: f.claim,
        preconditions: f.preconditions,
        capabilitiesGained: f.capabilitiesGained,
        proofObligations: f.proofObligations,
        threatModelClass: f.threatModelClass,
        ...(f.baselineReference ? { baselineReference: f.baselineReference } : {}),
        ...(f.invariantId ? { invariantId: f.invariantId } : {}),
        ...(f.familyId ? { familyId: f.familyId } : {}),
        ...(f.sourcePass ? { sourcePass: f.sourcePass } : {}),
      },
    }));
    const registered = await this.registerDrafts(rt, drafts, by, item.itemId);
    await this.maybeSeedCritic(rt, item, registered.created.length);
    for (const gap of d.deferred) {
      await rt.cases.appendJournal({
        caseId: rt.rc.caseId,
        kind: 'GAP',
        author: `${by.persona}/${by.runId}`,
        itemId: item.itemId,
        handles: [],
        refs: [],
        text: gap,
      });
      rt.deferred.push(`${item.title}: ${gap}`);
    }
    if (d.notes) {
      await rt.cases.appendJournal({
        caseId: rt.rc.caseId,
        kind: 'OBSERVATION',
        author: `${by.persona}/${by.runId}`,
        itemId: item.itemId,
        handles: [],
        refs: [],
        text: d.notes,
      });
    }
    return undefined;
  }

  private async recordVerdict(rt: CaseRuntime, verdict: CaseVerdict, item: WorkItem): Promise<void> {
    await rt.cases.saveVerdict(verdict);
    await rt.cases.appendJournal({
      caseId: rt.rc.caseId,
      kind: 'VERDICT',
      author: `${verdict.validator?.persona}/${verdict.validator?.runId}`,
      itemId: item.itemId,
      handles: [verdict.handle],
      refs: verdict.evidence.map(({ path, startLine, endLine }) => ({ path, startLine, endLine })),
      text: `${verdict.verdict} ${verdict.severity ?? ''}: ${verdict.rationale}`.slice(0, 4000),
    });
    await this.audit(rt.cases, rt.rc.caseId, 'verdict.applied', {
      handle: verdict.handle,
      verdict: verdict.verdict,
      severity: verdict.severity,
      validator: verdict.validator,
    });
    this.emit({
      type: 'verdict',
      caseId: rt.rc.caseId,
      message: `${verdict.handle}: ${verdict.verdict} ${verdict.severity ?? ''}`,
    });
    await this.maybeSeedPoc(rt, verdict);
  }

  /** L3 (ADR-045): a confirmed, runtime-verifiable HIGH+ finding gets a sandboxed PoC when enabled. */
  private async maybeSeedPoc(rt: CaseRuntime, verdict: CaseVerdict): Promise<void> {
    if (!this.o.config.l3 || !rt.subject.ports.validation || verdict.verdict !== 'TRUE_POSITIVE' || verdict.poc) return;
    const handle = rt.handles.get(verdict.handle);
    if (!handle || !ORACLE_FOR_CATEGORY[handle.category]) return;
    if (!['HIGH', 'CRITICAL'].includes(verdict.severity ?? handle.severity)) return;
    const itemId = `${rt.rc.caseId}:poc-${handle.handle}`;
    if (await rt.cases.getWorkItem(itemId)) return;
    const at = this.now().toISOString();
    await rt.cases.saveWorkItem({
      itemId,
      caseId: rt.rc.caseId,
      kind: 'EXPLOIT_POC',
      title: `Prove ${handle.handle} (${handle.title}) in the sandbox`,
      description: `Confirmed by ${verdict.validator?.persona ?? 'a validator'}: ${verdict.rationale.slice(0, 1500)}`,
      status: 'todo',
      mandatory: true,
      persona: 'exploit',
      handles: [handle.handle],
      dependsOn: [],
      createdBy: 'host',
      round: rt.rc.round,
      attempts: 0,
      createdAt: at,
      updatedAt: at,
    });
  }

  private async acceptPoc(
    rt: CaseRuntime,
    item: WorkItem,
    d: PocDeliverable,
  ): Promise<{ hold?: boolean; patch?: Partial<WorkItem> }> {
    if (!item.handles.includes(d.handle))
      throw new Error(`the PoC is about ${d.handle}, not ${item.handles.join(', ')}`);
    const run = await rt.subject.ports.validation?.lastRun(d.workspaceId, d.handle);
    if (!run) throw new Error(`no validation run for ${d.handle}`);
    await rt.cases.appendJournal({
      caseId: rt.rc.caseId,
      kind: 'EVIDENCE',
      author: `${item.producer?.persona}/${item.producer?.runId}`,
      itemId: item.itemId,
      handles: [d.handle],
      refs: [],
      text: `PoC run (${run.oracle}): host decision ${run.outcome} — ${run.detail}. ${d.summary}`.slice(0, 4000),
      data: { harnessDigest: run.harnessDigest, workspaceId: run.workspaceId },
    });
    await this.audit(rt.cases, rt.rc.caseId, 'validation.oracle', {
      handle: d.handle,
      oracle: run.oracle,
      outcome: run.outcome,
      attackTriggered: run.attackTriggered,
      controlTriggered: run.controlTriggered,
      harnessDigest: run.harnessDigest,
    });
    if (run.outcome !== 'CONFIRMED') {
      await this.updatePoc(rt, d.handle, {
        outcome: run.outcome,
        oracle: run.oracle,
        runs: 1,
        attackTriggered: run.attackTriggered,
        controlTriggered: run.controlTriggered,
        harnessDigest: run.harnessDigest,
        detail: run.detail,
      });
      return { patch: { result: { ...(item.result as object), needsVerification: false } } };
    }
    const at = this.now().toISOString();
    await rt.cases.saveWorkItem({
      itemId: `${rt.rc.caseId}:review-poc-${d.handle}`,
      caseId: rt.rc.caseId,
      kind: 'REVIEW_POC',
      title: `Review the PoC harness of ${d.handle}`,
      description: `Workspace ${d.workspaceId}, oracle ${d.oracle}. Exploit summary: ${d.summary}`,
      status: 'todo',
      mandatory: true,
      persona: 'validator',
      handles: [d.handle],
      dependsOn: [],
      subjectItemId: item.itemId,
      createdBy: 'host',
      round: rt.rc.round,
      attempts: 0,
      createdAt: at,
      updatedAt: at,
    });
    return { hold: true };
  }

  private async acceptPocReview(rt: CaseRuntime, item: WorkItem, d: PocReviewDeliverable, by: RunRef): Promise<void> {
    const subject = item.subjectItemId ? await rt.cases.getWorkItem(item.subjectItemId) : undefined;
    if (subject?.status !== 'review') throw new Error('the PoC under review is not waiting for review');
    checkIndependence(subject.producer, by);
    const ws = (subject.result as PocDeliverable | undefined)?.workspaceId ?? '';
    const run = await rt.subject.ports.validation?.lastRun(ws, d.handle);
    if (!run) throw new Error(`no validation run for ${d.handle}`);
    const confirmed = d.approve && run.outcome === 'CONFIRMED';
    await this.updatePoc(
      rt,
      d.handle,
      {
        outcome: confirmed ? 'CONFIRMED' : 'INVALID_HARNESS',
        oracle: run.oracle,
        runs: 1,
        attackTriggered: run.attackTriggered,
        controlTriggered: run.controlTriggered,
        harnessDigest: run.harnessDigest,
        reviewedBy: by.runId,
        detail:
          `${run.detail}. Review: ${d.reason}${d.concerns.length ? ` Concerns: ${d.concerns.join('; ')}` : ''}`.slice(
            0,
            2000,
          ),
      },
      by,
    );
    await this.transition(
      rt,
      subject,
      'done',
      { kind: 'host' },
      {
        verifier: by,
        ...(confirmed ? {} : { result: { ...(subject.result as object), needsVerification: false } }),
      },
    );
  }

  /** Records the PoC outcome on the latest verdict of a handle (L3 only when CONFIRMED and reviewed). */
  private async updatePoc(
    rt: CaseRuntime,
    handle: string,
    poc: NonNullable<CaseVerdict['poc']>,
    reviewer?: RunRef,
  ): Promise<void> {
    const latest = (await rt.cases.listVerdicts(rt.rc.caseId)).filter((v) => v.handle === handle).at(-1);
    if (!latest) return;
    const confirmed = poc.outcome === 'CONFIRMED' && poc.reviewedBy !== undefined;
    const next: CaseVerdict = {
      ...latest,
      poc,
      ...(confirmed ? { verificationLevel: 'L3_CONTROLLED', classification: 'CONFIRMED', confidence: 'HIGH' } : {}),
      ...(reviewer ? { validator: latest.validator ?? reviewer } : {}),
      at: this.now().toISOString(),
    };
    await rt.cases.saveVerdict(next);
    await rt.cases.appendJournal({
      caseId: rt.rc.caseId,
      kind: 'VERDICT',
      author: 'host',
      handles: [handle],
      refs: [],
      text: `PoC ${poc.outcome}${confirmed ? ' (L3, reviewed)' : ''}: ${poc.detail}`.slice(0, 4000),
    });
    this.emit({ type: 'verdict', caseId: rt.rc.caseId, message: `${handle}: PoC ${poc.outcome}` });
  }

  /** What the reviewing validator sees: the harness, both runs and the oracle. */
  private async pocReviewContext(rt: CaseRuntime, item: WorkItem): Promise<string> {
    const subject = item.subjectItemId ? await rt.cases.getWorkItem(item.subjectItemId) : undefined;
    const d = subject?.result as PocDeliverable | undefined;
    const port = rt.subject.ports.validation;
    if (!d || !port) return 'The PoC under review is not available.';
    const files = await port.harnessFiles(d.workspaceId);
    const run = await port.lastRun(d.workspaceId, d.handle);
    return [
      'You review a proof of concept written by another agent. Approve only if the attack input reaches the oracle marker through the vulnerable code identified by the finding, the control run sends a benign input through the same path, and the harness does not produce the marker itself (directly, through a helper, or by branching on SPX_MODE beyond choosing the input).',
      ...Object.entries(files).map(
        ([path, content]) =>
          `<untrusted_harness path="${path}">\n${rt.subject.scrubber.scrub(content).slice(0, 8000)}\n</untrusted_harness>`,
      ),
      run
        ? `Host oracle ${run.oracle}: ${run.outcome} (${run.detail}).\n--- attack run ---\n${run.attackLog}\n--- control run ---\n${run.controlLog}`
        : 'No run recorded.',
    ].join('\n\n');
  }

  /** New agent findings become handles with their producer and a mandatory independent triage. */
  private async registerDrafts(
    rt: CaseRuntime,
    drafts: CandidateDraft[],
    producer: RunRef,
    itemId?: string,
  ): Promise<{ handles: string[]; created: CaseHandle[] }> {
    const created: CaseHandle[] = [];
    const handles: string[] = [];
    for (const draft of drafts) {
      const locs = draft.locations.filter((l) => rt.snapshot.has(l.path));
      if (locs.length === 0) {
        handles.push('');
        continue;
      }
      const r = rt.handles.assign({ ...draft, locations: locs }, 'agent', producer);
      handles.push(r.handle.handle);
      if (itemId) rt.handleItems.set(r.handle.handle, itemId);
      if (r.created) created.push(r.handle);
    }
    await rt.cases.saveHandles(created);
    const at = this.now().toISOString();
    for (const h of created) {
      await rt.cases.saveWorkItem({
        itemId: `${rt.rc.caseId}:triage-${h.handle}`,
        caseId: rt.rc.caseId,
        kind: 'TRIAGE_FINDING',
        title: `Validate ${h.handle}: ${h.title} at ${h.path}:${h.startLine}`,
        description: `Reported by ${producer.persona}; confirm or refute it independently.`,
        status: 'todo',
        mandatory: true,
        persona: 'validator',
        handles: [h.handle],
        dependsOn: [],
        createdBy: 'host',
        round: rt.rc.round,
        attempts: 0,
        createdAt: at,
        updatedAt: at,
      });
    }
    return { handles, created };
  }

  /** The RECON deliverable becomes the case's ground truth; uncovered families get logic audits (ADR-049). */
  private async acceptRecon(rt: CaseRuntime, item: WorkItem, d: ReconDeliverableLike, by: RunRef): Promise<void> {
    const gt = mergeOperatorContext(GroundTruth.parse(d.groundTruth), this.o.config.context);
    rt.groundTruth = gt;
    const author = `${by.persona}/${by.runId}`;
    await rt.cases.appendJournal({
      caseId: rt.rc.caseId,
      kind: 'OBSERVATION',
      author,
      itemId: item.itemId,
      handles: [],
      refs: [],
      text: subjectScrub(
        rt,
        `Recon: archetype ${gt.archetype}${gt.archetypeNote ? ` (${gt.archetypeNote})` : ''}; ${gt.invariants.length} invariants, ${gt.baselines.length} baseline references, ${gt.families.length} variant families, ${gt.carveouts.length} carve-outs, ${gt.residualUnknowns.length} residual unknowns. ${d.threatModel.summary}`.slice(
          0,
          4000,
        ),
      ),
    });
    for (const u of gt.residualUnknowns) {
      await rt.cases.appendJournal({
        caseId: rt.rc.caseId,
        kind: 'GAP',
        author,
        itemId: item.itemId,
        handles: [],
        refs: [],
        text: subjectScrub(rt, `${u.unknownId} [${u.kind}] ${u.question} — ${u.whySourceCannotSettle}`),
        data: { unknownId: u.unknownId, kind: u.kind, affects: u.affects },
      });
    }
    await this.askContextQuestions(rt, gt);
    // Families the census did not already turn into a LOGIC_AUDIT get one, within the cap.
    const items = await rt.cases.listWorkItems(rt.rc.caseId);
    const logicItems = items.filter((i) => i.kind === 'LOGIC_AUDIT');
    const covered = new Set(
      logicItems.flatMap((i) => [...`${i.title}\n${i.description}`.matchAll(/\bFAM-\d+\b/g)].map((m) => m[0])),
    );
    const coveredPaths = new Set(
      logicItems.flatMap((i) =>
        [...i.description.matchAll(/([\w./-]+\.[A-Za-z0-9]+):\d+/g)].map((m) => m[1] as string),
      ),
    );
    const cap = this.o.config.recon?.maxLogicItems ?? 8;
    const at = this.now().toISOString();
    let count = logicItems.length;
    for (const f of gt.families) {
      if (count >= cap) break;
      if (covered.has(f.familyId) || f.members.every((m) => coveredPaths.has(m.path))) continue;
      const itemId = `${rt.rc.caseId}:${logicItemSlug(`fam-${f.familyId}`)}`;
      if (await rt.cases.getWorkItem(itemId)) continue;
      await rt.cases.saveWorkItem({
        itemId,
        caseId: rt.rc.caseId,
        kind: 'LOGIC_AUDIT',
        title: `Logic audit of ${f.familyId}: ${f.rootCause.slice(0, 120)}`,
        description: `Variant family ${f.familyId}${f.baselineId ? ` (baseline ${f.baselineId})` : ''}:\n${f.members.map((m) => `- ${m.path}:${m.startLine} ${m.label}`).join('\n')}`,
        status: 'todo',
        mandatory: true,
        persona: 'logic',
        handles: [],
        dependsOn: [],
        createdBy: 'host',
        round: rt.rc.round,
        attempts: 0,
        createdAt: at,
        updatedAt: at,
      });
      count++;
    }
  }

  /** Residual unknowns become human-only review questions in the inbox (ADR-051); the case does not park. */
  private async askContextQuestions(rt: CaseRuntime, gt: GroundTruth): Promise<void> {
    const created = await askContextQuestions(rt.cases, rt.rc, gt.residualUnknowns, this.now());
    for (const a of created) {
      this.emit({
        type: 'approval',
        caseId: rt.rc.caseId,
        message: `review question for a human: ${a.title}`,
        data: { approvalId: a.approvalId, humanOnly: true, question: true },
      });
    }
  }

  /** After a hunt item, a critic re-pass looks only for what was missed, until a pass adds nothing (ADR-049). */
  private async maybeSeedCritic(rt: CaseRuntime, item: WorkItem, created: number): Promise<void> {
    const passes = this.o.config.recon?.enabled ? this.o.config.recon.criticPasses : 0;
    if (passes <= 0 || !rt.groundTruth) return;
    let subjectId = item.itemId;
    let pass = 1;
    if (item.kind === 'COMPLETENESS_CRITIC') {
      if (!item.subjectItemId) return;
      const m = /-critic-(\d+)$/.exec(item.itemId);
      pass = (m ? Number(m[1]) : 1) + 1;
      subjectId = item.subjectItemId;
      if (created === 0) {
        await rt.cases.appendJournal({
          caseId: rt.rc.caseId,
          kind: 'NOTE',
          author: 'host',
          itemId: item.itemId,
          handles: [],
          refs: [],
          text: `Critic pass ${pass - 1} over ${subjectId.split(':').pop()} added nothing new; stopping.`,
        });
        return;
      }
    } else if (!CRITIQUED_KINDS.has(item.kind)) return;
    if (pass > passes) return;
    const itemId = `${subjectId}-critic-${pass}`;
    if (await rt.cases.getWorkItem(itemId)) return;
    const subject = subjectId === item.itemId ? item : await rt.cases.getWorkItem(subjectId);
    const at = this.now().toISOString();
    await rt.cases.saveWorkItem({
      itemId,
      caseId: rt.rc.caseId,
      kind: 'COMPLETENESS_CRITIC',
      title: `Completeness re-pass ${pass}: ${(subject ?? item).title.slice(0, 120)}`,
      description: (subject ?? item).description,
      status: 'todo',
      mandatory: true,
      persona: 'critic',
      handles: [],
      dependsOn: [item.itemId],
      subjectItemId: subjectId,
      createdBy: 'host',
      round: rt.rc.round,
      attempts: 0,
      createdAt: at,
      updatedAt: at,
    });
  }

  private async loadGroundTruth(rt: CaseRuntime): Promise<GroundTruth | undefined> {
    const recon = await rt.cases.getWorkItem(`${rt.rc.caseId}:${RECON_ITEM}`);
    const parsed = GroundTruth.safeParse((recon?.result as { groundTruth?: unknown } | undefined)?.groundTruth);
    return parsed.success ? mergeOperatorContext(parsed.data, this.o.config.context) : undefined;
  }

  private async rememberNoise(rt: CaseRuntime, d: TriageDeliverable, by: RunRef): Promise<void> {
    const handle = rt.handles.get(d.handle);
    if (!handle) return;
    const now = this.now().toISOString();
    await rt.cases.saveMemory({
      memoryId: `mem_${handle.draftRef.slice(7, 39)}`,
      projectId: rt.rc.projectId,
      kind: 'LESSON',
      status: initialMemoryStatus('LESSON', 'agent'),
      key: `${handle.ruleId}|${handle.path}`,
      text: `${handle.ruleId} at ${handle.path}:${handle.startLine} judged a false positive: ${d.noiseReason}`,
      sourceCaseId: rt.rc.caseId,
      createdBy: `agent:${by.persona}/${by.runId}`,
      createdAt: now,
      updatedAt: now,
    });
  }

  // Remediation (after the scan committed the case's findings)

  /**
   * Fix loop with an independent verifier (ADR-045): the fixer iterates with re-scan and test
   * feedback; a verifier persona (another persona, another run) approves, requests changes or
   * rejects; an approved patch becomes a human-only request to change the repository. The store
   * enforces fixer ≠ verifier on the FIX item; nothing is applied without a human.
   */
  async remediate(o: {
    cases: CaseRepository;
    caseId: string;
    source: SourceTree;
    snapshotPaths: readonly string[];
    redactions: readonly Location[];
    scrubber: SecretScrubber;
    targets: readonly RemediationTarget[];
    fix: (findingId: string, feedback?: string) => Promise<{ result: PatchResult; attempts: PatchResult[] }>;
    apply: (patchId: string) => Promise<string[]>;
    maxReviewCycles?: number;
    signal?: AbortSignal;
  }): Promise<RemediationOutcome[]> {
    const rc = await o.cases.getCase(o.caseId);
    if (!rc) throw new Error(`case ${o.caseId} not found`);
    const verifier = this.personas.get('verifier');
    if (!verifier) throw new Error('verifier persona missing');
    const rt: CaseRuntime = {
      rc,
      subject: {
        scan: { scanId: rc.scanId, projectId: rc.projectId, snapshotId: rc.snapshotId } as never,
        snapshotPaths: o.snapshotPaths,
        scannerDrafts: [],
        redactions: o.redactions,
        scrubber: o.scrubber,
        ports: { cases: o.cases, images: { toolbox: '', scanners: {} }, workDir: '' },
      },
      source: o.source,
      cases: o.cases,
      handles: new HandleTable(o.caseId, await o.cases.listHandles(o.caseId)),
      snapshot: new Set(o.snapshotPaths),
      ...(o.signal ? { signal: o.signal } : {}),
      deadline: Date.now() + this.o.config.maxWallClockMin * 60_000,
      maxCostUsd: this.o.config.maxCostUsd,
      runIds: [],
      deferred: [],
      reviewerBreaker: new ConsecutiveBreaker(5),
      exploreLimit: new Semaphore(3),
      handleItems: new Map(),
    };
    const out: RemediationOutcome[] = [];
    for (const target of o.targets) {
      let feedback: string | undefined;
      let outcome: RemediationOutcome | undefined;
      for (let cycle = 0; cycle <= (o.maxReviewCycles ?? 2) && !outcome; cycle++) {
        const { result } = await o.fix(target.findingId, feedback);
        const at = this.now().toISOString();
        const fixer: RunRef = { persona: 'fixer', runId: result.runId ?? `fix_${result.patchId}` };
        if (result.status !== 'verified' && result.status !== 'rescan_passed') {
          outcome = {
            findingId: target.findingId,
            patchId: result.patchId,
            status: 'unverified',
            reason: `${result.status}: ${result.reason ?? ''}`,
          };
          break;
        }
        let fixItem: WorkItem = {
          itemId: `${o.caseId}:fix-${target.findingId}-${cycle}`,
          caseId: o.caseId,
          kind: 'FIX',
          title: `Fix ${target.findingId}: ${target.title}`,
          description: result.proposal?.summary ?? '',
          status: 'review',
          mandatory: false,
          persona: 'fixer',
          handles: [],
          dependsOn: [],
          producer: fixer,
          result: { patchId: result.patchId, status: result.status, diffFiles: result.files },
          createdBy: 'host',
          round: rc.round,
          attempts: cycle,
          createdAt: at,
          updatedAt: at,
        };
        await o.cases.saveWorkItem(fixItem);
        const runId = `run_verify_${sha256Hex(result.patchId).slice(0, 16)}`;
        const by: RunRef = { persona: verifier.manifest.id, runId };
        checkIndependence(fixer, by);
        const code = createCodeTools({ source: o.source, paths: o.snapshotPaths, redactions: o.redactions }).map(
          withPathTargets,
        );
        const review = await this.session(rt, {
          persona: verifier,
          runId,
          itemId: fixItem.itemId,
          tools: this.forPersona(verifier, code),
          submit: {
            name: 'submit_fix_review',
            description: 'Approve, request changes or reject the fix.',
            output: FixReviewDeliverable,
          },
          prompt: fixReviewPrompt(target, {
            ...(result.diff ? { diff: o.scrubber.scrub(result.diff) } : {}),
            ...(result.proposal?.summary ? { summary: result.proposal.summary } : {}),
            verification: result.verification,
            ...(result.reason ? { reason: result.reason } : {}),
          }),
        });
        const d = review.output as FixReviewDeliverable | undefined;
        await o.cases.appendJournal({
          caseId: o.caseId,
          kind: 'DECISION',
          author: `${by.persona}/${by.runId}`,
          handles: [],
          refs: [],
          text: `Fix ${result.patchId} for ${target.findingId}: ${d?.verdict ?? review.status} — ${d?.comments ?? review.error ?? ''}`.slice(
            0,
            4000,
          ),
        });
        if (!d) {
          outcome = {
            findingId: target.findingId,
            patchId: result.patchId,
            status: 'unverified',
            reason: `the verifier did not finish (${review.status})`,
          };
          break;
        }
        if (d.verdict === 'request_changes') {
          fixItem = await this.transition(rt, fixItem, 'in_progress', { kind: 'host' });
          await this.transition(rt, fixItem, 'cancelled', { kind: 'host' });
          feedback = `An independent reviewer asked for changes:
${d.comments}
Risks: ${d.risks.join('; ')}`;
          continue;
        }
        fixItem = await this.transition(
          rt,
          fixItem,
          'done',
          { kind: 'host' },
          {
            verifier: by,
            ...(d.verdict === 'reject' ? { result: { ...(fixItem.result as object), needsVerification: false } } : {}),
          },
        );
        if (d.verdict === 'reject') {
          outcome = { findingId: target.findingId, patchId: result.patchId, status: 'rejected', reason: d.comments };
          break;
        }
        outcome = await this.requestApply(rt, target, result, d, o.apply);
      }
      out.push(outcome ?? { findingId: target.findingId, status: 'unverified', reason: 'review cycles exhausted' });
    }
    return out;
  }

  /** Human-only request to change the repository with a verified, reviewed patch. */
  private async requestApply(
    rt: CaseRuntime,
    target: RemediationTarget,
    patch: PatchResult,
    review: FixReviewDeliverable,
    apply: (patchId: string) => Promise<string[]>,
  ): Promise<RemediationOutcome> {
    const toolCallId = `apply_${patch.patchId}`;
    const request: PermissionRequest = {
      toolCallId,
      caseId: rt.rc.caseId,
      tool: 'request_apply',
      inputValid: true,
      targets: [],
      exec: 'none',
      argsText: JSON.stringify({ patchId: patch.patchId, findingId: target.findingId }),
    };
    const decision = evaluate(request, {
      ...(await this.policyContext(rt, { manifest: { tools: ['request_apply'] } } as Persona, request)),
      personaTools: 'any',
    });
    await this.audit(rt.cases, rt.rc.caseId, 'policy.decided', {
      tool: 'request_apply',
      outcome: decision.outcome,
      layer: decision.layer,
      rule: decision.rule,
      humanOnly: decision.humanOnly,
    });
    const approval = buildApprovalRequest({
      approvalId: `apr_${sha256Hex(toolCallId).slice(0, 20)}`,
      projectId: rt.rc.projectId,
      caseId: rt.rc.caseId,
      toolCallId,
      tool: 'request_apply',
      decision,
      title: `Apply the verified fix for ${target.findingId} (${target.title}) to your repository`,
      summary:
        `Re-scan ${patch.verification.rescan.toLowerCase()}, tests ${patch.verification.tests}. Reviewer: ${review.comments}`.slice(
          0,
          2000,
        ),
      targets: patch.files.map((f) => ({ kind: 'repo_path' as const, value: f })),
      argsPreview: JSON.stringify({ patchId: patch.patchId, findingId: target.findingId, files: patch.files }, null, 2),
      ...(patch.diff ? { diff: rt.subject.scrubber.scrub(patch.diff) } : {}),
    });
    const stored = await rt.cases.createApproval({
      ...approval,
      targets: [...approval.targets],
      offeredGrants: [...approval.offeredGrants],
      status: 'PENDING',
      requestedAt: this.now().toISOString(),
    });
    await this.audit(rt.cases, rt.rc.caseId, 'approval.requested', {
      approvalId: stored.approvalId,
      tool: 'request_apply',
      humanOnly: true,
      patchId: patch.patchId,
    });
    if (decision.outcome !== 'ask' || !decision.humanOnly) {
      return {
        findingId: target.findingId,
        patchId: patch.patchId,
        status: 'declined',
        reason: `policy ${decision.outcome} ${decision.layer}`,
      };
    }
    const { final } = await resolveApproval({ ...approval, approvalId: stored.approvalId }, this.approvers(rt), {
      onResolution: (r) => this.audit(rt.cases, rt.rc.caseId, 'approval.resolved', resolutionAudit(approval, r)),
    });
    if (final.status === 'parked') {
      return {
        findingId: target.findingId,
        patchId: patch.patchId,
        status: 'awaiting_approval',
        reason: 'waiting in the inbox',
        approvalId: stored.approvalId,
      };
    }
    const resolved = await rt.cases.resolveApproval(stored.approvalId, {
      status: final.status === 'approved' ? 'APPROVED' : 'DENIED',
      resolvedBy: final.by,
      ...(final.reason ? { reason: final.reason } : {}),
      resolvedAt: this.now().toISOString(),
    });
    if (resolved.approval.status !== 'APPROVED' || resolved.approval.resolvedBy?.kind !== 'human') {
      return {
        findingId: target.findingId,
        patchId: patch.patchId,
        status: 'declined',
        reason: final.reason ?? 'not approved by a human',
      };
    }
    const files = await apply(patch.patchId);
    await rt.cases.appendJournal({
      caseId: rt.rc.caseId,
      kind: 'DECISION',
      author: `human:${final.by.id}`,
      handles: [],
      refs: [],
      text: `Applied ${patch.patchId} to ${files.join(', ')}`,
    });
    await this.audit(rt.cases, rt.rc.caseId, 'tool.finished', {
      tool: 'apply_patch',
      patchId: patch.patchId,
      files,
      approvedBy: final.by.id,
    });
    return {
      findingId: target.findingId,
      patchId: patch.patchId,
      status: 'applied',
      reason: `applied to ${files.join(', ')}`,
    };
  }

  // Finish

  private async finish(rt: CaseRuntime, status: CaseStatus, reason: string): Promise<ReviewOutcome> {
    // Parked and paused cases continue later: nothing is reported as not run yet.
    const final = status !== 'PARKED' && status !== 'PAUSED';
    const items = await rt.cases.listWorkItems(rt.rc.caseId);
    if (final) {
      for (const i of items.filter((x) => x.mandatory && x.status !== 'done' && x.persona !== 'host')) {
        await rt.cases.saveCheck({
          caseId: rt.rc.caseId,
          checkId: `item:${i.itemId.split(':').pop()}`,
          title: i.title,
          outcome: 'NOT_RUN',
          reason: i.blockedReason ?? `${i.status} when the case stopped (${reason})`,
          at: this.now().toISOString(),
        });
      }
    }
    const objectives = evaluateObjectives(
      await rt.cases.listObjectives(rt.rc.caseId),
      await this.state(rt),
      final,
      this.now(),
    );
    await rt.cases.saveObjectives(objectives);
    rt.rc = await rt.cases.updateCase(rt.rc.caseId, {
      status,
      stopReason: reason,
      ...(final ? { completedAt: this.now().toISOString() } : {}),
    });
    const ledger = await rt.cases.getLedger(rt.rc.caseId);
    const head = (await rt.cases.listAudit(rt.rc.caseId)).at(-1)?.hash;
    await this.audit(rt.cases, rt.rc.caseId, 'case.stopped', {
      status,
      reason,
      objectives: objectives.map((o) => `${o.kind}:${o.status}`),
      costUsd: ledger.costUsd,
      auditHeadBeforeStop: head,
    });
    this.emit({ type: 'case', caseId: rt.rc.caseId, message: `case ${status.toLowerCase()}: ${reason}` });

    const verdicts = await rt.cases.listVerdicts(rt.rc.caseId);
    const latest = new Map<string, CaseVerdict>();
    for (const v of [...verdicts].sort((a, b) => a.at.localeCompare(b.at))) latest.set(v.handle, v);
    const drafts: CandidateDraft[] = [];
    for (const h of rt.handles.all()) {
      const draft = h.draft as CandidateDraft | undefined;
      if (!draft) continue;
      const v = latest.get(h.handle);
      // History secrets are scanner output the scan does not have yet; agent findings count only once validated.
      // Downgrade-don't-delete (ADR-050): a BLOCKED agent finding is kept (POTENTIAL, exempt from the
      // gate until confirmed) and listed as needing verification, never dropped.
      if (
        (h.origin === 'scanner' && h.scanner === 'gitleaks-history') ||
        (h.origin === 'agent' && (v?.verdict === 'TRUE_POSITIVE' || v?.verdict === 'BLOCKED'))
      ) {
        drafts.push(draft);
        if (v?.verdict === 'BLOCKED')
          rt.deferred.push(`${h.handle} (${h.title}) kept, needs verification: ${v.rationale.slice(0, 300)}`);
      } else if (h.origin === 'agent' && (!v || v.verdict === 'UNREVIEWED'))
        rt.deferred.push(`${h.handle} (${h.title}) was not confirmed by a validator`);
    }
    return {
      caseId: rt.rc.caseId,
      status,
      drafts,
      verdicts: [...latest.values()].flatMap((v) => {
        const h = rt.handles.get(v.handle);
        return h ? [{ draftRef: h.draftRef, verdict: v }] : [];
      }),
      costUsd: ledger.costUsd,
      deferred: rt.deferred,
      runIds: rt.runIds,
    };
  }

  // Sessions, tools, policy

  private async session(
    rt: CaseRuntime,
    s: {
      persona: Persona;
      runId: string;
      itemId?: string;
      tools: AgentTool<never>[];
      submit: Parameters<typeof runAgentSession>[0]['submit'];
      prompt: string;
    },
  ): Promise<SessionResult<unknown>> {
    const { persona, runId } = s;
    const provider = (persona.manifest.tier === 'fast' ? (this.o.fastProvider ?? this.o.provider) : this.o.provider)();
    const startedAt = this.now().toISOString();
    const memory = renderMemory(await rt.cases.listMemory({ projectId: rt.rc.projectId, status: 'active' }));
    const skills = this.skills.forPersona(persona.manifest.skills, persona.manifest.tools);
    const system = [
      persona.prompt.replace(/\{\{accepted_risks\}\}/g, acceptedRisksVar(this.o.config.context)),
      skills.length ? `## Playbooks (load with load_skill)\n${this.skills.index(skills)}` : '',
      memory,
    ]
      .filter(Boolean)
      .join('\n\n');
    const executor = new GovernedToolExecutor({
      cases: rt.cases,
      projectId: rt.rc.projectId,
      caseId: rt.rc.caseId,
      runId,
      persona: persona.manifest.id,
      ...(s.itemId ? { itemId: s.itemId } : {}),
      tools: s.tools,
      policy: (request) => this.policyContext(rt, persona, request),
      approvers: this.approvers(rt),
      scrubber: rt.subject.scrubber,
      now: this.now,
    });
    const result = await runAgentSession({
      runId,
      caseId: rt.rc.caseId,
      role: persona.manifest.role,
      provider,
      system,
      prompt: s.prompt,
      tools: s.tools,
      submit: s.submit,
      executor,
      store: caseSessionStore(rt.cases),
      budget: {
        maxSteps: persona.manifest.max_steps ?? 24,
        maxToolCalls: persona.manifest.max_tool_calls ?? 60,
        maxOutputTokens: 16_000,
        maxTotalTokens: 800_000,
      },
      ...(this.o.effort ? { effort: this.o.effort } : {}),
      ...(rt.signal ? { signal: rt.signal } : {}),
      scanId: rt.rc.scanId,
      costOf: this.costOf,
      onUsage: async (usage, _model, cost) => {
        await rt.cases.chargeLedger(rt.rc.caseId, {
          costUsd: cost ?? 0,
          inputTokens: usage.inputTokens,
          outputTokens: usage.outputTokens,
          modelCalls: 1,
          unpriced: cost === undefined,
        });
      },
      budgetGuard: async () => {
        const ledger = await rt.cases.getLedger(rt.rc.caseId);
        if (ledger.costUsd >= rt.maxCostUsd) return `case cost budget $${rt.maxCostUsd} reached`;
        if (Date.now() > rt.deadline) return 'case wall-clock budget reached';
        return undefined;
      },
      compaction: DEFAULT_COMPACTION,
      now: this.now,
    });
    const record: AgentRunRecord = {
      agentRunId: runId,
      role: persona.manifest.role,
      scanId: rt.rc.scanId,
      caseId: rt.rc.caseId,
      ...(s.itemId ? { workItemId: s.itemId } : {}),
      personaId: persona.manifest.id,
      provider: provider.id,
      model: provider.model,
      modelsUsed: result.models,
      promptBundleDigest: this.info.promptBundleDigest,
      status: result.status,
      usage: result.usage,
      ...(result.costUsd !== undefined ? { costUsd: result.costUsd } : {}),
      ...(result.output !== undefined ? { output: result.output } : {}),
      ...(result.error ? { error: result.error } : {}),
      ...(result.refusal?.category ? { refusalCategory: result.refusal.category } : {}),
      steps: result.steps.map((st) => ({
        index: st.index,
        stopReason: st.stopReason,
        model: st.model,
        toolCalls: st.toolCalls,
      })),
      startedAt,
      completedAt: this.now().toISOString(),
    };
    await rt.onRun?.(record);
    rt.runIds.push(runId);
    return result;
  }

  private approvers(rt: CaseRuntime) {
    const judgeProvider = this.o.judgeProvider ?? this.o.fastProvider ?? this.o.provider;
    return approverChain({
      mode: this.o.config.mode,
      attended: this.o.config.attended,
      reviewer: this.o.config.reviewer,
      judge: providerJudge(judgeProvider()),
      world: {
        goal: this.o.goal,
        mode: this.o.config.mode,
        objectives: this.o.objectives ?? [],
        facts: [`files: ${rt.subject.snapshotPaths.length}`, `L3 PoC enabled: ${this.o.config.l3}`],
      },
      breaker: rt.reviewerBreaker,
      ...(this.o.human && this.o.config.attended ? { human: this.o.human } : {}),
      park: async (request) => {
        this.emit({
          type: 'approval',
          caseId: rt.rc.caseId,
          message: `approval parked: ${request.title}`,
          data: { approvalId: request.approvalId },
        });
      },
      onReviewerEvent: async (event) => {
        if (event.type === 'verdict') {
          await this.audit(rt.cases, rt.rc.caseId, event.shadow ? 'reviewer.shadow' : 'reviewer.verdict', {
            approvalId: event.request.approvalId,
            tool: event.request.tool,
            verdict: event.verdict.verdict,
            reason: event.verdict.reason,
          });
        } else {
          await this.audit(rt.cases, rt.rc.caseId, 'reviewer.breaker_tripped', { denials: event.denials });
          await rt.cases.appendJournal({
            caseId: rt.rc.caseId,
            kind: 'GAP',
            author: 'host',
            handles: [],
            refs: [],
            text: `The reviewer model denied ${event.denials} actions in a row; every further ask goes to a human.`,
          });
        }
        this.emit({
          type: 'reviewer',
          caseId: rt.rc.caseId,
          message: event.type === 'verdict' ? `reviewer: ${event.verdict.verdict}` : 'reviewer breaker tripped',
        });
      },
    });
  }

  private async policyContext(rt: CaseRuntime, persona: Persona, request: PermissionRequest): Promise<PolicyContext> {
    const handle = request.targets.find((t) => t.kind === 'handle')?.value;
    const c = this.o.config;
    return {
      projectId: rt.rc.projectId,
      mode: c.mode,
      personaTools: new Set(persona.manifest.tools),
      denyTools: c.denyTools,
      riskOverrides: c.riskOverrides,
      protection: { protectedRoots: c.protectedRoots, extraProtected: c.extraProtected },
      dataPolicyExclude: c.dataPolicyExclude,
      ...(c.allowedProviders ? { allowedProviders: c.allowedProviders } : {}),
      scope: {
        workspaces: new Set(rt.subject.ports.validation?.workspaces() ?? []),
        handles: new Set(rt.handles.all().map((h) => h.handle)),
        repoPaths: rt.snapshot,
      },
      quota: quotaOf(
        await rt.cases.getLedger(rt.rc.caseId),
        {
          maxCostUsd: rt.maxCostUsd,
          maxSandboxRuns: c.maxSandboxRuns,
          maxSandboxCpuSec: c.maxSandboxCpuSec,
          maxRunsPerFinding: c.maxRunsPerFinding,
        },
        handle,
      ),
      grants: await rt.cases.listGrants({ projectId: rt.rc.projectId, caseId: rt.rc.caseId }),
      autoAllow: c.autoAllow,
      validationL3: c.l3,
      containsSecret: (text) => rt.subject.scrubber.detects(text),
      now: this.now(),
    };
  }

  private securityTools(rt: CaseRuntime, persona: string, runId: string, itemId?: string): AgentTool<never>[] {
    const p = rt.subject.ports;
    return createSecurityTools({
      caseId: rt.rc.caseId,
      projectId: rt.rc.projectId,
      persona,
      runId,
      ...(itemId ? { itemId } : {}),
      cases: rt.cases,
      handles: rt.handles,
      ...(p.probe ? { probe: p.probe } : {}),
      ...(p.dependencies ? { dependencies: p.dependencies } : {}),
      ...(p.kb ? { kb: p.kb } : {}),
      ...(p.shell ? { shell: p.shell } : {}),
      images: p.images,
      scrubber: rt.subject.scrubber,
      registerDrafts: async (drafts, producer) => (await this.registerDrafts(rt, drafts, producer, itemId)).handles,
      evidenceOf: (h) => this.evidenceOf(rt, h),
      now: this.now,
    }).map((t) => this.metered(rt, t));
  }

  private workerTools(rt: CaseRuntime, persona: Persona, runId: string, item: WorkItem): AgentTool<never>[] {
    const code = createCodeTools({
      source: rt.source,
      paths: rt.subject.snapshotPaths,
      redactions: rt.subject.redactions,
    }).map(withPathTargets);
    const graph = rt.subject.graph ? createGraphTools(rt.subject.graph) : [];
    const read = [...code, ...graph];
    const explorePersona = this.personas.get('explore');
    const explore = explorePersona
      ? [
          createExploreTool({
            provider: this.o.fastProvider ?? this.o.provider,
            tools: read,
            system: explorePersona.prompt,
            semaphore: rt.exploreLimit,
            parentRunId: runId,
            caseId: rt.rc.caseId,
            costOf: this.costOf,
            onRun: async (r) => {
              await rt.cases.chargeLedger(rt.rc.caseId, {
                costUsd: r.costUsd ?? 0,
                inputTokens: r.usage.inputTokens,
                outputTokens: r.usage.outputTokens,
                modelCalls: r.steps.length,
              });
              await rt.onRun?.({ ...r, scanId: rt.rc.scanId, workItemId: item.itemId });
            },
          }) as AgentTool<never>,
        ]
      : [];
    const skills = this.skills.forPersona(persona.manifest.skills, persona.manifest.tools);
    const validation = rt.subject.ports.validation
      ? createValidationTools({
          port: rt.subject.ports.validation,
          interpreters: rt.subject.ports.images.interpreters ?? {},
          onRun: async (handle) => {
            await rt.cases.chargeLedger(rt.rc.caseId, { validationRunFor: handle });
          },
        }).map((t) => this.metered(rt, t))
      : [];
    return [
      ...read,
      ...explore,
      ...validation,
      ...this.securityTools(rt, persona.manifest.id, runId, item.itemId),
      createSkillTool(skills) as AgentTool<never>,
    ];
  }

  /** Only tools in the persona manifest are offered (the policy engine re-checks at L0). */
  private forPersona(persona: Persona, tools: AgentTool<never>[]): AgentTool<never>[] {
    const allowed = new Set(persona.manifest.tools);
    const seen = new Set<string>();
    return tools.filter((t) => allowed.has(t.name) && !seen.has(t.name) && seen.add(t.name));
  }

  /** Sandboxed tools charge the case ledger (runs and seconds) after each run. */
  private metered(rt: CaseRuntime, tool: AgentTool<never>): AgentTool<never> {
    if (!tool.sandbox) return tool;
    return {
      ...tool,
      run: async (input, ctx) => {
        const started = Date.now();
        try {
          return await tool.run(input, ctx);
        } finally {
          await rt.cases.chargeLedger(rt.rc.caseId, {
            sandboxRuns: 1,
            sandboxCpuSec: Math.ceil((Date.now() - started) / 1000),
          });
        }
      },
    };
  }

  // Helpers

  private async historySweep(rt: CaseRuntime, created: CaseHandle[]): Promise<void> {
    const port = rt.subject.ports.history;
    const checks = await rt.cases.listChecks(rt.rc.caseId);
    if (checks.some((c) => c.checkId === 'secrets-history')) return;
    const at = this.now().toISOString();
    if (!port) {
      await rt.cases.saveCheck({
        caseId: rt.rc.caseId,
        checkId: 'secrets-history',
        title: 'Secrets in git history',
        outcome: 'NOT_RUN',
        reason: 'no history scanner configured',
        at,
      });
      return;
    }
    const result = await port.scan(rt.signal);
    await rt.cases.saveCheck({
      caseId: rt.rc.caseId,
      checkId: 'secrets-history',
      title: 'Secrets in git history',
      outcome: result.outcome,
      ...(result.reason ? { reason: result.reason } : {}),
      at,
    });
    rt.historySummary = `${result.outcome}${result.reason ? ` (${result.reason})` : ''}, ${result.secrets.length} secret(s) found`;
    for (const s of result.secrets) {
      const draft: CandidateDraft = {
        scanner: 'gitleaks-history',
        ruleId: `gitleaks-history.${s.ruleId}`,
        ruleFamily: 'hardcoded-secret',
        category: 'HARDCODED_SECRET',
        cwe: ['CWE-798'],
        title: `Secret committed in git history (${s.ruleId})`,
        message: `A ${s.ruleId} secret was committed in ${s.commit.slice(0, 12)}; rotate it even if the file changed since.`,
        severityHint: 'HIGH',
        confidenceHint: 'MEDIUM',
        locations: [{ path: s.path, startLine: Math.max(1, s.line), endLine: Math.max(1, s.line), role: 'primary' }],
        anchorHint: { symbol: `history:${s.commit.slice(0, 12)}`, shape: s.fingerprint || `${s.path}:${s.line}` },
      };
      const r = rt.handles.assign(draft, 'scanner');
      // The scan does not have history findings yet: keep the draft on the handle to report it.
      Object.assign(r.handle, { draft });
      if (r.created) created.push(r.handle);
    }
  }

  private packageOf(h: CaseHandle | undefined): { ecosystem: string; name: string } | undefined {
    if (!h?.packagePurl) return undefined;
    const m = /^pkg:([^/]+)\/(.+)@[^@]+$/.exec(h.packagePurl);
    if (!m) return undefined;
    const type = m[1] as string;
    const rest = decodeURIComponent(m[2] as string);
    const ecosystem = type === 'npm' ? 'npm' : type === 'pypi' ? 'PyPI' : type === 'maven' ? 'Maven' : type;
    return { ecosystem, name: type === 'maven' ? rest.replace('/', ':') : rest };
  }

  private async evidenceOf(rt: CaseRuntime, handle: string): Promise<string> {
    const h = rt.handles.get(handle);
    if (!h || !rt.snapshot.has(h.path)) return '(no excerpt: the file is not in the snapshot)';
    const lines = (await rt.source.readText(h.path))?.split(/\r?\n/) ?? [];
    const start = Math.max(1, h.startLine - 6);
    const end = Math.min(lines.length, h.startLine + 10);
    const body = applyRedactions(lines.slice(start - 1, end), start, h.path, rt.subject.redactions)
      .map((l, i) => `${String(start + i).padStart(5)} | ${redactSecrets(l).text}`)
      .join('\n');
    return rt.subject.scrubber.scrub(
      `<untrusted_repository_content path="${h.path}" lines="${start}-${end}">\n${body}\n</untrusted_repository_content>`,
    );
  }

  private async promptContext(rt: CaseRuntime) {
    const objectives = await rt.cases.listObjectives(rt.rc.caseId);
    let inventory: Promise<readonly DependencyInfo[]> | undefined;
    return {
      goal: this.o.goal,
      objectives,
      handle: (h: string) => rt.handles.get(h),
      evidence: (h: string) => this.evidenceOf(rt, h),
      inventory: () => {
        inventory ??= rt.subject.ports.dependencies?.inventory() ?? Promise.resolve([]);
        return inventory;
      },
      snapshotSize: rt.subject.snapshotPaths.length,
      endpointCount: rt.subject.graph?.endpoints().length ?? 0,
      duplicates: duplicateGroups(rt.handles.all()),
      ...(rt.historySummary ? { historySummary: rt.historySummary } : {}),
      ...(rt.groundTruth ? { groundTruth: rt.groundTruth } : {}),
      ...(rt.matrix ? { matrix: rt.matrix } : {}),
      operatorContext: renderOperatorContext(this.o.config.context),
      agentHandles: () =>
        rt.handles
          .all()
          .filter((h) => h.origin === 'agent')
          .map((h) => ({
            handle: h.handle,
            title: h.title,
            path: h.path,
            startLine: h.startLine,
            ...(rt.handleItems.has(h.handle) ? { itemId: rt.handleItems.get(h.handle) } : {}),
          })),
      itemResult: async (itemId: string) => (await rt.cases.getWorkItem(itemId))?.result,
    };
  }

  private async state(rt: CaseRuntime) {
    const items = await rt.cases.listWorkItems(rt.rc.caseId);
    const results = items
      .filter((i) => FINDINGS_KINDS.has(i.kind) && i.result)
      .map((i) => i.result as Partial<FindingsDeliverable>)
      .map((r) => ({ invariantResults: r.invariantResults ?? [], variantLog: r.variantLog ?? [] }));
    return {
      items,
      verdicts: await rt.cases.listVerdicts(rt.rc.caseId),
      handles: rt.handles.all(),
      checks: await rt.cases.listChecks(rt.rc.caseId),
      ...(rt.groundTruth ? { groundTruthCoverage: coverageOf(rt.groundTruth, results) } : {}),
    };
  }

  private async transition(
    rt: CaseRuntime,
    item: WorkItem,
    to: WorkItem['status'],
    actor: Parameters<typeof moveItem>[2],
    patch: Partial<WorkItem> = {},
  ): Promise<WorkItem> {
    const next = moveItem(item, to, actor, this.now(), patch);
    await rt.cases.saveWorkItem(next, item.updatedAt);
    await this.audit(rt.cases, rt.rc.caseId, 'item.transition', {
      itemId: item.itemId,
      from: item.status,
      to,
      by: actor.kind === 'worker' ? `${actor.persona}/${actor.runId}` : actor.kind,
      ...(next.blockedReason ? { reason: next.blockedReason } : {}),
    });
    return next;
  }

  private async audit(
    cases: CaseRepository,
    caseId: string,
    stage: Parameters<CaseRepository['appendAudit']>[0]['stage'],
    data: Record<string, unknown>,
  ) {
    await cases.appendAudit({ caseId, stage, actor: 'host', data });
  }

  private emit(event: CaseEvent): void {
    this.o.onEvent?.(event);
  }
}

interface ReconDeliverableLike {
  threatModel: { summary: string };
  groundTruth: unknown;
}

function subjectScrub(rt: CaseRuntime, text: string): string {
  return rt.subject.scrubber.scrub(text);
}

/** Adds policy targets to the read tools so data policy, scope and self-protection see the path. */
function withPathTargets(tool: AgentTool<never>): AgentTool<never> {
  if (tool.name === 'read_file') {
    return {
      ...tool,
      risk: 'READ',
      targets: (input: { path: string }) => [{ kind: 'repo_path', value: input.path }],
    } as AgentTool<never>;
  }
  if (tool.name === 'list_files' || tool.name === 'search_code') {
    return {
      ...tool,
      risk: 'READ',
      targets: (input: { path_prefix?: string }) => {
        const prefix = (input.path_prefix ?? '').replace(/^\.\/?/, '').replace(/\/+$/, '');
        return prefix ? [{ kind: 'repo_path', value: prefix }] : [];
      },
    } as AgentTool<never>;
  }
  return tool;
}

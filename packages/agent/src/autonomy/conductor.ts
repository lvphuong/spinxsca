import { type ResourceMatrix, renderCensus } from '@spinxsca/core';
import type { CaseHandle, Objective, Shard, WorkItem, WorkItemKind } from '@spinxsca/schemas';

/** Persona that triages a handle, by category: secrets and IaC have their own specialists. */
export function triagePersona(h: Pick<CaseHandle, 'category' | 'scanner'>): string {
  if (h.category === 'HARDCODED_SECRET') return 'secrets';
  if (h.category === 'INSECURE_CONFIGURATION' || h.scanner === 'trivy') return 'iac';
  return 'validator';
}

export interface EndpointRef {
  id: string;
  method: string;
  route: string;
  path: string;
  line: number;
}

export interface ConductorInput {
  caseId: string;
  now: Date;
  handles: readonly CaseHandle[];
  endpoints: readonly EndpointRef[];
  iacFiles: readonly string[];
  l3: boolean;
  /** Operator objectives (`--objectives`), each becomes a mandatory hypothesis item. */
  objectives: readonly string[];
  maxThreatPackets?: number;
  /** Recon-first flow (ADR-049): a RECON item runs before every hunt; false restores the Phase 5 board. */
  recon?: boolean;
  /** Deterministic census of the code index; flagged resource groups become LOGIC_AUDIT items. */
  matrix?: ResourceMatrix;
  maxLogicItems?: number;
  /** Rendered operator context (ADR-051) shown to the recon item. */
  operatorContext?: string;
  /** Large repositories (ADR-055): one threat packet per shard, by priority, instead of per endpoint file. */
  shards?: readonly Shard[];
}

const MAX_BASELINE_ENDPOINTS = 40;

export const RECON_ITEM = 'recon';
export const logicItemSlug = (group: string) =>
  `logic-${group
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .slice(0, 40)}`;

const IAC_FILE =
  /(^|\/)(Dockerfile(\.[^/]*)?|docker-compose[^/]*\.ya?ml|[^/]*\.tf|Chart\.yaml|values[^/]*\.ya?ml|k8s\/[^/]*\.ya?ml|kubernetes\/[^/]*\.ya?ml)$/;

export function isIacFile(path: string): boolean {
  return IAC_FILE.test(path);
}

/**
 * The conductor (ADR-044) seeds the work a case owes, deterministically and before any model runs:
 * one triage or applicability item per finding, a threat packet per group of endpoints, a secrets
 * sweep (worktree and history), an IaC review, a baseline audit and the report. These items are
 * mandatory: the lead can add work but never cancel them, so coverage cannot shrink.
 */
export function seedBoard(input: ConductorInput): { items: WorkItem[]; objectives: Objective[] } {
  const at = input.now.toISOString();
  const items: WorkItem[] = [];
  const item = (
    slug: string,
    kind: WorkItemKind,
    persona: string,
    title: string,
    extra: Partial<WorkItem> = {},
  ): WorkItem => {
    const w: WorkItem = {
      itemId: `${input.caseId}:${slug}`,
      caseId: input.caseId,
      kind,
      title,
      description: '',
      status: 'todo',
      mandatory: true,
      persona,
      handles: [],
      dependsOn: [],
      createdBy: 'host',
      round: 0,
      attempts: 0,
      createdAt: at,
      updatedAt: at,
      ...extra,
    };
    items.push(w);
    return w;
  };

  const recon = input.recon ?? false;
  const afterRecon = recon ? [`${input.caseId}:${RECON_ITEM}`] : [];
  if (recon) {
    item(
      RECON_ITEM,
      'RECON',
      'recon',
      'Reconnaissance: archetype, invariants, baselines, variant families, carve-outs',
      {
        description: [input.matrix ? renderCensus(input.matrix) : '', input.operatorContext ?? '']
          .filter(Boolean)
          .join('\n\n')
          .slice(0, 6000),
      },
    );
  }

  for (const h of input.handles) {
    if (h.packagePurl || h.category === 'VULNERABLE_DEPENDENCY') {
      item(
        `deps-${h.handle}`,
        'DEPENDENCY_APPLICABILITY',
        'dependency',
        `Does ${h.title} affect this project? (${h.handle})`,
        {
          handles: [h.handle],
        },
      );
    } else {
      item(
        `triage-${h.handle}`,
        'TRIAGE_FINDING',
        triagePersona(h),
        `Triage ${h.handle}: ${h.title} at ${h.path}:${h.startLine}`,
        {
          handles: [h.handle],
        },
      );
    }
  }

  let rest: EndpointRef[];
  if (input.shards?.length) {
    // Sharded board: packets follow the plan's priority; endpoints outside any packet go to the baseline audit.
    const limit = input.maxThreatPackets ?? input.shards.length;
    const covered = new Set<string>();
    [...input.shards]
      .sort((a, b) => a.priority - b.priority)
      .slice(0, limit)
      .forEach((shard, i) => {
        for (const f of shard.files) covered.add(f.path);
        const signals = shard.signals
          .slice(0, 20)
          .map((s) => `${s.path}:${s.line ?? '?'} [${s.selectorId}] ${s.evidence}`);
        item(`threat-${i + 1}`, 'THREAT_PACKET', 'appsec', `Threat-model shard ${shard.shardId}: ${shard.module}`, {
          description: [
            `Owned files:\n${shard.files.map((f) => `- ${f.path}`).join('\n')}`,
            shard.neighbors.length
              ? `Readable neighbours (context only):\n${shard.neighbors.map((n) => `- ${n}`).join('\n')}`
              : '',
            signals.length ? `Signals:\n${signals.join('\n')}` : '',
          ]
            .filter(Boolean)
            .join('\n\n'),
          dependsOn: afterRecon,
        });
      });
    rest = input.endpoints.filter((e) => !covered.has(e.path));
  } else {
    const groups = new Map<string, EndpointRef[]>();
    for (const e of input.endpoints) groups.set(e.path, [...(groups.get(e.path) ?? []), e]);
    const ranked = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
    const limit = input.maxThreatPackets ?? 6;
    ranked.slice(0, limit).forEach(([path, endpoints], i) => {
      item(`threat-${i + 1}`, 'THREAT_PACKET', 'appsec', `Threat-model the endpoints in ${path}`, {
        description: endpoints.map((e) => `${e.method} ${e.route} (${e.path}:${e.line}, id ${e.id})`).join('\n'),
        dependsOn: afterRecon,
      });
    });
    rest = ranked.slice(limit).flatMap(([, e]) => e);
  }

  // Logic audits (ADR-049): one per resource group where a sibling lacks a control its siblings have.
  if (recon && input.matrix) {
    const flagged = input.matrix.groups.filter((g) => g.flaggedCount > 0).slice(0, input.maxLogicItems ?? 8);
    for (const g of flagged) {
      item(
        logicItemSlug(g.group),
        'LOGIC_AUDIT',
        'logic',
        `Logic audit of ${g.group}: ${g.flaggedCount} operation(s) without a sibling's control`,
        {
          description: g.rows
            .map(
              (r) =>
                `${r.flagged ? '[!] ' : ''}${r.method} ${r.route} (${r.path}:${r.line}) authz=${r.controls.authz.join(',') || 'none'} scoped=${r.dataAccess.map((d) => d.scopedBy).join(',') || 'n/a'}`,
            )
            .join('\n'),
          dependsOn: afterRecon,
        },
      );
    }
  }

  item(
    'secrets-sweep',
    'SECRETS_SWEEP',
    'secrets',
    'Sweep for secrets the scanners missed, including git history results',
    {
      handles: input.handles.filter((h) => h.category === 'HARDCODED_SECRET').map((h) => h.handle),
    },
  );
  if (input.iacFiles.length) {
    item('iac-review', 'IAC_REVIEW', 'iac', 'Review container and deployment configuration', {
      description: input.iacFiles.slice(0, 50).join('\n'),
    });
  }
  item('baseline-audit', 'BASELINE_AUDIT', 'appsec', 'Independent baseline audit of the codebase', {
    description: rest.length
      ? `Endpoints not covered by a threat packet:\n${rest
          .slice(0, MAX_BASELINE_ENDPOINTS)
          .map((e) => `${e.method} ${e.route} (${e.path}:${e.line})`)
          .join(
            '\n',
          )}${rest.length > MAX_BASELINE_ENDPOINTS ? `\n(+${rest.length - MAX_BASELINE_ENDPOINTS} more; use list_endpoints)` : ''}`
      : '',
    dependsOn: afterRecon,
  });

  const objectives: Objective[] = [];
  const objective = (key: string, kind: Objective['kind'], title: string, criteria: Record<string, unknown> = {}) =>
    objectives.push({
      objectiveId: `${input.caseId}:${key}`,
      caseId: input.caseId,
      kind,
      title,
      criteria,
      status: 'OPEN',
    });
  input.objectives.forEach((text, i) => {
    const hyp = item(`objective-${i + 1}`, 'HYPOTHESIS', 'appsec', text.slice(0, 160), {
      description: `Operator objective: ${text}`,
      dependsOn: afterRecon,
    });
    objective(`custom-${i + 1}`, 'CUSTOM', text.slice(0, 200), { itemId: hyp.itemId });
  });
  item('report', 'REPORT', 'host', 'Assemble the case report', {
    dependsOn: items.filter((i) => i.mandatory).map((i) => i.itemId),
  });

  objective('mandatory', 'MANDATORY_DONE', 'Every mandatory work item is done');
  objective('triaged', 'ALL_TRIAGED', 'Every finding has a verdict');
  objective(
    'evidence',
    'CONFIRMED_HAVE_EVIDENCE',
    'Every confirmed finding is backed by evidence (and an attack path when HIGH+)',
  );
  if (input.handles.some((h) => h.packagePurl || h.category === 'VULNERABLE_DEPENDENCY')) {
    objective('dependencies', 'DEPENDENCIES_ASSESSED', 'Every vulnerable dependency has an applicability decision');
  }
  objective('coverage', 'COVERAGE_RECORDED', 'Every coverage check ran or says why not', {
    required: ['secrets-history'],
  });
  if (input.l3)
    objective('l3', 'L3_ATTEMPTED', 'Runtime-verifiable confirmed findings have a PoC outcome', {
      minSeverity: 'HIGH',
    });
  if (recon) {
    objective('invariants', 'INVARIANTS_CHECKED', 'Every ground-truth invariant has a PASS/FAIL/UNKNOWN result');
    objective('families', 'FAMILIES_SWEPT', 'Every variant-family member has a hunt-log verdict');
  }
  return { items, objectives };
}

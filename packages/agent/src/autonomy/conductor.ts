import type { CaseHandle, Objective, WorkItem, WorkItemKind } from '@spinxsca/schemas';

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
}

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

  const groups = new Map<string, EndpointRef[]>();
  for (const e of input.endpoints) groups.set(e.path, [...(groups.get(e.path) ?? []), e]);
  const ranked = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  const limit = input.maxThreatPackets ?? 6;
  ranked.slice(0, limit).forEach(([path, endpoints], i) => {
    item(`threat-${i + 1}`, 'THREAT_PACKET', 'appsec', `Threat-model the endpoints in ${path}`, {
      description: endpoints.map((e) => `${e.method} ${e.route} (${e.path}:${e.line}, id ${e.id})`).join('\n'),
    });
  });
  const rest = ranked.slice(limit).flatMap(([, e]) => e);

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
      ? `Endpoints not covered by a threat packet:\n${rest.map((e) => `${e.method} ${e.route} (${e.path}:${e.line})`).join('\n')}`
      : '',
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
  return { items, objectives };
}

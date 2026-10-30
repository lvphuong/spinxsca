import type {
  AskSubject,
  CodeGraphView,
  ExplainSubject,
  FindingExplainer,
  InvestigationSubject,
  Investigator,
  ProjectAssistant,
  Remediator,
  SourceTree,
} from '@spinxsca/core';

/**
 * Data policy for AI (`ai.data_policy`, docs/architecture/06 section 3.2): repository paths that must
 * never reach a model. Excluded files disappear from the snapshot the roles can read, their evidence
 * excerpts are withheld, and findings located in them are not sent at all.
 */
export interface DataPolicy {
  excludePaths: readonly string[];
}

export function compileDataPolicy(policy: DataPolicy): (path: string) => boolean {
  const patterns = policy.excludePaths.map(globToRegExp);
  return (path) => !patterns.some((re) => re.test(path));
}

/** `**` any depth, `*` within a segment, `?` one character; a bare directory also matches its contents. */
export function globToRegExp(pattern: string): RegExp {
  const p = pattern.replace(/^\.\//, '').replace(/\/+$/, '');
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i] as string;
    if (ch === '*' && p[i + 1] === '*') {
      re += '.*';
      i++;
      if (p[i + 1] === '/') i++;
    } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}(?:/.*)?$`);
}

export class DataPolicyError extends Error {
  constructor(path: string) {
    super(`${path} is excluded from AI by ai.data_policy; nothing was sent to the model`);
    this.name = 'DataPolicyError';
  }
}

function restrictSubject<T extends { snapshotPaths: readonly string[] }>(
  subject: T,
  allows: (p: string) => boolean,
): T {
  return { ...subject, snapshotPaths: subject.snapshotPaths.filter(allows) };
}

function restrictSource(source: SourceTree, allows: (p: string) => boolean): SourceTree {
  return {
    root: source.root,
    listFiles: async (o) => (await source.listFiles(o)).filter((f) => allows(f.path)),
    readText: async (p) => (allows(p) ? source.readText(p) : undefined),
    gitInfo: () => source.gitInfo(),
  };
}

function restrictGraph(graph: CodeGraphView, allows: (p: string) => boolean): CodeGraphView {
  const ok = (key: string) => {
    const s = graph.getSymbol(key);
    return !s || allows(s.path);
  };
  return {
    get symbolCount() {
      return graph.symbolCount;
    },
    getSymbol: (key) => {
      const s = graph.getSymbol(key);
      return s && allows(s.path) ? s : undefined;
    },
    symbolAt: (path, line) => (allows(path) ? graph.symbolAt(path, line) : undefined),
    search: (q) => graph.search(q).filter((s) => allows(s.path)),
    callers: (key) => graph.callers(key).filter((e) => ok(e.from) && allows(e.path)),
    callees: (key) => graph.callees(key).filter((e) => ok(e.to) && allows(e.path)),
    endpoints: (f) => graph.endpoints(f).filter((e) => allows(e.path)),
    authContext: (id) => {
      const ctx = graph.authContext(id);
      return ctx && allows(ctx.endpoint.path)
        ? {
            ...ctx,
            controls: ctx.controls.filter((c) => allows(c.path)),
            handlers: ctx.handlers.filter((h) => allows(h.path)),
          }
        : undefined;
    },
  };
}

function restrictExplainSubject(subject: ExplainSubject, allows: (p: string) => boolean): ExplainSubject {
  const primary = subject.occurrence.locations[0];
  if (primary && !allows(primary.path)) throw new DataPolicyError(primary.path);
  return {
    ...restrictSubject(subject, allows),
    evidence: subject.evidence.map((e) =>
      e.locations.some((l) => !allows(l.path)) ? { ...e, excerpt: '[withheld by data policy]' } : e,
    ),
    related: subject.related.filter((r) => !r.location || allows(r.location.split(':')[0] ?? '')),
  };
}

export function withDataPolicy(explainer: FindingExplainer, policy: DataPolicy): FindingExplainer;
export function withDataPolicy(explainer: Investigator, policy: DataPolicy): Investigator;
export function withDataPolicy(explainer: Remediator, policy: DataPolicy): Remediator;
export function withDataPolicy(explainer: ProjectAssistant, policy: DataPolicy): ProjectAssistant;
export function withDataPolicy(
  role: FindingExplainer | Investigator | Remediator | ProjectAssistant,
  policy: DataPolicy,
): FindingExplainer | Investigator | Remediator | ProjectAssistant {
  if (policy.excludePaths.length === 0) return role;
  const allows = compileDataPolicy(policy);
  if ('ask' in role) {
    return {
      info: role.info,
      ask: async (subject: AskSubject, source: SourceTree, signal?: AbortSignal) =>
        role.ask(
          {
            ...restrictSubject(subject, allows),
            findings: subject.findings.filter((f) => !f.location || allows(f.location.split(':')[0] ?? '')),
            ...(subject.focus ? { focus: restrictExplainSubject(subject.focus, allows) } : {}),
          },
          restrictSource(source, allows),
          signal,
        ),
    } satisfies ProjectAssistant;
  }
  if ('explain' in role) {
    return {
      info: role.info,
      explain: async (subject: ExplainSubject, source: SourceTree, signal?: AbortSignal) =>
        role.explain(restrictExplainSubject(subject, allows), restrictSource(source, allows), signal),
    } satisfies FindingExplainer;
  }
  if ('propose' in role) {
    return {
      info: role.info,
      propose: async (subject: ExplainSubject, source: SourceTree, signal?: AbortSignal) =>
        role.propose(restrictExplainSubject(subject, allows), restrictSource(source, allows), signal),
    } satisfies Remediator;
  }
  return {
    info: role.info,
    investigate: async (subject: InvestigationSubject, source: SourceTree, options) =>
      role.investigate(
        {
          ...restrictSubject(subject, allows),
          ...(subject.graph ? { graph: restrictGraph(subject.graph, allows) } : {}),
          scannerCandidates: subject.scannerCandidates.filter((c) => c.locations.every((l) => allows(l.path))),
        },
        restrictSource(source, allows),
        options,
      ),
  } satisfies Investigator;
}

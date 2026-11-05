import type { CodeGraphView, SourceTree } from '../ports';

/**
 * Deterministic census of data-access sites (ADR-049). It is sidecar evidence for the recon and
 * audit prompts and for the `data_access_sites` tool: a lower-bound, name-based list that never
 * becomes a finding. Scope detection is lexical ("does the statement mention the caller or tenant")
 * and says `unknown` whenever it cannot tell.
 */
export type DataAccessOrm =
  | 'prisma'
  | 'typeorm'
  | 'sequelize'
  | 'knex'
  | 'mongoose'
  | 'raw-sql'
  | 'sqlalchemy'
  | 'django'
  | 'jpa'
  | 'jdbc';

export type DataAccessOperation = 'read' | 'write' | 'delete' | 'unknown';
export type DataAccessScope = 'user' | 'tenant' | 'none' | 'unknown';

export interface DataAccessSite {
  path: string;
  line: number;
  /** Symbol containing the call (code-intel key). */
  callerKey: string;
  /** Callee as written, e.g. "prisma.order.findUnique". */
  callee: string;
  orm: DataAccessOrm;
  operation: DataAccessOperation;
  /** Whether the statement text scopes the query to the current user or tenant. */
  scopedBy: DataAccessScope;
  /** Tokens that decided `scopedBy`, for the reader to verify. */
  scopeTokens: string[];
}

interface Pattern {
  orm: DataAccessOrm;
  test: RegExp;
  operation: (name: string) => DataAccessOperation;
}

const READ =
  /^(find|findOne|findOneBy|findBy|findById|findByPk|findAll|findFirst|findUnique|findMany|get|filter|filter_by|all|query|select|execute|raw|createQueryBuilder|exists|count)$/;
const WRITE =
  /^(update|updateMany|updateOne|upsert|create|save|insert|findByIdAndUpdate|findOneAndUpdate|bulkCreate|increment|decrement|persist|merge)$/;
const DELETE = /^(delete|deleteMany|deleteOne|destroy|remove|findByIdAndDelete|findOneAndDelete|deleteById|deleteAll)$/;

const opOf = (name: string): DataAccessOperation =>
  DELETE.test(name) ? 'delete' : WRITE.test(name) ? 'write' : READ.test(name) ? 'read' : 'unknown';

const PATTERNS: readonly Pattern[] = [
  { orm: 'prisma', test: /(^|\.)prisma\.\w+\.\w+$/, operation: opOf },
  {
    orm: 'typeorm',
    test: /(repository|repo|Repository|manager|entityManager)\.(find\w*|update|delete|remove|save|insert|upsert|createQueryBuilder|count|exists)$/,
    operation: opOf,
  },
  {
    orm: 'sequelize',
    test: /\.(findByPk|findOne|findAll|findAndCountAll|bulkCreate|destroy|increment|decrement)$/,
    operation: opOf,
  },
  {
    orm: 'knex',
    test: /(^knex$|\.where$|\.whereIn$|\.first$|\.del$|\.insert$|\.update$)/,
    operation: (n) => (n === 'del' ? 'delete' : opOf(n)),
  },
  {
    orm: 'mongoose',
    // Mongoose models are capitalized (`Order.findById`); a lowercase receiver is usually a service method.
    test: /(^|\.)[A-Z]\w*\.(findById|findOne|findByIdAndUpdate|findOneAndUpdate|findByIdAndDelete|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany)$/,
    operation: opOf,
  },
  { orm: 'raw-sql', test: /\.(query|execute|raw|run|all|get)$/, operation: () => 'unknown' },
  {
    orm: 'sqlalchemy',
    test: /(session|db\.session|Session)\.(query|execute|get|add|delete|merge)$|\.filter(_by)?$/,
    operation: opOf,
  },
  {
    orm: 'django',
    test: /\.objects\.(get|filter|all|update|delete|create|get_or_create|update_or_create)$/,
    operation: opOf,
  },
  {
    orm: 'jpa',
    test: /(Repository|repository|repo)\.(findById|findAll|findBy\w*|save|saveAll|delete\w*|existsById|count)$|(^|\.)(em|entityManager)\.(find|createQuery|persist|merge|remove)$/,
    operation: opOf,
  },
  {
    orm: 'jdbc',
    test: /(jdbcTemplate|statement|stmt|preparedStatement|ps)\.(query\w*|execute\w*|update)$/,
    operation: () => 'unknown',
  },
];

const USER_SCOPE =
  /\b(req\.user|request\.user|current_user|currentUser|g\.user|ctx\.user|ctx\.state\.user|AuthenticationPrincipal|principal|user_?id|owner_?id|ownerId|userId|author_?id|created_?by|session\.user|getCurrentUser|@CurrentUser)\b/i;
const TENANT_SCOPE =
  /\b(tenant_?id|tenantId|org(anization)?_?id|orgId|organizationId|account_?id|accountId|workspace_?id|workspaceId|company_?id|companyId)\b/i;
const HAS_FILTER = /\b(where|filter|filter_by|findBy|findOne|findUnique|findFirst|WHERE)\b/;

/** Lines from `start` until the call's brackets balance (capped), as the statement text. */
export function statementText(lines: readonly string[], start: number, cap = 6): string {
  let depth = 0;
  let out = '';
  for (let i = start; i < Math.min(lines.length, start + cap); i++) {
    const line = lines[i] ?? '';
    out += `${line}\n`;
    for (const ch of line) {
      if (ch === '(' || ch === '{' || ch === '[') depth++;
      else if (ch === ')' || ch === '}' || ch === ']') depth--;
    }
    if (depth <= 0 && i > start) break;
    if (depth <= 0 && /[;)]\s*$/.test(line)) break;
  }
  return out;
}

export function classifyScope(statement: string): { scopedBy: DataAccessScope; tokens: string[] } {
  const tokens: string[] = [];
  const tenant = TENANT_SCOPE.exec(statement);
  const user = USER_SCOPE.exec(statement);
  if (tenant) tokens.push(tenant[0]);
  if (user) tokens.push(user[0]);
  if (tenant) return { scopedBy: 'tenant', tokens };
  if (user) return { scopedBy: 'user', tokens };
  if (HAS_FILTER.test(statement)) return { scopedBy: 'none', tokens };
  return { scopedBy: 'unknown', tokens };
}

export function matchDataAccess(callee: string): { orm: DataAccessOrm; operation: DataAccessOperation } | undefined {
  const name = callee.replace(/\(.*$/s, '').split('.').pop() ?? callee;
  for (const p of PATTERNS) {
    if (p.test.test(callee)) return { orm: p.orm, operation: p.operation(name) };
  }
  return undefined;
}

export async function extractDataAccessSites(
  graph: CodeGraphView,
  source: SourceTree,
  paths: readonly string[],
): Promise<DataAccessSite[]> {
  if (!graph.callSitesIn) return [];
  const sites: DataAccessSite[] = [];
  for (const path of paths) {
    const calls = graph.callSitesIn(path);
    if (!calls.length) continue;
    const matched = calls.flatMap((c) => {
      const m = matchDataAccess(c.callee);
      return m ? [{ call: c, ...m }] : [];
    });
    if (!matched.length) continue;
    const text = await source.readText(path);
    const lines = text?.split(/\r?\n/) ?? [];
    for (const { call, orm, operation } of matched) {
      const statement = statementText(lines, Math.max(0, call.line - 1));
      const scope = classifyScope(statement);
      sites.push({
        path,
        line: call.line,
        callerKey: call.callerKey,
        callee: call.callee,
        orm,
        operation,
        scopedBy: scope.scopedBy,
        scopeTokens: scope.tokens,
      });
    }
  }
  return sites.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
}

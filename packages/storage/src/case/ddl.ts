/**
 * Case store tables (ADR-044), shared by SQLite (applied as migration 0002_autonomy) and PostgreSQL
 * (created with the project schema). Rows keep the validated domain object in `data` plus lookup
 * columns; chained tables have UNIQUE(case_id, seq).
 */
export function caseTables(dialect: 'sqlite' | 'pg', prefix = ''): string[] {
  const json = dialect === 'pg' ? 'jsonb' : 'text';
  const t = (name: string) => `${prefix}${name}`;
  const ine = 'IF NOT EXISTS';
  return [
    `CREATE TABLE ${ine} ${t('review_cases')} (case_id text PRIMARY KEY NOT NULL, project_id text NOT NULL, scan_id text NOT NULL, status text NOT NULL, created_at text NOT NULL, data ${json} NOT NULL)`,
    `CREATE INDEX ${ine} idx_review_cases_project ON ${t('review_cases')} (project_id, created_at)`,
    `CREATE INDEX ${ine} idx_review_cases_scan ON ${t('review_cases')} (scan_id)`,
    `CREATE TABLE ${ine} ${t('case_objectives')} (objective_id text PRIMARY KEY NOT NULL, case_id text NOT NULL, data ${json} NOT NULL)`,
    `CREATE INDEX ${ine} idx_case_objectives_case ON ${t('case_objectives')} (case_id)`,
    `CREATE TABLE ${ine} ${t('work_items')} (item_id text PRIMARY KEY NOT NULL, case_id text NOT NULL, status text NOT NULL, updated_at text NOT NULL, data ${json} NOT NULL)`,
    `CREATE INDEX ${ine} idx_work_items_case ON ${t('work_items')} (case_id)`,
    `CREATE TABLE ${ine} ${t('case_journal')} (case_id text NOT NULL, seq integer NOT NULL, hash text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (case_id, seq))`,
    `CREATE TABLE ${ine} ${t('case_audit')} (case_id text NOT NULL, seq integer NOT NULL, hash text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (case_id, seq))`,
    `CREATE TABLE ${ine} ${t('agent_steps')} (agent_run_id text NOT NULL, idx integer NOT NULL, case_id text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (agent_run_id, idx))`,
    `CREATE TABLE ${ine} ${t('tool_calls')} (case_id text NOT NULL, tool_call_id text NOT NULL, agent_run_id text NOT NULL, status text NOT NULL, created_at text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (case_id, tool_call_id))`,
    `CREATE INDEX ${ine} idx_tool_calls_run ON ${t('tool_calls')} (agent_run_id)`,
    `CREATE TABLE ${ine} ${t('approvals')} (approval_id text PRIMARY KEY NOT NULL, project_id text NOT NULL, case_id text NOT NULL, tool_call_id text NOT NULL, status text NOT NULL, requested_at text NOT NULL, data ${json} NOT NULL, UNIQUE (case_id, tool_call_id))`,
    `CREATE INDEX ${ine} idx_approvals_status ON ${t('approvals')} (project_id, status)`,
    `CREATE TABLE ${ine} ${t('grants')} (grant_id text PRIMARY KEY NOT NULL, project_id text NOT NULL, case_id text, created_at text NOT NULL, data ${json} NOT NULL)`,
    `CREATE INDEX ${ine} idx_grants_project ON ${t('grants')} (project_id)`,
    `CREATE TABLE ${ine} ${t('case_ledger')} (case_id text PRIMARY KEY NOT NULL, data ${json} NOT NULL)`,
    `CREATE TABLE ${ine} ${t('case_checks')} (case_id text NOT NULL, check_id text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (case_id, check_id))`,
    `CREATE TABLE ${ine} ${t('case_verdicts')} (case_id text NOT NULL, handle text NOT NULL, at text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (case_id, handle, at))`,
    `CREATE TABLE ${ine} ${t('case_handles')} (case_id text NOT NULL, handle text NOT NULL, draft_ref text NOT NULL, data ${json} NOT NULL, PRIMARY KEY (case_id, handle), UNIQUE (case_id, draft_ref))`,
    `CREATE TABLE ${ine} ${t('memory_entries')} (memory_id text PRIMARY KEY NOT NULL, project_id text NOT NULL, kind text NOT NULL, status text NOT NULL, mem_key text NOT NULL, updated_at text NOT NULL, data ${json} NOT NULL)`,
    `CREATE INDEX ${ine} idx_memory_project ON ${t('memory_entries')} (project_id, kind, status)`,
  ];
}

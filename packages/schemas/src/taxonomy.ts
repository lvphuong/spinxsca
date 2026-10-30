import { z } from 'zod';

/**
 * Internal vulnerability category taxonomy. Scanner rules map onto these via rule metadata or CWE.
 * Keep in sync with docs/architecture/02-core-engine.md section 9.
 */
export const Category = z.enum([
  'SQL_INJECTION',
  'NOSQL_INJECTION',
  'COMMAND_INJECTION',
  'CODE_INJECTION',
  'XSS',
  'PATH_TRAVERSAL',
  'SSRF',
  'OPEN_REDIRECT',
  'XXE',
  'INSECURE_DESERIALIZATION',
  'MISSING_AUTHENTICATION',
  'MISSING_AUTHORIZATION',
  'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
  'TENANT_ISOLATION',
  'HARDCODED_SECRET',
  'WEAK_CRYPTO',
  'INSECURE_RANDOMNESS',
  'CSRF',
  'INSECURE_CONFIGURATION',
  'VULNERABLE_DEPENDENCY',
  'RACE_CONDITION',
  'BUSINESS_LOGIC',
  'PROTOTYPE_POLLUTION',
  'LOG_INJECTION',
  'SENSITIVE_DATA_EXPOSURE',
  'OTHER',
]);
export type Category = z.infer<typeof Category>;

/** Canonical "CWE-<n>" identifier. */
export const CweId = z.string().regex(/^CWE-\d+$/, 'expected CWE-<number>');
export type CweId = z.infer<typeof CweId>;

const CWE_TO_CATEGORY: Record<string, Category> = {
  'CWE-89': 'SQL_INJECTION',
  'CWE-564': 'SQL_INJECTION',
  'CWE-943': 'NOSQL_INJECTION',
  'CWE-77': 'COMMAND_INJECTION',
  'CWE-78': 'COMMAND_INJECTION',
  'CWE-94': 'CODE_INJECTION',
  'CWE-95': 'CODE_INJECTION',
  'CWE-79': 'XSS',
  'CWE-80': 'XSS',
  'CWE-22': 'PATH_TRAVERSAL',
  'CWE-23': 'PATH_TRAVERSAL',
  'CWE-918': 'SSRF',
  'CWE-601': 'OPEN_REDIRECT',
  'CWE-611': 'XXE',
  'CWE-502': 'INSECURE_DESERIALIZATION',
  'CWE-306': 'MISSING_AUTHENTICATION',
  'CWE-285': 'MISSING_AUTHORIZATION',
  'CWE-862': 'MISSING_AUTHORIZATION',
  'CWE-863': 'MISSING_AUTHORIZATION',
  'CWE-639': 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
  'CWE-259': 'HARDCODED_SECRET',
  'CWE-798': 'HARDCODED_SECRET',
  'CWE-327': 'WEAK_CRYPTO',
  'CWE-328': 'WEAK_CRYPTO',
  'CWE-330': 'INSECURE_RANDOMNESS',
  'CWE-338': 'INSECURE_RANDOMNESS',
  'CWE-352': 'CSRF',
  'CWE-16': 'INSECURE_CONFIGURATION',
  'CWE-1104': 'VULNERABLE_DEPENDENCY',
  'CWE-1395': 'VULNERABLE_DEPENDENCY',
  'CWE-362': 'RACE_CONDITION',
  'CWE-840': 'BUSINESS_LOGIC',
  'CWE-1321': 'PROTOTYPE_POLLUTION',
  'CWE-117': 'LOG_INJECTION',
  'CWE-200': 'SENSITIVE_DATA_EXPOSURE',
};

/** Normalize strings such as "CWE-89: Improper Neutralization..." or "cwe-89" to "CWE-89". */
export function normalizeCwe(raw: string): CweId | undefined {
  const match = /cwe[-_ ]?(\d+)/i.exec(raw);
  return match ? `CWE-${match[1]}` : undefined;
}

export function categoryFromCwes(cwes: readonly string[]): Category {
  for (const cwe of cwes) {
    const category = CWE_TO_CATEGORY[cwe];
    if (category) return category;
  }
  return 'OTHER';
}

const FAMILY: Partial<Record<Category, string>> = {
  SQL_INJECTION: 'sqli',
  NOSQL_INJECTION: 'nosqli',
  COMMAND_INJECTION: 'command-injection',
  CODE_INJECTION: 'code-injection',
  XSS: 'xss-html-sink',
  PATH_TRAVERSAL: 'path-traversal',
  SSRF: 'ssrf',
  OPEN_REDIRECT: 'open-redirect',
  XXE: 'xxe',
  INSECURE_DESERIALIZATION: 'deserialization',
  MISSING_AUTHENTICATION: 'missing-authn',
  MISSING_AUTHORIZATION: 'missing-authz',
  BROKEN_OBJECT_LEVEL_AUTHORIZATION: 'bola',
  TENANT_ISOLATION: 'tenant-isolation',
  HARDCODED_SECRET: 'hardcoded-secret',
  VULNERABLE_DEPENDENCY: 'vulnerable-dependency',
};

/** Rule family shared by scanner rules and AI findings of one category, so they reconcile together. */
export function familyOf(category: Category): string {
  return FAMILY[category] ?? category.toLowerCase().replace(/_/g, '-');
}

import { describe, expect, it } from 'vitest';
import {
  anchorFor,
  assignInstances,
  enclosingSymbol,
  normalizeCodeShape,
  semanticFingerprint,
} from '../src/fingerprint';

describe('normalizeCodeShape', () => {
  it('ignores whitespace, comments and literal values', () => {
    const a = normalizeCodeShape(`db.query("SELECT * FROM users WHERE name = '" + name + "'"); // lookup`, 'js');
    const b = normalizeCodeShape(`db.query( "SELECT id FROM users WHERE name = '"+name+"'" )`, 'js');
    expect(a).toBe(b);
  });

  it('distinguishes a different sink expression', () => {
    expect(normalizeCodeShape('db.query(sql)', 'js')).not.toBe(normalizeCodeShape('db.execute(sql)', 'js'));
  });

  it('keeps URLs intact when stripping line comments', () => {
    expect(normalizeCodeShape('fetch("http://x")', 'js')).toBe('fetch("")');
  });
});

describe('enclosingSymbol', () => {
  it('finds an express route handler', () => {
    const lines = ["router.get('/users', async (req, res) => {", '  const x = 1;', '  db.query(x);', '});'];
    expect(enclosingSymbol(lines, 3, 'js')).toBe('heuristic:route:GET /users');
  });

  it('finds function declarations and arrow bindings', () => {
    expect(enclosingSymbol(['function searchUsers(q) {', '  run(q);', '}'], 2, 'js')).toBe('heuristic:searchUsers');
    expect(enclosingSymbol(['const Profile = ({ user }) => {', '  return x;', '};'], 2, 'js')).toBe(
      'heuristic:Profile',
    );
  });

  it('finds class methods but not control flow', () => {
    const lines = [
      'class Svc {',
      '  async findOne(id: string): Promise<User> {',
      '    if (id) {',
      '      return q(id);',
    ];
    expect(enclosingSymbol(lines, 4, 'js')).toBe('heuristic:findOne');
  });

  it('uses indentation for python', () => {
    const lines = [
      'def outer():',
      '    pass',
      '',
      'def ping():',
      '    host = request.args.get("h")',
      '    os.system(host)',
    ];
    expect(enclosingSymbol(lines, 6, 'python')).toBe('heuristic:ping');
  });

  it('returns empty string at file level', () => {
    expect(enclosingSymbol(['const a = 1;', 'eval(a);'], 2, 'js')).toBe('');
  });
});

describe('semanticFingerprint', () => {
  const file = ['function search(q) {', '  db.query("SELECT " + q);', '}'].join('\n');
  const shifted = ['// new header', '// another line', '', file].join('\n');

  it('is stable when lines move', () => {
    const a = anchorFor({ path: 'a.js', startLine: 2, endLine: 2, fileText: file });
    const b = anchorFor({ path: 'a.js', startLine: 5, endLine: 5, fileText: shifted });
    expect(a).toEqual(b);
    const fp = (anchor: typeof a) =>
      semanticFingerprint({
        repositoryId: 'r',
        category: 'SQL_INJECTION',
        ruleFamily: 'sqli',
        anchor: { ...anchor, instance: 0 },
      });
    expect(fp(a)).toBe(fp(b));
    expect(fp(a)).toMatch(/^spx1:[0-9a-f]{32}$/);
  });

  it('changes with category, rule family or instance', () => {
    const anchor = { ...anchorFor({ path: 'a.js', startLine: 2, endLine: 2, fileText: file }), instance: 0 };
    const base = semanticFingerprint({ repositoryId: 'r', category: 'SQL_INJECTION', ruleFamily: 'sqli', anchor });
    expect(semanticFingerprint({ repositoryId: 'r', category: 'XSS', ruleFamily: 'sqli', anchor })).not.toBe(base);
    expect(
      semanticFingerprint({
        repositoryId: 'r',
        category: 'SQL_INJECTION',
        ruleFamily: 'sqli',
        anchor: { ...anchor, instance: 1 },
      }),
    ).not.toBe(base);
  });

  it('falls back to a line anchor without source text', () => {
    expect(anchorFor({ path: 'gone.js', startLine: 7, endLine: 7, fileText: undefined })).toEqual({
      path: 'gone.js',
      symbol: '',
      shape: 'line:7',
    });
  });
});

describe('assignInstances', () => {
  it('numbers identical keys by line order', () => {
    const items = [
      { key: 'k', line: 20 },
      { key: 'k', line: 5 },
      { key: 'other', line: 1 },
    ];
    const result = assignInstances(items);
    expect(result.get(items[1] as (typeof items)[number])).toBe(0);
    expect(result.get(items[0] as (typeof items)[number])).toBe(1);
    expect(result.get(items[2] as (typeof items)[number])).toBe(0);
  });
});

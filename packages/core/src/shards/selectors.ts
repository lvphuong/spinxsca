import type { ShardSignal } from '@spinxsca/schemas';
import { redactSecrets } from '../redact';

/**
 * Lexical security selectors (ADR-055), ported from Agent Code's security profile and restricted to
 * the languages spinxsca analyses. A selector marks a line as worth a reviewer's attention; it never
 * produces a finding. Weights rank files when shards are packed.
 */
export type SelectorLanguage = 'javascript' | 'typescript' | 'python' | 'java' | 'any';

export interface LexicalSelector {
  id: string;
  description: string;
  /** Languages the selector applies to; `any` matches every text file. */
  langs: readonly SelectorLanguage[];
  pattern: RegExp;
  weight: number;
}

export const SELECTOR_VERSION = 'selectors/v1';

/** Signals per selector per file beyond which the rest of the file adds nothing. */
export const MAX_SIGNALS_PER_SELECTOR = 100;

const JS: SelectorLanguage[] = ['javascript', 'typescript'];
const JSPY: SelectorLanguage[] = ['javascript', 'typescript', 'python'];
const ALL: SelectorLanguage[] = ['any'];

export const SECURITY_SELECTORS: readonly LexicalSelector[] = [
  {
    id: 'rce.py_dangerous_call',
    description: 'Python code/command execution sink',
    langs: ['python'],
    weight: 3,
    pattern:
      /\b(os\.system|os\.popen|subprocess\.(Popen|call|run|check_output|check_call)|eval|exec|__import__|compile)\s*\(/,
  },
  {
    id: 'rce.subprocess_shell_true',
    description: 'subprocess invoked with shell=True',
    langs: ['python'],
    weight: 3,
    pattern: /shell\s*=\s*True/,
  },
  {
    id: 'rce.node_exec',
    description: 'Node child_process exec sink',
    langs: JS,
    weight: 3,
    pattern:
      /child_process|\bexecSync\b|\bexecFile(Sync)?\s*\(|\bspawn(Sync)?\s*\(|\bexec\s*\(|\beval\s*\(|new Function\s*\(|vm\.runIn/,
  },
  {
    id: 'rce.java_exec',
    description: 'Java command execution sink',
    langs: ['java'],
    weight: 3,
    pattern: /(Runtime\.getRuntime\(\)\s*\.\s*exec|new\s+ProcessBuilder|ProcessBuilder\s*\()/,
  },
  {
    id: 'deser.python',
    description: 'Insecure Python deserialization sink',
    langs: ['python'],
    weight: 3,
    pattern: /(pickle\s*\.\s*loads?|marshal\s*\.\s*loads?|yaml\s*\.\s*load\s*\(|jsonpickle)/,
  },
  {
    id: 'deser.java',
    description: 'Unsafe JVM deserialization sink',
    langs: ['java'],
    weight: 3,
    pattern: /(ObjectInputStream|readObject\s*\(|readUnshared|XMLDecoder|enableDefaultTyping|new\s+Yaml\s*\()/,
  },
  {
    id: 'deser.js',
    description: 'Unsafe JavaScript deserialization',
    langs: JS,
    weight: 3,
    pattern: /\b(node-serialize|serialize-javascript|unserialize\s*\(|yaml\.load\s*\(|JSON\.parse\s*\(\s*req\.)/,
  },
  {
    id: 'xxe.parser',
    description: 'XML parser that may resolve external entities',
    langs: ALL,
    weight: 2,
    pattern:
      /(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SchemaFactory|TransformerFactory|XMLReader|libxml|etree\.parse|lxml\.etree|xml2js|fast-xml-parser)/,
  },
  {
    id: 'sqli.raw_query',
    description: 'Raw SQL execution with possible string building',
    langs: ALL,
    weight: 2,
    pattern:
      /\b(execute|executemany|executescript|query|raw|rawQuery|\$queryRaw|\$executeRaw|prepare|createQuery|createNativeQuery)\s*\(/,
  },
  {
    id: 'sqli.fstring',
    description: 'SQL keyword inside an interpolated or concatenated string',
    langs: ALL,
    weight: 2,
    pattern: /(select|insert into|update|delete from)\b[^;\n]*(\{|%s|\$\{|"\s*\+|'\s*\+|f")/i,
  },
  {
    id: 'ssrf.http_client',
    description: 'Outbound HTTP request (possible SSRF sink)',
    langs: JSPY,
    weight: 2,
    pattern:
      /(requests\.(get|post|put|delete|head|request)|urllib\.request\.urlopen|httpx\.|axios\.|\bfetch\s*\(|got\s*\(|http\.get\s*\(|https\.get\s*\()/,
  },
  {
    id: 'ssrf.jvm',
    description: 'JVM outbound HTTP request (possible SSRF sink)',
    langs: ['java'],
    weight: 2,
    pattern: /(HttpURLConnection|HttpClient|RestTemplate|WebClient|new\s+URL\s*\()/,
  },
  {
    id: 'path.open_concat',
    description: 'File access with a concatenated or interpolated path',
    langs: JSPY,
    weight: 2,
    pattern:
      /(open|readFile|readFileSync|sendFile|createReadStream|writeFile|writeFileSync|unlink|res\.download)\s*\([^)\n]*(\+|\{|\$\{|%s|os\.path\.join|path\.join|path\.resolve)/,
  },
  {
    id: 'path.jvm',
    description: 'JVM file access (possible path traversal)',
    langs: ['java'],
    weight: 2,
    pattern:
      /(new\s+File\s*\(|Paths\.get|Files\.(newInputStream|readAllBytes|copy|write)|FileInputStream|getResourceAsStream)/,
  },
  {
    id: 'path.archive_slip',
    description: 'Archive extraction (zip-slip surface)',
    langs: ALL,
    weight: 1,
    pattern: /(zipentry|getnextentry|tarentry|extractall|extract\s*\(|unzip|untar|adm-zip|tar\.x)/i,
  },
  {
    id: 'proto.pollution',
    description: 'Prototype-pollution sink',
    langs: JS,
    weight: 1,
    pattern:
      /(__proto__|constructor\s*\.\s*prototype|prototype\s*\[|deepmerge|mergeWith|lodash\.merge|_\.merge\s*\(|_\.set\s*\()/,
  },
  {
    id: 'redos.regex',
    description: 'Dynamically built regex (ReDoS surface)',
    langs: ['javascript', 'typescript', 'python', 'java'],
    weight: 1,
    pattern: /(new\s+RegExp\s*\(|re\.compile\s*\(|Pattern\.compile\s*\()/,
  },
  {
    id: 'ssti.render_string',
    description: 'Template rendered from a string (possible SSTI)',
    langs: JSPY,
    weight: 2,
    pattern:
      /(render_template_string\s*\(|Template\s*\(\s*[^'")\n]|\.compile\s*\(\s*req\.|ejs\.render\s*\(|handlebars\.compile\s*\(|nunjucks\.renderString)/,
  },
  {
    id: 'xss.unescaped_output',
    description: 'Unescaped value rendered into output',
    langs: ALL,
    weight: 2,
    pattern:
      /(<%=|\|\s*safe\b|\bMarkup\s*\(|\.html_safe\b|innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|res\.send\s*\(\s*[`'"][^`'"]*\$\{|v-html=)/,
  },
  {
    id: 'crypto.weak_hash',
    description: 'Weak hash primitive',
    langs: ALL,
    weight: 1,
    pattern: /\b(md5|sha1)\b\s*[(:'"]/i,
  },
  {
    id: 'crypto.insecure_random',
    description: 'Insecure randomness for a security value',
    langs: JSPY,
    weight: 1,
    pattern: /(Math\.random\s*\(\)|\brandom\.(random|randint|choice)\s*\().*(token|secret|password|nonce|otp|key)/i,
  },
  {
    id: 'secret.aws_key',
    description: 'AWS access key id literal',
    langs: ALL,
    weight: 2,
    pattern: /AKIA[0-9A-Z]{16}/,
  },
  {
    id: 'secret.private_key',
    description: 'Embedded private key',
    langs: ALL,
    weight: 2,
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
  },
  {
    id: 'secret.assignment',
    description: 'Credential-like literal assignment',
    langs: ALL,
    weight: 1,
    pattern: /(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'][^"'\n]{6,}["']/i,
  },
  {
    id: 'auth.boundary',
    description: 'Auth/permission boundary marker',
    langs: ALL,
    weight: 2,
    pattern:
      /(@(login_required|permission_required|requires_auth|authenticated|preauthorize|rolesallowed|secured|UseGuards|Roles))\b|\b(authorize|authenticate|has_?role|is_?admin|check_?permission|before_action|require_?auth|ensureAuthenticated|passport\.authenticate)\b/i,
  },
  {
    id: 'auth.jwt_verify',
    description: 'Token verification or decode',
    langs: ALL,
    weight: 2,
    pattern:
      /(jwt\.(verify|decode)\s*\(|jsonwebtoken|jose\.|verifyIdToken|algorithms\s*[:=]\s*\[|"none"\s*\]|decode\s*\([^)]*verify\s*[:=]\s*False)/i,
  },
  {
    id: 'authz.id_from_request',
    description: 'Object identifier read from the request',
    langs: ALL,
    weight: 2,
    pattern:
      /(req\.params\.\w*[iI]d|request\.args\.get\(\s*['"][^'"]*id|@Param\(\s*['"]\w*[iI]d|@PathVariable|request\.view_args|params\[['"]\w*[iI]d['"]\]|ctx\.params\.\w*[iI]d|event\.pathParameters)/,
  },
  {
    id: 'authz.mass_assignment',
    description: 'Whole request body written to a model',
    langs: ALL,
    weight: 2,
    pattern:
      /(\.(create|update|updateOne|findOneAndUpdate|insertOne|save)\s*\(\s*(req\.body|request\.json|request\.form|request\.data|\{\s*\.\.\.req\.body)|Object\.assign\s*\([^,]+,\s*req\.body|\.update\s*\(\s*\*\*request\.(json|form))/,
  },
  {
    id: 'redirect.open',
    description: 'Redirect to a request-controlled target',
    langs: ALL,
    weight: 1,
    pattern:
      /(res\.redirect\s*\(\s*(req\.|request\.)|redirect\s*\(\s*request\.(args|form|GET)|sendRedirect\s*\(\s*request\.getParameter|next\s*=\s*request\.)/,
  },
  {
    id: 'cors.wildcard',
    description: 'Permissive CORS or credentials leak',
    langs: ALL,
    weight: 1,
    pattern:
      /(Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*|origin\s*:\s*true|cors\(\s*\)|allow_origins\s*=\s*\[\s*['"]\*)/,
  },
  {
    id: 'upload.unrestricted',
    description: 'File upload handling',
    langs: ALL,
    weight: 1,
    pattern: /(multer\s*\(|MultipartFile|request\.files|FileStorage|formidable|busboy|@UploadedFile)/,
  },
];

export const EXTENSION_LANGUAGE: Readonly<Record<string, SelectorLanguage>> = {
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  py: 'python',
  java: 'java',
  kt: 'java',
  scala: 'java',
};

/** Text extensions worth scanning lexically even when no parser exists for them. */
const TEXT_EXTENSIONS = new Set([
  ...Object.keys(EXTENSION_LANGUAGE),
  'go',
  'rb',
  'php',
  'cs',
  'rs',
  'c',
  'cc',
  'cpp',
  'h',
  'hpp',
  'swift',
  'vue',
  'svelte',
  'html',
  'ejs',
  'hbs',
  'njk',
  'jinja',
  'jinja2',
  'j2',
  'erb',
  'tpl',
  'yaml',
  'yml',
  'json',
  'toml',
  'xml',
  'env',
  'ini',
  'cfg',
  'conf',
  'properties',
  'sql',
  'sh',
  'bash',
  'tf',
  'dockerfile',
]);

export function selectorLanguageOf(path: string): SelectorLanguage | undefined {
  const base = path.slice(path.lastIndexOf('/') + 1).toLowerCase();
  if (base === 'dockerfile' || base.startsWith('.env')) return 'any';
  const ext = base.slice(base.lastIndexOf('.') + 1);
  if (base.indexOf('.') < 0) return undefined;
  return EXTENSION_LANGUAGE[ext] ?? (TEXT_EXTENSIONS.has(ext) ? 'any' : undefined);
}

/** True for files whose content is not worth a lexical scan (binary, lock files, minified bundles). */
export function skipForSelectors(path: string, bytes: number): boolean {
  if (bytes > 1_048_576) return true;
  const base = path.slice(path.lastIndexOf('/') + 1).toLowerCase();
  if (/\.(min|bundle)\.(js|css)$/.test(base) || /-lock\.(json|yaml)$|^yarn\.lock$|^pnpm-lock\.yaml$/.test(base))
    return true;
  return path.split('/').some((seg) => seg.startsWith('.') && seg !== '.' && seg !== '..');
}

/** Lexical signals of one file; evidence is the trimmed, secret-redacted line. */
export function scanLexical(
  path: string,
  text: string,
  selectors: readonly LexicalSelector[] = SECURITY_SELECTORS,
): ShardSignal[] {
  const language = selectorLanguageOf(path);
  if (!language) return [];
  const applicable = selectors.filter((s) => s.langs.includes('any') || s.langs.includes(language));
  if (applicable.length === 0) return [];
  const out: ShardSignal[] = [];
  const counts = new Map<string, number>();
  const lines = text.split('\n');
  for (const [index, raw] of lines.entries()) {
    if (raw.length > 2_000) continue;
    for (const selector of applicable) {
      if ((counts.get(selector.id) ?? 0) >= MAX_SIGNALS_PER_SELECTOR) continue;
      if (!selector.pattern.test(raw)) continue;
      counts.set(selector.id, (counts.get(selector.id) ?? 0) + 1);
      out.push({
        path,
        line: index + 1,
        selectorId: `lex.${selector.id}`,
        weight: selector.weight,
        evidence: redactSecrets(raw.trim()).text.slice(0, 200),
      });
    }
  }
  return out;
}

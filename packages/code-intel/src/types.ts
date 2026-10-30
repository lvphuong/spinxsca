/**
 * Code intelligence model (docs/architecture/02 section 5). Symbol keys are stable identifiers of the
 * form "<path>::<qualified name>"; anonymous route handlers get "<path>::<METHOD /route>".
 */
export type Language = 'javascript' | 'typescript' | 'tsx' | 'python' | 'java';

export type SymbolKind = 'function' | 'method' | 'class' | 'handler' | 'module';

export interface SymbolRecord {
  key: string;
  path: string;
  name: string;
  qualifiedName: string;
  kind: SymbolKind;
  startLine: number;
  endLine: number;
  /** sha256 (hex, 16 chars) of the normalized body; changes when the implementation changes. */
  contentHash: string;
  /** Class that owns a method. */
  owner?: string;
  exported: boolean;
}

export interface ImportRecord {
  path: string;
  /** Module specifier as written ("./db", "express", "org.example.Foo"). */
  specifier: string;
  /** Imported names (default import is "default", namespace is "*"). */
  names: Array<{ imported: string; local: string }>;
  line: number;
}

export interface CallSite {
  path: string;
  line: number;
  /** Symbol that contains the call. */
  callerKey: string;
  /** Callee as written: "db.query", "helper", "this.service.find". */
  callee: string;
  /** Last segment of the callee. */
  name: string;
}

export type ControlKind = 'AUTHENTICATION' | 'AUTHORIZATION' | 'VALIDATION' | 'RATE_LIMIT' | 'OTHER';
export type ControlSource = 'global' | 'router' | 'inline' | 'decorator' | 'dependency' | 'annotation';

export interface ControlRef {
  /** Symbol key when resolved, otherwise the name as written. */
  ref: string;
  name: string;
  kind: ControlKind;
  source: ControlSource;
  path: string;
  line: number;
}

export interface Endpoint {
  id: string;
  path: string;
  line: number;
  method: string;
  route: string;
  framework: string;
  /** Handler symbol keys in execution order (middleware first, final handler last). */
  handlers: string[];
  controls: ControlRef[];
  /** Mount prefix is applied when a router is mounted with app.use('/prefix', router). */
  mountedAt?: string;
}

export interface GlobalControl {
  path: string;
  line: number;
  /** Owner object the middleware was registered on ("app", "router"). */
  owner: string;
  mountPath?: string;
  ref: string;
  name: string;
  kind: ControlKind;
}

export interface FileExtraction {
  path: string;
  language: Language;
  symbols: SymbolRecord[];
  imports: ImportRecord[];
  calls: CallSite[];
  endpoints: Endpoint[];
  globalControls: GlobalControl[];
  /** Routers mounted on another router/app: app.use('/api', usersRouter). */
  mounts: Array<{ line: number; prefix: string; target: string }>;
  /** Typed class fields (constructor injection): owner class key -> field -> type name. */
  fieldTypes?: Array<{ owner: string; field: string; type: string }>;
  /** Parse failed or file skipped; the file is still part of coverage. */
  error?: string;
}

export interface CallEdge {
  from: string;
  to: string;
  path: string;
  line: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface CodeIndexData {
  version: number;
  extractorVersion: string;
  files: FileExtraction[];
  edges: CallEdge[];
}

export const EXTRACTOR_VERSION = 'code-intel/v1';
export const INDEX_SCHEMA_VERSION = 1;

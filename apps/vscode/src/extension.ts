import { execFile } from 'node:child_process';
import { relative, resolve, sep } from 'node:path';
import * as vscode from 'vscode';
import { runCli } from './cli';
import {
  type CliFinding,
  type DiagnosticSpec,
  diagnosticsFromCli,
  diagnosticsFromServer,
  findingsAt,
  type Level,
  summary,
} from './model';
import { ServerClient } from './server-client';

const TOKEN_KEY = 'spinxsca.serverToken';
const LEVEL: Record<Level, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

interface Explanation {
  summary?: string;
  classification?: string;
  severity?: string;
  attackPath?: { attacker?: string; entryPoint?: string; source?: string; sink?: string };
  remediation?: { strategy?: string; steps?: string[] };
}
interface PatchResult {
  patchId: string;
  status: string;
  reason?: string;
  diff?: string;
  proposal?: { summary: string };
}

/**
 * spinxsca in the editor (docs/architecture/06 section 3.5): local mode drives the CLI on this
 * machine (scans run in its sandbox, state stays in .spinxsca); server mode shows the branch's
 * findings from a spinxsca server. Explain and fix always go through the CLI, which verifies patches.
 */
export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection('spinxsca');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'spinxsca.refresh';
  status.text = '$(shield) spinxsca';
  status.show();
  const output = vscode.window.createOutputChannel('spinxsca');
  let specs: DiagnosticSpec[] = [];
  context.subscriptions.push(diagnostics, status, output);

  const config = () => vscode.workspace.getConfiguration('spinxsca');
  const workspaceRoot = (): string | undefined => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const cli = () => config().get<string>('cliPath', 'spinxsca');

  const publish = (root: string, next: DiagnosticSpec[], target?: (id: string) => vscode.Uri) => {
    specs = next;
    diagnostics.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const s of next) {
      const range = new vscode.Range(
        s.startLine - 1,
        (s.startColumn ?? 1) - 1,
        s.endLine - 1,
        s.endColumn ? s.endColumn - 1 : Number.MAX_SAFE_INTEGER,
      );
      const d = new vscode.Diagnostic(range, s.message, LEVEL[s.level]);
      d.source = 'spinxsca';
      d.code = target ? { value: s.findingId, target: target(s.findingId) } : s.findingId;
      byFile.set(s.path, [...(byFile.get(s.path) ?? []), d]);
    }
    for (const [path, list] of byFile) diagnostics.set(vscode.Uri.file(resolve(root, path)), list);
    status.text = `$(shield) ${summary(next)}`;
  };

  const refresh = async (): Promise<void> => {
    const root = workspaceRoot();
    if (!root) return;
    const minSeverity = config().get<string>('minSeverity', 'low');
    if (config().get<string>('mode') === 'server') {
      const url = config().get<string>('server.url', '');
      const projectId = config().get<string>('server.projectId', '');
      const token = await context.secrets.get(TOKEN_KEY);
      if (!url || !projectId || !token) {
        status.text = '$(shield) spinxsca: configure server mode';
        return;
      }
      const branch = await currentBranch(root);
      const client = new ServerClient(url, token);
      try {
        const [rows, gate] = await Promise.all([client.findings(projectId, branch), client.gate(projectId, branch)]);
        publish(root, diagnosticsFromServer(rows, minSeverity), (id) =>
          vscode.Uri.parse(client.findingUrl(projectId, id)),
        );
        status.text += gate.passed ? ' · gate ✓' : ' · gate ✗';
        status.tooltip = gate.checks.map((c) => `${c.passed ? '✓' : '✗'} ${c.message}`).join('\n');
      } catch (err) {
        status.text = '$(shield) spinxsca: server error';
        output.appendLine(`server: ${(err as Error).message}`);
      }
      return;
    }
    const result = await runCli<CliFinding[]>(cli(), ['findings', 'list', root, '--json'], root);
    if (!result.ok) {
      status.text = /no completed scan/.test(result.error ?? '')
        ? '$(shield) spinxsca: not scanned'
        : '$(shield) spinxsca: error';
      if (result.error) output.appendLine(result.error);
      return;
    }
    publish(root, diagnosticsFromCli(result.data ?? [], minSeverity));
  };

  const scan = async (paths?: string[]): Promise<void> => {
    const root = workspaceRoot();
    if (!root) return;
    if (config().get<string>('mode') === 'server') {
      void vscode.window.showInformationMessage(
        'Server mode: scans run on the spinxsca server; showing its latest results.',
      );
      return refresh();
    }
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: paths ? `spinxsca: scanning ${paths[0]}` : 'spinxsca: scanning workspace',
        cancellable: true,
      },
      async (_progress, token) => {
        const abort = new AbortController();
        token.onCancellationRequested(() => abort.abort());
        const args = ['scan', root, '--json', ...(paths ?? []).flatMap((p) => ['--paths', p])];
        const result = await runCli(cli(), args, root, { signal: abort.signal });
        if (!result.ok && !abort.signal.aborted)
          void vscode.window.showErrorMessage(`spinxsca scan failed: ${result.error}`);
      },
    );
    await refresh();
  };

  const pickFinding = async (id?: string): Promise<string | undefined> => {
    if (id) return id;
    const items = specs.map((s) => ({
      label: s.findingId,
      description: `${s.severity} · ${s.path}:${s.startLine}`,
      detail: s.message,
    }));
    return (await vscode.window.showQuickPick(items, { placeHolder: 'Finding' }))?.label;
  };

  const showMarkdown = async (content: string, language = 'markdown') => {
    const doc = await vscode.workspace.openTextDocument({ content, language });
    await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
  };

  context.subscriptions.push(
    vscode.commands.registerCommand('spinxsca.refresh', refresh),
    vscode.commands.registerCommand('spinxsca.scanWorkspace', () => scan()),
    vscode.commands.registerCommand('spinxsca.scanFile', (uri?: vscode.Uri) => {
      const root = workspaceRoot();
      const file = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!root || !file) return;
      const rel = relative(root, file.fsPath).split(sep).join('/');
      if (rel.startsWith('..')) return;
      return scan([rel]);
    }),
    vscode.commands.registerCommand('spinxsca.explainFinding', async (id?: string) => {
      const root = workspaceRoot();
      const findingId = await pickFinding(id);
      if (!root || !findingId) return;
      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `spinxsca: explaining ${findingId}` },
        () =>
          runCli<{ explanation?: Explanation; run?: { status: string; error?: string } }>(
            cli(),
            ['explain', findingId, root, '--json'],
            root,
          ),
      );
      if (!result.ok || !result.data?.explanation) {
        void vscode.window.showErrorMessage(
          `spinxsca explain: ${result.error ?? result.data?.run?.error ?? result.data?.run?.status ?? 'no explanation'}`,
        );
        return;
      }
      const e = result.data.explanation;
      const path = [e.attackPath?.attacker, e.attackPath?.entryPoint, e.attackPath?.source, e.attackPath?.sink]
        .filter(Boolean)
        .join(' → ');
      await showMarkdown(
        [
          `# ${findingId}`,
          '',
          `**${e.classification ?? ''} · ${e.severity ?? ''}**`,
          '',
          e.summary ?? '',
          '',
          path ? `**Attack path:** ${path}` : '',
          '',
          '## Fix',
          '',
          e.remediation?.strategy ?? '',
          ...(e.remediation?.steps ?? []).map((s) => `- ${s}`),
        ].join('\n'),
      );
    }),
    vscode.commands.registerCommand('spinxsca.fixFinding', async (id?: string) => {
      const root = workspaceRoot();
      const findingId = await pickFinding(id);
      if (!root || !findingId) return;
      const result = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `spinxsca: proposing and verifying a fix for ${findingId}`,
        },
        () => runCli<PatchResult>(cli(), ['fix', findingId, root, '--json'], root),
      );
      const patch = result.data;
      if (!patch) {
        void vscode.window.showErrorMessage(`spinxsca fix: ${result.error}`);
        return;
      }
      if (patch.diff) await showMarkdown(patch.diff, 'diff');
      if (patch.status !== 'verified' && patch.status !== 'rescan_passed') {
        void vscode.window.showWarningMessage(`spinxsca fix ${patch.status}: ${patch.reason ?? ''}`);
        return;
      }
      const choice = await vscode.window.showInformationMessage(
        `${patch.status === 'verified' ? 'Verified' : 'Re-scan passed (tests not run)'}: ${patch.reason ?? ''}`,
        'Apply',
        'Discard',
      );
      if (choice !== 'Apply') return;
      const applied = await runCli(cli(), ['fix', findingId, root, '--apply', '--patch', patch.patchId], root);
      if (!applied.ok) void vscode.window.showErrorMessage(`spinxsca: apply failed: ${applied.error}`);
      await refresh();
    }),
    vscode.commands.registerCommand('spinxsca.setServerToken', async () => {
      const token = await vscode.window.showInputBox({
        prompt: 'spinxsca server API token (viewer role is enough)',
        password: true,
        ignoreFocusOut: true,
      });
      if (token) {
        await context.secrets.store(TOKEN_KEY, token.trim());
        await refresh();
      }
    }),
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      {
        provideCodeActions(document, range) {
          const root = workspaceRoot();
          if (!root) return [];
          const rel = relative(root, document.uri.fsPath).split(sep).join('/');
          return findingsAt(specs, rel, range.start.line + 1).flatMap((s) => {
            const explain = new vscode.CodeAction(`spinxsca: explain ${s.findingId}`, vscode.CodeActionKind.QuickFix);
            explain.command = { command: 'spinxsca.explainFinding', title: 'Explain', arguments: [s.findingId] };
            const fix = new vscode.CodeAction(
              `spinxsca: propose a verified fix for ${s.findingId}`,
              vscode.CodeActionKind.QuickFix,
            );
            fix.command = { command: 'spinxsca.fixFinding', title: 'Fix', arguments: [s.findingId] };
            return config().get<string>('mode') === 'server' ? [] : [explain, fix];
          });
        },
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (config().get<boolean>('scanOnSave') && config().get<string>('mode') !== 'server')
        void vscode.commands.executeCommand('spinxsca.scanFile', doc.uri);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('spinxsca')) void refresh();
    }),
  );
  void refresh();
}

export function deactivate(): void {}

function currentBranch(root: string): Promise<string> {
  return new Promise((resolveBranch) => {
    execFile('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: root }, (err, stdout) =>
      resolveBranch(err ? 'main' : stdout.trim()),
    );
  });
}

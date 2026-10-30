import { ENGINE_VERSION } from '@spinxsca/core';
import { Command, Option } from 'commander';
import pc from 'picocolors';
import { evalCommand } from './commands/eval';
import { askCommand, explainCommand } from './commands/explain';
import { exportCommand, sbomCommand } from './commands/export';
import { findingsDisposeCommand, findingsListCommand, findingsShowCommand } from './commands/findings';
import { fixCommand, verifyFixCommand } from './commands/fix';
import { branchesCommand, gateCommand } from './commands/gate';
import { infoCommand } from './commands/info';
import { initCommand } from './commands/init';
import {
  kbBundleExportCommand,
  kbBundleImportCommand,
  kbBundleKeygenCommand,
  kbExportCommand,
  kbImportCommand,
  kbLookupCommand,
  kbSnapshotsCommand,
  kbStatusCommand,
  kbSyncCommand,
} from './commands/kb';
import { baselineListCommand, baselineSetCommand, compareCommand } from './commands/lifecycle';
import { scanCommand } from './commands/scan';
import { createToken, serveCommand, serverInitCommand } from './commands/serve';
import { temporalWorkerCommand } from './commands/temporal';
import { provisionWorkerCommand, workerRegisterCommand, workerRunCommand } from './commands/worker';
import { CliError, EXIT } from './ui';

const collect = (value: string, previous: string[] = []) => [...previous, value];

function run(action: (...args: never[]) => Promise<number>) {
  return async (...args: unknown[]) => {
    try {
      process.exitCode = await (action as (...a: unknown[]) => Promise<number>)(...args);
    } catch (err) {
      if (err instanceof CliError) {
        process.stderr.write(`${pc.red('error')} ${err.message}\n`);
        process.exitCode = err.exitCode;
      } else {
        process.stderr.write(`${pc.red('error')} ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
        process.exitCode = EXIT.ERROR;
      }
    }
  };
}

/** Options shared by commands that open a project state directory. */
function stateOptions(command: Command): Command {
  return command
    .option('-c, --config <file>', 'configuration file (default: ./spinxsca.yaml if present)')
    .option('--state-dir <dir>', 'state directory (default: <path>/.spinxsca)')
    .option('--kb-dir <dir>', 'knowledge base directory (default: ~/.spinxsca/kb)')
    .option('--json', 'machine-readable output')
    .option('-v, --verbose', 'verbose logging');
}

function aiFlags(command: Command): Command {
  return command
    .addOption(
      new Option('--ai-provider <provider>', 'AI provider').choices(['anthropic', 'openai-compatible', 'scripted']),
    )
    .option('--model <id>', 'model id (default claude-opus-5-5)')
    .option('--max-cost <usd>', 'cost budget in USD');
}

const program = new Command()
  .name('spinxsca')
  .description('Spinx SecureCode AI: evidence-driven security code analysis')
  .version(ENGINE_VERSION)
  .showHelpAfterError();

program
  .command('init')
  .description('create spinxsca.yaml in the current directory and check the sandbox')
  .option('--force', 'overwrite an existing spinxsca.yaml')
  .action(run(initCommand));

aiFlags(
  stateOptions(
    program
      .command('scan')
      .description('scan a directory, reconcile findings with the baseline and write reports')
      .argument('[path]', 'directory to scan', '.'),
  ),
)
  .addOption(
    new Option('--mode <mode>', 'scan mode (default: full; incremental with --diff; targeted with --paths)').choices([
      'full',
      'incremental',
      'targeted',
      'dependency-reassessment',
    ]),
  )
  .option('--diff <ref>', 'incremental scan: analyse the change impact since this git ref (e.g. origin/main)')
  .option('--paths <path>', 'targeted scan: file or directory to analyse (repeatable)', collect)
  .option('--scanners <list>', 'only these scanners: semgrep,osv-scanner,gitleaks,trivy')
  .option('--kb-snapshot <id>', 'pin a knowledge base snapshot (default: latest)')
  .option(
    '--baseline <scanId|branch:NAME|none>',
    'baseline for reconciliation (default: branch baseline, else latest scan)',
  )
  .option('--exclude <glob>', 'exclude paths (repeatable)', collect)
  .option('--format <list>', 'report formats: sarif,md,json')
  .option('--out <dir>', 'report directory (default: <state-dir>/reports/<scanId>)')
  .option('--fail-on <severity>', 'exit 1 when a finding at or above this severity is present')
  .option('--all-findings', 'apply --fail-on to existing findings too, not only new ones')
  .option('--require-complete-coverage', 'exit 3 when scanner coverage is partial')
  .addOption(
    new Option(
      '--ai <level>',
      'AI: explain validates new findings; standard also plans, investigates and audits',
    ).choices(['off', 'explain', 'standard']),
  )
  .option('--max-ai-findings <n>', 'explain at most this many new findings')
  .option('--resume <scanId>', 'resume an interrupted scan')
  .option('--no-cache', 'do not reuse scanner output from earlier scans with identical inputs')
  .action(run(scanCommand));

const findings = program.command('findings').description('inspect and triage findings');
stateOptions(
  findings
    .command('list')
    .description('list findings of the latest (or given) scan')
    .argument('[path]', 'scanned directory', '.'),
)
  .option('--scan <scanId>', 'scan to list')
  .addOption(
    new Option('--state <state>', 'filter').choices([
      'new',
      'existing',
      'reopened',
      'resolved',
      'not-reevaluated',
      'needs-reconciliation',
      'suppressed',
    ]),
  )
  .action(run(findingsListCommand));
stateOptions(
  findings
    .command('show')
    .description('show a finding with evidence, history and AI explanation')
    .argument('<findingId>', 'finding id, e.g. SPX-000001')
    .argument('[path]', 'scanned directory', '.'),
).action(run(findingsShowCommand));
stateOptions(
  findings
    .command('dispose')
    .description('record a human decision: false positive, accepted risk, won’t fix or duplicate')
    .argument('<findingId>', 'finding id')
    .argument('[path]', 'scanned directory', '.'),
)
  .addOption(
    new Option('--as <kind>', 'disposition')
      .choices(['false-positive', 'accepted-risk', 'wont-fix', 'duplicate'])
      .makeOptionMandatory(),
  )
  .requiredOption('--reason <text>', 'why')
  .option('--expires <30d|ISO date>', 'expiry (required for accepted risk)')
  .option('--duplicate-of <findingId>', 'canonical finding for duplicates')
  .option('--by <name>', 'who decided (default: current OS user)')
  .action(run(findingsDisposeCommand));

stateOptions(
  program
    .command('compare')
    .description('compare two scans and explain why findings appeared or disappeared')
    .argument('<fromScan>', 'earlier scan id')
    .argument('<toScan>', 'later scan id')
    .argument('[path]', 'scanned directory', '.'),
).action(run(compareCommand));

stateOptions(
  program
    .command('gate')
    .description(
      'release security gate: latest scan of a branch must be recent, complete, and free of blocking findings',
    )
    .argument('[path]', 'scanned directory', '.'),
)
  .option('--branch <name>', 'branch to evaluate (default: current git branch)')
  .option('--max-scan-age <duration>', 'override gate.max_scan_age_hours, e.g. 72h or 3d')
  .addOption(
    new Option('--fail-on <severity>', 'override gate.fail_on_severity').choices([
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ]),
  )
  .action(run(gateCommand));
stateOptions(
  program
    .command('branches')
    .description('finding status per branch (open / fixed / not re-evaluated)')
    .argument('[path]', 'scanned directory', '.'),
).action(run(branchesCommand));
stateOptions(
  program.command('status').description('alias of `branches`').argument('[path]', 'scanned directory', '.'),
).action(run(branchesCommand));

const baseline = program.command('baseline').description('manage branch baselines');
stateOptions(
  baseline
    .command('set')
    .description('promote a completed scan to the baseline of a branch')
    .argument('[path]', 'scanned directory', '.'),
)
  .requiredOption('--branch <name>', 'branch')
  .option('--scan <scanId>', 'scan to promote (default: latest completed)')
  .requiredOption('--reason <text>', 'why this baseline is accepted')
  .action(run(baselineSetCommand));
stateOptions(
  baseline.command('list').description('list baselines').argument('[path]', 'scanned directory', '.'),
).action(run(baselineListCommand));

stateOptions(program.command('export').description('export a scan').argument('[path]', 'scanned directory', '.'))
  .addOption(
    new Option('--format <format>', 'format')
      .choices(['sarif', 'json', 'md', 'csv', 'cyclonedx', 'pr-comment'])
      .makeOptionMandatory(),
  )
  .option('--scan <scanId>', 'scan (default: latest)')
  .option('--out <file>', 'write to a file instead of stdout')
  .action(run(exportCommand));
stateOptions(
  program
    .command('sbom')
    .description('CycloneDX SBOM of the dependency inventory')
    .argument('[path]', 'scanned directory', '.'),
)
  .option('--scan <scanId>', 'scan (default: latest)')
  .option('--out <file>', 'write to a file instead of stdout')
  .action(run(sbomCommand));

aiFlags(
  stateOptions(
    program
      .command('explain')
      .description('AI validation and explanation of one finding (sends redacted code excerpts to the provider)')
      .argument('<findingId>', 'finding id')
      .argument('[path]', 'scanned directory', '.'),
  ),
).action(run(explainCommand));
aiFlags(
  stateOptions(
    program
      .command('ask')
      .description('ask a security question about the scanned code (sends redacted code excerpts to the provider)')
      .argument('<question>', 'question')
      .argument('[path]', 'scanned directory', '.'),
  ),
)
  .option('--finding <findingId>', 'focus on a finding')
  .action(run(askCommand));

aiFlags(
  stateOptions(
    program
      .command('fix')
      .description(
        'AI-proposed patch for a finding, applied to a copy and verified by re-scan and project tests; never auto-applied',
      )
      .argument('<findingId>', 'finding id')
      .argument('[path]', 'scanned directory', '.'),
  ),
)
  .option('--apply', 'write a verified patch to the working tree (with --patch <id>, apply an earlier result)')
  .option('--patch <patchId>', 'patch id from an earlier `fix` run')
  .action(run(fixCommand));
stateOptions(
  program
    .command('verify-fix')
    .description('read-only targeted re-scan of a finding’s file: fixed, still vulnerable or inconclusive')
    .argument('<findingId>', 'finding id')
    .argument('[path]', 'scanned directory', '.'),
).action(run(verifyFixCommand));

program
  .command('serve')
  .description('run the spinxsca service: REST API, web UI, webhooks, job worker and scheduled knowledge base refresh')
  .requiredOption('--data-dir <dir>', 'server data directory (registry, project state, checkouts)')
  .option('-c, --config <file>', 'configuration applied to every project scan and the release gate')
  .option('--kb-dir <dir>', 'knowledge base directory (default: <data-dir>/kb)')
  .option('--host <host>', 'listen address', '127.0.0.1')
  .option('--port <port>', 'listen port', '8080')
  .option('--kb-sync-interval <minutes>', 'minutes between knowledge base refreshes (0 disables)', '30')
  .option(
    '--notify-url <url>',
    'POST new-finding events to this URL (repeatable; signed with SPINXSCA_NOTIFY_SECRET)',
    collect,
  )
  .option('--public-url <url>', 'external base URL, used in notification links')
  .option('--secure-cookies', 'mark the web session cookie Secure (behind HTTPS)')
  .option('--no-worker', 'do not run scan jobs here (remote workers only); knowledge base refreshes still run')
  .option('--pool <name>', 'worker pools served in-process (repeatable; default: default)', collect)
  .addOption(
    new Option('--orchestrator <name>', 'job orchestration: internal queue or Temporal workflows')
      .choices(['internal', 'temporal'])
      .default('internal'),
  )
  .option('--temporal-address <host:port>', 'Temporal frontend', 'localhost:7233')
  .option('--temporal-namespace <name>', 'Temporal namespace', 'default')
  .option('--temporal-task-queue <name>', 'Temporal task queue', 'spinxsca-jobs')
  .option('-v, --verbose', 'verbose logging')
  .action(run(serveCommand));
const server = program.command('server').description('service administration');
server
  .command('init')
  .description('create an admin API token (printed once)')
  .requiredOption('--data-dir <dir>', 'server data directory')
  .option('--name <name>', 'token name', 'admin')
  .action(run(serverInitCommand));
server
  .command('token')
  .description('create an API token (printed once)')
  .requiredOption('--data-dir <dir>', 'server data directory')
  .requiredOption('--name <name>', 'token name')
  .addOption(new Option('--role <role>', 'role').choices(['admin', 'member', 'viewer']).default('member'))
  .action(run(createToken));

server
  .command('provision-worker')
  .description('single-use provisioning token for a remote worker (printed once)')
  .requiredOption('--data-dir <dir>', 'server data directory')
  .option('--pool <name>', 'worker pool the worker serves (repeatable; default: default)', collect)
  .option('--ttl <minutes>', 'token lifetime', '60')
  .option('--uses <n>', 'registrations allowed with this token (e.g. worker replicas)', '1')
  .action(run(provisionWorkerCommand));

program
  .command('temporal-worker')
  .description('run job activities for Temporal against a server data directory')
  .requiredOption('--data-dir <dir>', 'server data directory (shared with `spinxsca serve`)')
  .option('-c, --config <file>', 'scanner configuration')
  .option('--kb-dir <dir>', 'knowledge base directory (default: <data-dir>/kb)')
  .option('--temporal-address <host:port>', 'Temporal frontend', 'localhost:7233')
  .option('--temporal-namespace <name>', 'Temporal namespace', 'default')
  .option('--temporal-task-queue <name>', 'Temporal task queue', 'spinxsca-jobs')
  .option('--concurrency <n>', 'concurrent jobs', '1')
  .option('-v, --verbose', 'verbose logging')
  .action(run(temporalWorkerCommand));

const worker = program
  .command('worker')
  .description('remote scan worker: runs jobs next to the source, reports to a spinxsca server');
worker
  .command('register')
  .description('register this host with a server using a provisioning token')
  .requiredOption('--server <url>', 'server base URL')
  .requiredOption(
    '--provisioning-token <token>',
    'token from `spinxsca server provision-worker` or POST /v1/workers/provision',
  )
  .requiredOption('--data-dir <dir>', 'worker data directory (credential, checkouts, knowledge base replica)')
  .option('--name <name>', 'worker name (default: host name)')
  .action(run(workerRegisterCommand));
worker
  .command('run')
  .description('poll the server and run leased scan jobs')
  .requiredOption('--data-dir <dir>', 'worker data directory')
  .option('-c, --config <file>', 'scanner configuration for jobs run here')
  .option('--poll <seconds>', 'poll interval when idle', '5')
  .option('--once', 'run at most one job and exit (ephemeral workers)')
  .option('-v, --verbose', 'verbose logging')
  .action(run(workerRunCommand));

const kb = program.command('kb').description('vulnerability knowledge base');
const kbOptions = (c: Command) =>
  c
    .option('-c, --config <file>', 'configuration file')
    .option('--kb-dir <dir>', 'knowledge base directory')
    .option('--json', 'JSON output');
kbOptions(
  kb
    .command('sync')
    .description(
      'mirror ecosystems (--ecosystem), sync the packages of a project (path), add KEV/EPSS/NVD (--intel), or refresh existing sources',
    )
    .argument('[path]', 'project whose dependencies to sync via the OSV API'),
)
  .option('--ecosystem <name>', 'mirror an OSV ecosystem, e.g. npm, PyPI, Maven, Go (repeatable)', collect)
  .option(
    '--intel <sources>',
    'exploitation intelligence: kev, epss, nvd (comma-separated or repeatable; NVD_API_KEY raises NVD rate limits)',
    collect,
  )
  .action(run(kbSyncCommand));
const bundle = kb.command('bundle').description('signed offline bundles for air-gapped / on-prem knowledge bases');
bundle
  .command('keygen')
  .description('create an Ed25519 signing key pair')
  .requiredOption('--out <dir>', 'directory for kb-signing.key (mode 600) and kb-signing.pub')
  .action(run(kbBundleKeygenCommand));
kbOptions(
  bundle
    .command('export')
    .description('export a snapshot (default: latest) as a signed bundle')
    .requiredOption('--out <file>', 'bundle file')
    .requiredOption('--sign-key <file>', 'private key (PEM)')
    .option('--snapshot <id>', 'snapshot to export'),
).action(run(kbBundleExportCommand));
kbOptions(
  bundle
    .command('import')
    .description('verify and import a signed bundle; the result must reproduce the bundle snapshot exactly')
    .argument('<file>', 'bundle file')
    .requiredOption('--trust-key <file>', 'trusted public key (PEM, repeatable)', collect),
).action(run(kbBundleImportCommand));
kbOptions(kb.command('status').description('knowledge base sources and latest snapshot')).action(run(kbStatusCommand));
kbOptions(kb.command('snapshots').description('list snapshots')).action(run(kbSnapshotsCommand));
kbOptions(
  kb.command('lookup').description('show an advisory by id or alias').argument('<id>', 'GHSA, CVE, PYSEC, OSV id'),
)
  .option('--snapshot <id>', 'as of this snapshot')
  .action(run(kbLookupCommand));
kbOptions(
  kb
    .command('import')
    .description('import OSV JSON files or directories')
    .argument('<paths...>', 'files or directories'),
)
  .option('--authoritative-for <ecosystems>', 'declare the import complete for these ecosystems (comma separated)')
  .option('--name <name>', 'source name')
  .action(run(kbImportCommand));
kbOptions(
  kb.command('export').description('export a snapshot as native OSV files').argument('<outDir>', 'output directory'),
)
  .option('--snapshot <id>', 'snapshot (default: latest)')
  .option('--ecosystem <name>', 'only this ecosystem (repeatable)', collect)
  .action(run(kbExportCommand));

program
  .command('info')
  .description('show versions, pinned images, rule and prompt digests, knowledge base and sandbox preflight')
  .option('-c, --config <file>', 'configuration file')
  .option('--kb-dir <dir>', 'knowledge base directory')
  .option('--json', 'JSON output')
  .action(run(infoCommand));

program
  .command('eval')
  .description('run the evaluation suite and check acceptance thresholds')
  .option('--suite <name>', 'suite under evals/', 'internal')
  .option('--cases-dir <dir>', 'explicit suite directory')
  .option('--case <id>', 'run only this case (repeatable)', collect)
  .option('--out <dir>', 'results directory (default: evals/results/<timestamp>)')
  .option('--no-stability', 'skip identity stability re-scans')
  .addOption(
    new Option('--ai <level>', 'run AI explain on new findings during evaluation')
      .choices(['off', 'explain'])
      .default('off'),
  )
  .addOption(
    new Option('--ai-provider <provider>', 'AI provider for --ai explain')
      .choices(['anthropic', 'scripted'])
      .default('scripted'),
  )
  .option('--json', 'JSON output')
  .option('-v, --verbose', 'verbose logging')
  .action(run(evalCommand));

await program.parseAsync(process.argv);

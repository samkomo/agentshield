/**
 * agentshield — command line for the local gateway.
 *
 *   service       run the gateway in the background (launchd / systemd user service)
 *   connect       find an agent runtime, install into it and test it (currently: hermes)
 *   enroll        the gateway's half of connect, for an agent in another account
 *   disconnect    take AgentShield back out of an agent runtime
 *   doctor        check every link from the agent to the gateway
 *   up            create the data directory if needed, then run the gateway
 *   init          create a data directory: keys, database, default policy, first credentials
 *   serve         run the gateway
 *   policy sign   sign a policy bundle with the policy key
 *   audit verify  check the event chain, and checkpoints if a sink exists
 *   mcp-stdio     bridge a stdio MCP client to the gateway's MCP endpoint
 *   demo          run the twelve reference workflows in memory
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import type { Checkpoint } from './audit/events.ts';
import { generateKeyDir, loadKeyDir, signingKeyFromPem } from './core/crypto.ts';
import { digest, parseStrict, type Json } from './core/json.ts';
import type { Destination, GrantScope, ToolManifest } from './core/types.ts';
import {
  InstallError, MIN_HERMES, detectHermes, gatewayHealth, hookSelfTest, installPlugin, pluginCurrent, pluginSource,
  readMode, readUrl, removePlugin, tokenPath, tokenState, versionAtLeast, writeMode, writeToken, writeUrl, type HermesInfo,
} from './install/hermes.ts';
import { installService, serviceState, uninstallService } from './install/service.ts';
import { validateManifest } from './registry/tools.ts';
import { startServer } from './gateway/server.ts';
import { Shield } from './gateway/shield.ts';
import { DEFAULT_POLICY, signBundle, validateBundle } from './policy/bundle.ts';
import { Store } from './store/db.ts';

function parseArgs(argv: string[]): { positional: string[]; flags: Record<string, string | true> } {
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[a.slice(2)] = next;
        i++;
      } else flags[a.slice(2)] = true;
    } else positional.push(a);
  }
  return { positional, flags };
}

const flag = (flags: Record<string, string | true>, name: string, fallback: string): string =>
  typeof flags[name] === 'string' ? (flags[name] as string) : fallback;

function open(dir: string, twoPerson = true): Shield {
  if (!existsSync(join(dir, 'keys', 'permit.key'))) {
    throw new Error(`No AgentShield data in ${dir}. Run "agentshield init --dir ${dir}" first.`);
  }
  return new Shield({
    keys: loadKeyDir(join(dir, 'keys')),
    store: new Store(join(dir, 'agentshield.db')),
    checkpointSink: join(dir, 'checkpoints.jsonl'),
    twoPersonReview: twoPerson,
  });
}

/** The package root: where package.json, integrations/ and examples/ live, whether running from source or a build. */
function packageRoot(): string {
  let dir = import.meta.dirname;
  while (!existsSync(join(dir, 'package.json')) || !existsSync(join(dir, 'integrations'))) {
    const parent = dirname(dir);
    if (parent === dir) throw new Error('Could not locate the AgentShield package files.');
    dir = parent;
  }
  return dir;
}

function tenantOf(dir: string, flags: Record<string, string | true>): string {
  if (typeof flags.tenant === 'string') return flags.tenant;
  try {
    return (JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')) as { tenant: string }).tenant;
  } catch {
    return 'default';
  }
}

function init(dir: string, tenant: string, next = `agentshield serve --dir ${dir}`): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  writeFileSync(join(dir, 'config.json'), `${JSON.stringify({ tenant }, null, 2)}\n`, { mode: 0o600 });
  const keys = generateKeyDir(join(dir, 'keys'));
  const shield = new Shield({ keys, store: new Store(join(dir, 'agentshield.db')), checkpointSink: join(dir, 'checkpoints.jsonl') });
  const credentials: Record<string, string> = {};
  for (const [id, role] of [['admin', 'admin'], ['security', 'operator'], ['auditor', 'auditor']] as const) {
    credentials[id] = shield.identity.createPrincipal(tenant, id, role);
    shield.audit.append(tenant, { event_type: 'principal.created', detail: { principal_id: id, role, by: 'bootstrap' } });
  }
  // The first policy has no second person to activate it; that is recorded as a bootstrap activation.
  const record = shield.policies.create(tenant, signBundle(keys.policySigner!, DEFAULT_POLICY), 'bootstrap');
  shield.policies.activate(tenant, record.policy_id, record.version, 'bootstrap', false);
  shield.audit.append(tenant, { event_type: 'policy.activated', policy_version: record.version, detail: { policy_id: record.policy_id, bundle_digest: record.bundle_digest, by: 'bootstrap' } });
  const credPath = join(dir, 'bootstrap-credentials.json');
  writeFileSync(credPath, `${JSON.stringify({ tenant, credentials }, null, 2)}\n`, { mode: 0o600 });
  shield.close();
  console.log(`Initialized ${resolve(dir)} for tenant "${tenant}".
  Policy:       ${record.policy_id} v${record.version} (active)
  Credentials:  ${resolve(credPath)}  (admin, security, auditor — owner-readable only; shown nowhere else)
  Policy key:   ${resolve(join(dir, 'keys', 'policy-signing.key'))}
                Move this off the gateway host before production use. The gateway only needs keys/trust/*.pub.${next ? `\nNext: ${next}` : ''}`);
}

async function serve(dir: string, flags: Record<string, string | true>): Promise<void> {
  const shield = open(dir, flags['no-two-person'] !== true);
  const socket = typeof flags.socket === 'string' ? flags.socket : undefined;
  const host = flag(flags, 'host', '127.0.0.1');
  const port = Number(flag(flags, 'port', '8787'));
  const server = await startServer(shield, { socket, host, port });
  console.log(`AgentShield listening on ${socket ? `unix:${socket}` : `http://${host}:${port}`}`);
  if (!socket && host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    console.log('Warning: listening beyond loopback without TLS. Put a TLS-terminating proxy in front, or use --socket.');
  }
  const stop = () => {
    server.close(() => {
      shield.close();
      process.exit(0);
    });
    server.closeAllConnections();
  };
  console.log(`Audit checkpoints → ${resolve(join(dir, 'checkpoints.jsonl'))} (every 5 minutes and at shutdown)`);
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

interface HermesPreset {
  destinations: Omit<Destination, 'tenant_id'>[];
  grant_scope: GrantScope;
  tool: ToolManifest;
}

/** The gateway address named on the command line or in the environment, if any. */
const statedUrl = (flags: Record<string, string | true>): string | undefined => {
  const stated = typeof flags.url === 'string' ? flags.url : typeof flags.port === 'string' ? `http://127.0.0.1:${flags.port}` : process.env.AGENTSHIELD_URL;
  return stated?.replace(/\/$/, '');
};
const gatewayUrl = (flags: Record<string, string | true>): string => statedUrl(flags) ?? 'http://127.0.0.1:8787';

function versionLine(): string {
  const root = packageRoot();
  const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string };
  const rev = spawnSync('git', ['-C', root, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return `agentshield ${version}${rev.status === 0 && rev.stdout.trim() ? ` (${rev.stdout.trim()})` : ''}`;
}

/**
 * The gateway's half of connecting a Hermes agent: the destinations and tool
 * preset, an agent identity with a standing grant, and its credential saved
 * owner-only in the data directory. Safe to repeat; it changes only what is
 * missing or out of date, which is also how a grant is renewed.
 */
function enrollHermes(dir: string, flags: Record<string, string | true>, agentId: string): { tokenPath: string; token: string; tenant: string; done: string[] } {
  const tenant = tenantOf(dir, flags);
  const days = Number(flag(flags, 'days', '90'));
  if (!(days > 0)) throw new Error('--days must be a positive number.');
  const preset = parseStrict(readFileSync(join(packageRoot(), 'integrations', 'hermes', 'preset.json'), 'utf8')) as unknown as HermesPreset;
  const tokenDir = join(dir, 'agents');
  const tokenPath = join(tokenDir, `${agentId}.token`);
  const done: string[] = [];

  const shield = open(dir, false);
  let token: string;
  try {
    token = shield.store.tx(() => {
      for (const d of preset.destinations) shield.catalog.setDestination(tenant, d);

      const manifest = validateManifest(preset.tool);
      const current = shield.tools.get(tenant, manifest.tool_id);
      if (!current || current.state !== 'approved' || current.schema_hash !== digest(manifest as unknown as Json)) {
        const { tool } = shield.tools.register(tenant, manifest, 'cli:connect');
        shield.tools.approve(tenant, tool.tool_id, tool.schema_hash, 'cli:connect', false);
        shield.audit.append(tenant, { event_type: 'tool.registered', tool_revision: tool.schema_hash, detail: { tool_id: tool.tool_id, kind: manifest.kind, by: 'cli:connect' } });
        shield.audit.append(tenant, { event_type: 'tool.verified', tool_revision: tool.schema_hash, detail: { tool_id: tool.tool_id, by: 'cli:connect', note: 'bundled preset' } });
        done.push(`registered the "${tool.tool_id}" tool preset (${Object.keys(manifest.operations).length} operations)`);
      }

      let credential = '';
      const saved = existsSync(tokenPath) ? readFileSync(tokenPath, 'utf8').trim() : '';
      const savedPrincipal = saved ? shield.authenticate(saved) : null;
      if (!shield.identity.agent(tenant, agentId)) {
        credential = shield.identity.createPrincipal(tenant, agentId, 'agent', { sponsor: userInfo().username, displayName: 'Hermes agent' });
        shield.audit.append(tenant, { event_type: 'principal.created', agent_id: agentId, detail: { principal_id: agentId, role: 'agent', by: 'cli:connect' } });
        done.push(`created agent "${agentId}"`);
      } else if (flags.rotate === true || !savedPrincipal || savedPrincipal.principal_id !== agentId || savedPrincipal.tenant_id !== tenant) {
        credential = shield.identity.rotateCredential(tenant, agentId);
        shield.audit.append(tenant, { event_type: 'principal.credential_rotated', agent_id: agentId, detail: { principal_id: agentId, by: 'cli:connect' } });
        done.push(`issued a new credential for "${agentId}" (the old one no longer works)`);
      } else {
        credential = saved;
      }

      const standing = shield.grants.list(tenant, agentId).find((g) => g.task_id === '*' && g.scope.tools.includes(manifest.tool_id) && shield.grants.isLive(g));
      if (!standing) {
        const g = shield.grants.createRoot(tenant, {
          agent_id: agentId, task_id: '*', scope: preset.grant_scope, sponsor: userInfo().username,
          expires_at: shield.clock.now() + days * 86_400_000,
        }, 'cli:connect');
        shield.audit.append(tenant, { event_type: 'grant.created', agent_id: agentId, grant_revision: g.revision, detail: { grant_id: g.grant_id, by: 'cli:connect', days } });
        done.push(`granted "${agentId}" use of the Hermes tools for ${days} days`);
      }
      return credential;
    });
  } finally {
    shield.close();
  }

  mkdirSync(tokenDir, { recursive: true, mode: 0o700 });
  writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
  chmodSync(tokenPath, 0o600);
  return { tokenPath, token, tenant, done };
}

/** `enroll hermes`: the gateway's half only, for when Hermes runs in a different account from the gateway. */
function enrollCommand(dir: string, flags: Record<string, string | true>): void {
  const agentId = flag(flags, 'agent', 'hermes');
  const e = enrollHermes(dir, flags, agentId);
  console.log(`Gateway ready for Hermes agent "${agentId}" (tenant "${e.tenant}").`);
  for (const d of e.done) console.log(`  - ${d}`);
  if (!e.done.length) console.log('  - nothing to change');
  console.log(`
The agent's credential is in ${e.tokenPath} (owner-only; it is not displayed anywhere).

In the account that runs Hermes, install AgentShield the same way, then run this with the
credential on standard input:

  agentshield connect hermes --token-stdin < ${e.tokenPath}

From this account, for an agent account named ACCOUNT, that is:

  sudo -u ACCOUNT -H -i agentshield connect hermes --token-stdin < ${e.tokenPath}`);
}

function readSuppliedToken(flags: Record<string, string | true>): string {
  const token = (typeof flags['token-file'] === 'string' ? readFileSync(flags['token-file'], 'utf8') : readFileSync(0, 'utf8')).trim();
  if (!/^as_[A-Za-z0-9_-]{16,}$/.test(token)) throw new InstallError('That is not an AgentShield agent credential. Pass the file "agentshield enroll hermes" wrote.');
  return token;
}

/**
 * `connect hermes`: look at what is here, change what needs changing, then
 * prove it works. Nothing in Hermes is touched until Hermes has been found,
 * its version checked and the gateway seen to be answering — in enforce mode
 * a plugin with no gateway behind it blocks every tool call.
 */
async function connectHermes(dir: string, flags: Record<string, string | true>): Promise<void> {
  const wantMode = typeof flags.mode === 'string' ? flags.mode : undefined;
  if (wantMode !== undefined && wantMode !== 'enforce' && wantMode !== 'monitor') throw new InstallError('--mode is "enforce" or "monitor".');
  const supplied = flags['token-stdin'] === true || typeof flags['token-file'] === 'string';
  const dryRun = flags['dry-run'] === true;

  const hermes = detectHermes({ bin: typeof flags.hermes === 'string' ? flags.hermes : undefined, profile: typeof flags.profile === 'string' ? flags.profile : undefined });
  const source = pluginSource(packageRoot());
  const profile = basename(dirname(hermes.home)) === 'profiles' ? basename(hermes.home) : undefined;
  const agentId = flag(flags, 'agent', profile ?? 'hermes');
  const url = statedUrl(flags) ?? readUrl(hermes.envPath);
  const health = await gatewayHealth(url);
  const hasData = existsSync(join(dir, 'keys', 'permit.key'));

  console.log(`Found Hermes ${hermes.version}`);
  console.log(`  home:     ${hermes.home}${profile ? `  (profile "${profile}")` : ''}`);
  console.log(`  plugin:   ${hermes.plugin ? `${hermes.plugin.status}, ${hermes.plugin.source}` : 'not installed'}`);
  console.log(`  gateway:  ${health.detail}`);

  if (!versionAtLeast(hermes.version, MIN_HERMES)) throw new InstallError(`This plugin needs Hermes ${MIN_HERMES} or later; this is ${hermes.version}. Run "hermes update", then try again. Nothing was changed.`);
  if (!supplied && !hasData) {
    throw new InstallError(`There is no gateway data in ${dir}. Start a gateway here first ("agentshield service install"), or, if the gateway runs in another account, run "agentshield enroll hermes" there and pass its credential here with --token-stdin. Nothing was changed.`);
  }

  const mode = wantMode ?? readMode(hermes.envPath);
  const plan = [
    supplied ? 'use the credential supplied on standard input' : `make sure agent "${agentId}" exists on the gateway with a standing grant`,
    `save the credential to ${tokenPath()} (owner-only)`,
    pluginCurrent(hermes, source)
      ? 'leave the plugin as it is (already this version and enabled)'
      : source.kind === 'git'
        ? `install the plugin with "hermes plugins install", pinned to commit ${source.sha.slice(0, 12)}`
        : `copy the plugin into ${join(hermes.home, 'plugins')} and enable it (${source.why})`,
    `run in ${mode} mode${wantMode ? '' : ' (unchanged)'}`,
    'send one test call through the gateway',
  ];
  console.log('\nPlan:');
  for (const p of plan) console.log(`  - ${p}`);
  if (dryRun) return console.log('\nDry run: nothing was changed.');
  if (!health.ok) {
    throw new InstallError(`The gateway is not running (${health.detail}). Start it first: "agentshield service install" keeps it running, "agentshield up" runs it in this terminal. Nothing was changed.`);
  }

  console.log('');
  let token: string;
  if (supplied) token = readSuppliedToken(flags);
  else {
    const e = enrollHermes(dir, flags, agentId);
    for (const d of e.done) console.log(`Gateway: ${d}`);
    token = e.token;
  }
  const first = await hookSelfTest(url, token);
  if (!first.ok) throw new InstallError(`The gateway did not accept the agent's credential: ${first.detail}. Hermes was not changed.`);

  writeToken(token);
  if (!pluginCurrent(hermes, source)) installPlugin(hermes, source);
  if (wantMode && writeMode(hermes.envPath, wantMode)) console.log(`Set ${wantMode} mode in ${hermes.envPath}`);
  if (writeUrl(hermes.envPath, url)) console.log(`Recorded the gateway address ${url} in ${hermes.envPath}`);

  const after = detectHermes({ bin: hermes.command[0], profile: typeof flags.profile === 'string' ? flags.profile : undefined });
  const last = await hookSelfTest(url, token);
  if (after.plugin?.status !== 'enabled' || !last.ok) throw new InstallError(`Installed, but the final check failed (plugin: ${after.plugin?.status ?? 'missing'}; test call: ${last.detail}). Run "agentshield doctor".`);

  console.log(`
Connected. Hermes ${after.version} at ${after.home} now asks AgentShield before every tool call.
  plugin:  ${after.plugin.status}, ${after.plugin.source}
  mode:    ${readMode(after.envPath)}${readMode(after.envPath) === 'monitor' ? ' (nothing is blocked; what would be is written to the Hermes log)' : ''}
  check:   ${last.detail}

A Hermes that is already running picks the plugin up for new tool calls. If it does not, run:
  ${[...hermes.command, 'gateway', 'restart'].join(' ')}
Check any time with: agentshield doctor`);
}

/** `disconnect hermes`: takes the plugin, the credential copy and the mode setting back out of Hermes. */
function disconnectHermes(flags: Record<string, string | true>): void {
  const hermes = detectHermes({ bin: typeof flags.hermes === 'string' ? flags.hermes : undefined, profile: typeof flags.profile === 'string' ? flags.profile : undefined });
  const removed = removePlugin(hermes);
  const token = tokenState();
  if (token.exists) rmSync(token.path, { force: true });
  const mode = writeMode(hermes.envPath, 'enforce');
  writeUrl(hermes.envPath, undefined);
  console.log(`Disconnected Hermes at ${hermes.home}.`);
  console.log(`  - ${removed ? 'removed the plugin' : 'the plugin was not installed'}`);
  console.log(`  - ${token.exists ? `deleted ${token.path}` : 'there was no saved credential'}`);
  if (mode) console.log(`  - removed the monitor-mode setting from ${hermes.envPath}`);
  console.log('\nThe agent identity and its grant are still on the gateway, and so is everything it recorded.');
  console.log('Tool calls in Hermes are no longer checked.');
}

interface Check { status: 'ok' | 'fail' | 'warn' | 'note'; name: string; detail: string; fix?: string }

/** `doctor`: every link between an agent and the gateway, checked from this account, with what to run for anything broken. */
async function doctor(dir: string, flags: Record<string, string | true>): Promise<void> {
  const checks: Check[] = [];
  const add = (status: Check['status'], name: string, detail: string, fix?: string): void => void checks.push({ status, name, detail, ...(fix ? { fix } : {}) });

  let hermes: HermesInfo | null = null;
  let hermesMissing = '';
  try {
    hermes = detectHermes({ bin: typeof flags.hermes === 'string' ? flags.hermes : undefined, profile: typeof flags.profile === 'string' ? flags.profile : undefined });
  } catch (err) {
    hermesMissing = (err as Error).message;
  }
  const url = statedUrl(flags) ?? (hermes ? readUrl(hermes.envPath) : gatewayUrl(flags));

  add('ok', 'AgentShield', `${versionLine()} on Node ${process.versions.node}`);
  const hasData = existsSync(join(dir, 'keys', 'permit.key'));
  add('note', 'Gateway data', hasData ? dir : `none in ${dir} (expected if the gateway runs in another account)`);
  const health = await gatewayHealth(url);
  add(health.ok ? 'ok' : 'fail', 'Gateway', health.detail, health.ok ? undefined : 'agentshield service install');
  const svc = serviceState();
  if (hasData && svc.supported) {
    if (svc.installed && svc.running) add('ok', 'Service', `${svc.detail} is running`);
    else if (svc.installed) add('fail', 'Service', `${svc.detail} is installed but not running; see ${join(dir, 'gateway.log')}`, 'agentshield service install');
    else add(health.ok ? 'note' : 'warn', 'Service', 'not installed; the gateway stops when its terminal closes or the machine restarts', 'agentshield service install');
  }

  if (hasData && existsSync(join(dir, 'agents'))) {
    const shield = open(dir);
    try {
      for (const file of readdirSync(join(dir, 'agents')).filter((f) => f.endsWith('.token'))) {
        const id = file.slice(0, -'.token'.length);
        const principal = shield.authenticate(readFileSync(join(dir, 'agents', file), 'utf8').trim());
        if (!principal) { add('fail', `Agent "${id}"`, 'its saved credential is no longer valid', 'agentshield connect hermes --rotate'); continue; }
        const grant = shield.grants.list(principal.tenant_id, id).filter((g) => g.task_id === '*' && shield.grants.isLive(g)).sort((a, b) => b.expires_at - a.expires_at)[0];
        if (!grant) { add('fail', `Agent "${id}"`, 'has no live grant, so every tool call is blocked', 'agentshield connect hermes'); continue; }
        const daysLeft = Math.ceil((grant.expires_at - shield.clock.now()) / 86_400_000);
        add(daysLeft < 14 ? 'warn' : 'ok', `Agent "${id}"`, `grant runs for another ${daysLeft} days`, daysLeft < 14 ? 'agentshield connect hermes   (renews it)' : undefined);
      }
    } finally {
      shield.close();
    }
  }

  if (!hermes) add('note', 'Hermes', hermesMissing);
  else {
    add(versionAtLeast(hermes.version, MIN_HERMES) ? 'ok' : 'fail', 'Hermes', `${hermes.version} at ${hermes.home}`, versionAtLeast(hermes.version, MIN_HERMES) ? undefined : 'hermes update');
    if (!hermes.plugin) add('note', 'Hermes plugin', 'not installed; this Hermes is not protected', 'agentshield connect hermes');
    else {
      const source = pluginSource(packageRoot());
      add(hermes.plugin.status === 'enabled' ? 'ok' : 'fail', 'Hermes plugin', `${hermes.plugin.status}, ${hermes.plugin.source}${hermes.plugin.status === 'enabled' ? '' : ' — tool calls are NOT being checked'}`, hermes.plugin.status === 'enabled' ? undefined : 'agentshield connect hermes');
      if (hermes.plugin.status === 'enabled' && source.kind === 'git' && !pluginCurrent(hermes, source)) add('warn', 'Plugin version', 'differs from this AgentShield checkout', 'agentshield connect hermes');
      const token = tokenState();
      if (!token.exists) add('fail', 'Credential', `${token.path} is missing, so the plugin blocks every tool call`, 'agentshield connect hermes');
      else {
        add(token.ownerOnly ? 'ok' : 'fail', 'Credential', token.ownerOnly ? `${token.path} (owner-only)` : `${token.path} is readable by other accounts`, token.ownerOnly ? undefined : `chmod 600 ${token.path}`);
        const test = health.ok ? await hookSelfTest(url, readFileSync(token.path, 'utf8').trim()) : { ok: false, detail: 'skipped: the gateway is not answering' };
        add(test.ok ? 'ok' : 'fail', 'Test call', test.detail, test.ok ? undefined : 'agentshield connect hermes');
      }
      const mode = readMode(hermes.envPath);
      add(mode === 'monitor' ? 'warn' : 'ok', 'Mode', mode === 'monitor' ? 'monitor: nothing is blocked' : 'enforce', mode === 'monitor' ? 'agentshield connect hermes --mode enforce' : undefined);
    }
  }

  const failed = checks.filter((c) => c.status === 'fail').length;
  if (flags.json === true) process.stdout.write(`${JSON.stringify({ ok: failed === 0, checks }, null, 2)}\n`);
  else {
    const width = Math.max(...checks.map((c) => c.name.length));
    for (const c of checks) {
      console.log(`${c.status === 'fail' ? 'FAIL' : c.status.padEnd(4)}  ${c.name.padEnd(width)}  ${c.detail}`);
      if (c.fix) console.log(`      ${' '.repeat(width)}  fix: ${c.fix}`);
    }
    console.log(failed ? `\n${failed} problem${failed === 1 ? '' : 's'} found.` : '\nNo problems found.');
  }
  if (failed) process.exitCode = 1;
}

/** `service install|uninstall|status`: keeps the gateway running across logins and restarts. */
async function service(action: string | undefined, dir: string, flags: Record<string, string | true>): Promise<void> {
  if (action === 'status') {
    const s = serviceState();
    const health = await gatewayHealth(gatewayUrl(flags));
    console.log(`${s.detail}: ${!s.supported ? 'not supported here' : s.installed ? (s.running ? 'installed and running' : 'installed, not running') : 'not installed'}`);
    if (s.installed) console.log(`  definition: ${s.path}\n  log:        ${join(dir, 'gateway.log')}`);
    console.log(`  gateway:    ${health.detail}`);
    return;
  }
  if (action === 'uninstall') {
    console.log(uninstallService() ? 'Stopped the gateway and removed its service definition. Your data was not touched.' : 'No service was installed.');
    return;
  }
  if (action !== 'install') throw new Error('Usage: agentshield service install|uninstall|status [--port 8787]');
  const port = Number(flag(flags, 'port', '8787'));
  const host = flag(flags, 'host', '127.0.0.1');
  if (!existsSync(join(dir, 'keys', 'permit.key'))) init(resolve(dir), tenantOf(dir, flags), '');
  const s = installService({ root: packageRoot(), dir: resolve(dir), host, port });
  const url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
  let health = await gatewayHealth(url);
  for (let i = 0; i < 30 && !health.ok; i++) {
    await new Promise((r) => setTimeout(r, 500));
    health = await gatewayHealth(url);
  }
  if (!health.ok) throw new Error(`The service was installed (${s.path}) but the gateway is not answering at ${url}. See ${join(resolve(dir), 'gateway.log')}.`);
  console.log(`Gateway running as ${s.detail}; it starts at each login and is restarted if it crashes.
  address:    ${url}
  definition: ${s.path}
  data:       ${resolve(dir)}
  log:        ${join(resolve(dir), 'gateway.log')}`);
}

function policySign(file: string | undefined, flags: Record<string, string | true>): void {
  if (!file) throw new Error('Usage: agentshield policy sign <bundle.json> [--dir DIR | --key KEYFILE] [--out FILE]');
  const keyPath = flag(flags, 'key', join(flag(flags, 'dir', process.env.AGENTSHIELD_HOME ?? join(homedir(), '.agentshield')), 'keys', 'policy-signing.key'));
  const signed = signBundle(signingKeyFromPem(readFileSync(keyPath, 'utf8')), validateBundle(parseStrict(readFileSync(file, 'utf8'))));
  const out = `${JSON.stringify(signed, null, 2)}\n`;
  if (typeof flags.out === 'string') {
    writeFileSync(flags.out, out);
    console.log(`Signed ${signed.bundle.policy_id} v${signed.bundle.version} with key ${signed.key_id} → ${flags.out}`);
  } else process.stdout.write(out);
}

function auditVerify(dir: string, tenant: string): void {
  const shield = open(dir);
  const chain = shield.audit.verify(tenant);
  const sink = join(dir, 'checkpoints.jsonl');
  const checkpoints: Checkpoint[] = existsSync(sink)
    ? readFileSync(sink, 'utf8').split('\n').filter(Boolean).map((l) => parseStrict(l) as unknown as Checkpoint)
    : [];
  const cps = shield.audit.verifyCheckpoints(tenant, checkpoints);
  shield.close();
  console.log(chain.ok ? `Chain intact: ${chain.events} events, head ${chain.head?.event_digest ?? '(empty)'}` : `CHAIN BROKEN at sequence ${chain.error!.sequence}: ${chain.error!.problem}`);
  console.log(cps.ok ? `Checkpoints: ${cps.checked} checked, all present` : `CHECKPOINT MISMATCH:\n  ${cps.problems.join('\n  ')}`);
  if (!chain.ok || !cps.ok) process.exitCode = 1;
}

/** Lets a stdio-only MCP client (most desktop agents) use the gateway as its MCP server. */
async function mcpStdio(flags: Record<string, string | true>): Promise<void> {
  const tool = flag(flags, 'tool', '');
  const task = flag(flags, 'task', '');
  const token = process.env.AGENTSHIELD_TOKEN;
  if (!tool || !task || !token) throw new Error('Usage: AGENTSHIELD_TOKEN=… agentshield mcp-stdio --tool TOOL_ID --task TASK_ID [--url http://127.0.0.1:8787]');
  const url = `${flag(flags, 'url', 'http://127.0.0.1:8787').replace(/\/$/, '')}/mcp/${encodeURIComponent(tool)}`;
  const rl = createInterface({ input: process.stdin });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let id: unknown = null;
    try {
      id = (JSON.parse(line) as { id?: unknown }).id ?? null;
      const res = await fetch(url, {
        method: 'POST', body: line,
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'x-agentshield-task': task },
      });
      const text = await res.text();
      if (res.status === 202 || !text) continue;
      const body = JSON.parse(text) as { error?: { message?: string }; jsonrpc?: string };
      process.stdout.write(`${JSON.stringify(body.jsonrpc ? body : { jsonrpc: '2.0', id, error: { code: -32000, message: body.error?.message ?? `gateway answered ${res.status}` } })}\n`);
    } catch (err) {
      if (id !== null) process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: `AgentShield gateway unreachable: ${(err as Error).message}` } })}\n`);
    }
  }
}

const HELP = `agentshield <command>

Set up
  service install|uninstall|status [--port 8787]    Run the gateway in the background, now and after every login
  connect hermes [--profile NAME] [--mode enforce|monitor] [--agent ID] [--days 90] [--rotate] [--dry-run]
                                                    Find Hermes, install the plugin through Hermes, and test it
  connect hermes --token-stdin | --token-file FILE  The same, when the gateway runs in another account
  enroll hermes [--agent ID] [--days 90] [--rotate] Gateway side only: create the agent and save its credential
  disconnect hermes [--profile NAME]                Remove the plugin and the saved credential from Hermes
  doctor [--json]                                   Check every link from the agent to the gateway

Run
  up [--port 8787]                                  Create the data directory if needed, then run the gateway here
  init [--tenant default]                           Create keys, database, default policy and first credentials
  serve [--port 8787] [--host 127.0.0.1] [--socket PATH] [--no-two-person]
  policy sign <bundle.json> [--key KEYFILE] [--out FILE]
  audit verify [--tenant default]
  mcp-stdio --tool TOOL_ID --task TASK_ID [--url URL]   (credential in AGENTSHIELD_TOKEN)
  demo                                              Run the twelve reference workflows in memory
  --version

Every command takes --dir DIR. The default is $AGENTSHIELD_HOME, or ~/.agentshield.
The gateway address defaults to http://127.0.0.1:8787; change it with --url or $AGENTSHIELD_URL.
`;

async function main(): Promise<void> {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const dir = flag(flags, 'dir', process.env.AGENTSHIELD_HOME ?? join(homedir(), '.agentshield'));
  const tenant = tenantOf(dir, flags);
  if (flags.version === true && !positional.length) return console.log(versionLine());
  switch (positional[0]) {
    case 'up':
      if (!existsSync(join(dir, 'keys', 'permit.key'))) init(dir, tenant);
      return serve(dir, flags);
    case 'connect':
      if (positional[1] === 'hermes') return connectHermes(dir, flags);
      throw new Error('Usage: agentshield connect hermes   (Hermes is the runtime supported so far; see "agentshield --help")');
    case 'enroll':
      if (positional[1] === 'hermes') return enrollCommand(dir, flags);
      throw new Error('Usage: agentshield enroll hermes [--agent ID] [--days 90] [--rotate]');
    case 'disconnect':
      if (positional[1] === 'hermes') return disconnectHermes(flags);
      throw new Error('Usage: agentshield disconnect hermes [--profile NAME]');
    case 'doctor':
      return doctor(dir, flags);
    case 'service':
      return service(positional[1], dir, flags);
    case 'init':
      return init(dir, tenant);
    case 'serve':
      return serve(dir, flags);
    case 'policy':
      if (positional[1] === 'sign') return policySign(positional[2], flags);
      break;
    case 'audit':
      if (positional[1] === 'verify') return auditVerify(dir, tenant);
      break;
    case 'mcp-stdio':
      return mcpStdio(flags);
    case 'demo': {
      const { runDemo } = await import('../examples/demo.ts');
      return runDemo();
    }
  }
  process.stdout.write(HELP);
  if (positional.length) process.exitCode = 2;
}

main().catch((err) => {
  process.stderr.write(`agentshield: ${(err as Error).message}\n`);
  process.exit(1);
});

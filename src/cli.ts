/**
 * agentshield — command line for the local gateway.
 *
 *   up            create the data directory if needed, then run the gateway
 *   connect       set an agent runtime up to use the gateway (currently: hermes)
 *   init          create a data directory: keys, database, default policy, first credentials
 *   serve         run the gateway
 *   policy sign   sign a policy bundle with the policy key
 *   audit verify  check the event chain, and checkpoints if a sink exists
 *   mcp-stdio     bridge a stdio MCP client to the gateway's MCP endpoint
 *   demo          run the twelve reference workflows in memory
 */
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import type { Checkpoint } from './audit/events.ts';
import { generateKeyDir, loadKeyDir, signingKeyFromPem } from './core/crypto.ts';
import { digest, parseStrict, type Json } from './core/json.ts';
import type { Destination, GrantScope, ToolManifest } from './core/types.ts';
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

function init(dir: string, tenant: string): void {
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
                Move this off the gateway host before production use. The gateway only needs keys/trust/*.pub.
Next: agentshield serve --dir ${dir}`);
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

/** Recursively make a published folder readable by everyone and writable only by its owner. */
function publishReadOnly(path: string): void {
  const isDir = statSync(path).isDirectory();
  chmodSync(path, isDir ? 0o755 : 0o644);
  if (isDir) for (const name of readdirSync(path)) publishReadOnly(join(path, name));
}

interface HermesPreset {
  destinations: Omit<Destination, 'tenant_id'>[];
  grant_scope: GrantScope;
  tool: ToolManifest;
}

/**
 * Everything the gateway side needs for a Hermes agent to use it: the
 * destinations and tool preset, an agent identity with a standing grant, the
 * credential, and the plugin laid out where the agent's account can pick it
 * up. Safe to run again; it changes only what is missing or out of date.
 */
function connectHermes(dir: string, flags: Record<string, string | true>): void {
  const tenant = tenantOf(dir, flags);
  const user = typeof flags.user === 'string' ? flags.user : undefined;
  const agentId = flag(flags, 'agent', user ?? 'hermes-agent');
  const days = Number(flag(flags, 'days', '90'));
  if (!(days > 0)) throw new Error('--days must be a positive number.');
  const root = packageRoot();
  const pluginSource = join(root, 'integrations', 'hermes', 'agentshield');
  const preset = parseStrict(readFileSync(join(root, 'integrations', 'hermes', 'preset.json'), 'utf8')) as unknown as HermesPreset;
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

  const pluginsDir = '"${HERMES_HOME:-$HOME/.hermes}/plugins"';
  const lines: string[] = [];
  if (user && user !== userInfo().username) {
    // Another account cannot read this one's files, so lay the plugin out somewhere it can.
    const share = flag(flags, 'share-dir', process.platform === 'darwin' ? '/Users/Shared/agentshield' : '');
    if (!share) throw new Error('Pass --share-dir with a folder the other account can read.');
    const published = join(share, 'hermes', 'agentshield');
    rmSync(published, { recursive: true, force: true });
    mkdirSync(dirname(published), { recursive: true });
    cpSync(pluginSource, published, { recursive: true, filter: (src) => !src.includes('__pycache__') });
    publishReadOnly(share);
    lines.push(
      `1. Hand "${user}" its credential (asks for your password; the credential is never displayed):`,
      `     sudo -u ${user} sh -c 'umask 077; mkdir -p ~/.config/agentshield; cat > ~/.config/agentshield/token' < ${tokenPath}`,
      `2. In the "${user}" account, install the plugin:`,
      `     mkdir -p ${pluginsDir} && cp -R ${published} ${pluginsDir}/ && hermes plugins enable agentshield`,
      `3. Restart Hermes in that account.`,
    );
  } else {
    const own = join(homedir(), '.config', 'agentshield');
    mkdirSync(own, { recursive: true, mode: 0o700 });
    writeFileSync(join(own, 'token'), `${token}\n`, { mode: 0o600 });
    chmodSync(join(own, 'token'), 0o600);
    lines.push(
      `1. Install the plugin:`,
      `     mkdir -p ${pluginsDir} && cp -R ${pluginSource} ${pluginsDir}/ && hermes plugins enable agentshield`,
      `2. Restart Hermes.`,
    );
  }
  console.log(`Gateway side ready for Hermes (tenant "${tenant}", agent "${agentId}").`);
  for (const d of done) console.log(`  - ${d}`);
  if (!done.length) console.log('  - nothing to change');
  console.log(`\n${lines.join('\n')}`);
  console.log(`\nTo watch without blocking first, add AGENTSHIELD_MODE=monitor to that account's ~/.hermes/.env.`);
  console.log(`The gateway must be running: agentshield up`);
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

  up [--port 8787]                                  Create the data directory if needed, then run the gateway
  connect hermes [--user ACCOUNT] [--agent ID] [--days 90] [--rotate]
                                                    Prepare the gateway for a Hermes agent and print the install line
  init [--tenant default]                           Create keys, database, default policy and first credentials
  serve [--port 8787] [--host 127.0.0.1] [--socket PATH] [--no-two-person]
  policy sign <bundle.json> [--key KEYFILE] [--out FILE]
  audit verify [--tenant default]
  mcp-stdio --tool TOOL_ID --task TASK_ID [--url URL]   (credential in AGENTSHIELD_TOKEN)
  demo                                              Run the twelve reference workflows in memory

Every command takes --dir DIR. The default is $AGENTSHIELD_HOME, or ~/.agentshield.
`;

async function main(): Promise<void> {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const dir = flag(flags, 'dir', process.env.AGENTSHIELD_HOME ?? join(homedir(), '.agentshield'));
  const tenant = tenantOf(dir, flags);
  switch (positional[0]) {
    case 'up':
      if (!existsSync(join(dir, 'keys', 'permit.key'))) init(dir, tenant);
      return serve(dir, flags);
    case 'connect':
      if (positional[1] === 'hermes') return connectHermes(dir, flags);
      throw new Error('Usage: agentshield connect hermes [--user ACCOUNT] [--agent ID] [--days 90] [--rotate]');
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

/**
 * agentshield — command line for the local gateway.
 *
 *   init          create a data directory: keys, database, default policy, first credentials
 *   serve         run the gateway
 *   policy sign   sign a policy bundle with the policy key
 *   audit verify  check the event chain, and checkpoints if a sink exists
 *   mcp-stdio     bridge a stdio MCP client to the gateway's MCP endpoint
 *   demo          run the twelve reference workflows in memory
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import type { Checkpoint } from './audit/events.ts';
import { generateKeyDir, loadKeyDir, signingKeyFromPem } from './core/crypto.ts';
import { parseStrict } from './core/json.ts';
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

function init(dir: string, tenant: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
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

function policySign(file: string | undefined, flags: Record<string, string | true>): void {
  if (!file) throw new Error('Usage: agentshield policy sign <bundle.json> [--dir DIR | --key KEYFILE] [--out FILE]');
  const keyPath = flag(flags, 'key', join(flag(flags, 'dir', '.agentshield'), 'keys', 'policy-signing.key'));
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

  init [--dir .agentshield] [--tenant default]     Create keys, database, default policy and first credentials
  serve [--dir .agentshield] [--port 8787] [--host 127.0.0.1] [--socket PATH] [--no-two-person]
  policy sign <bundle.json> [--dir DIR | --key KEYFILE] [--out FILE]
  audit verify [--dir .agentshield] [--tenant default]
  mcp-stdio --tool TOOL_ID --task TASK_ID [--url URL]   (credential in AGENTSHIELD_TOKEN)
  demo                                              Run the twelve reference workflows in memory
`;

async function main(): Promise<void> {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const dir = flag(flags, 'dir', '.agentshield');
  const tenant = flag(flags, 'tenant', 'default');
  switch (positional[0]) {
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

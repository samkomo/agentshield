/**
 * The versioned REST interface, plus the MCP endpoint.
 *
 * Tenant and principal come from the bearer credential. Request bodies are
 * parsed strictly (duplicate keys are a 400) and are bounded in size.
 * Agent-facing routes and administrative routes share a port here but not
 * permissions: an agent credential cannot reach registry, policy, suspension
 * or audit operations.
 */
import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { JsonError, isObject, parseStrict, type Json, type JsonObject } from '../core/json.ts';
import type { DecisionResponse, ExecutionResponse, Permission, Principal, Role } from '../core/types.ts';
import { ShieldError } from '../core/util.ts';
import type { Checkpoint } from '../audit/events.ts';
import type { GrantRequest } from '../identity/grants.ts';
import { requirePermission } from '../identity/identity.ts';
import { handleMcpMessage } from '../mcp/proxy.ts';
import type { SignedBundle } from '../policy/bundle.ts';
import type { Shield } from './shield.ts';

const MAX_BODY = 2 * 1024 * 1024;

interface Ctx {
  p: Principal;
  body: Json;
  params: string[];
  query: URLSearchParams;
  req: IncomingMessage;
}
type Reply = { status: number; body: Json } | Json;
type Handler = (c: Ctx) => Reply | Promise<Reply>;

const obj = (b: Json): JsonObject => {
  if (!isObject(b)) throw new ShieldError(400, 'invalid_body', 'Request body must be a JSON object.');
  return b;
};
const str = (b: JsonObject, key: string): string => {
  const v = b[key];
  if (typeof v !== 'string' || !v) throw new ShieldError(422, 'invalid_field', `Field "${key}" is required.`);
  return v;
};
const anyOf = (p: Principal, ...perms: Permission[]): void => {
  if (!perms.some((x) => p.permissions.includes(x))) requirePermission(p, perms[0]!);
};
const num = (q: URLSearchParams, key: string): number | undefined => {
  const v = q.get(key);
  return v !== null && /^\d+$/.test(v) ? Number(v) : undefined;
};

function decisionStatus(d: DecisionResponse): number {
  return d.decision === 'block' ? 403 : d.decision === 'require_approval' ? 202 : 200;
}
function executionStatus(e: ExecutionResponse): number {
  return e.state === 'succeeded' ? 200 : e.state === 'denied' ? 403 : e.state === 'unknown' ? 504 : 502;
}
/** Accept either `{ action: {...}, ... }` or the bare envelope. */
function actionOf(b: JsonObject): Json {
  return b.action !== undefined ? b.action : b;
}

function routes(shield: Shield): [string, RegExp, Handler][] {
  const J = (v: unknown) => v as Json;
  const table: [string, string, Handler][] = [
    // ── scanning ──
    ['POST', '/v1/scan/input', (c) => shield.scanInput(c.p, c.body)],
    ['POST', '/v1/scan/output', (c) => shield.scanOutput(c.p, c.body)],
    ['POST', '/v1/detect/sensitive', (c) => shield.detectSensitive(c.p, c.body)],
    ['POST', '/v1/redact', (c) => shield.redact(c.p, c.body)],
    ['POST', '/v1/detect/injection', (c) => shield.detectInjection(c.p, c.body)],

    // ── actions ──
    ['POST', '/v1/tools/inspect', (c) => J(shield.inspect(c.p, actionOf(obj(c.body))))],
    ['POST', '/v1/actions/risk', (c) => {
      const r = shield.inspect(c.p, actionOf(obj(c.body)));
      return { score: r.risk.score, class: r.risk.class, factors: J(r.risk.factors) };
    }],
    ['POST', '/v1/actions/authorize', (c) => {
      const b = obj(c.body);
      const d = shield.authorize(c.p, actionOf(b), { approvalId: typeof b.approval_id === 'string' ? b.approval_id : undefined });
      return { status: decisionStatus(d), body: J(d) };
    }],
    ['POST', '/v1/actions/execute', async (c) => {
      const b = obj(c.body);
      const e = await shield.execute(c.p, b.action ?? null, str(b, 'permit'));
      return { status: executionStatus(e), body: J(e) };
    }],
    ['POST', '/v1/actions/run', async (c) => {
      const b = obj(c.body);
      const r = await shield.run(c.p, actionOf(b), { approvalId: typeof b.approval_id === 'string' ? b.approval_id : undefined });
      return { status: r.execution ? executionStatus(r.execution) : decisionStatus(r.decision), body: J(r) };
    }],
    ['POST', '/v1/actions/:id/block', (c) => J(shield.blockAction(c.p, c.params[0]!, String(obj(c.body).reason ?? '')))],
    ['POST', '/v1/actions/:id/reconcile', (c) => {
      const b = obj(c.body);
      const outcome = str(b, 'outcome');
      if (outcome !== 'succeeded' && outcome !== 'failed') throw new ShieldError(422, 'invalid_field', 'outcome must be succeeded or failed.');
      return J(shield.reconcile(c.p, c.params[0]!, outcome, str(b, 'evidence')));
    }],

    // ── approvals ──
    ['POST', '/v1/approvals', (c) => {
      const b = obj(c.body);
      const a = shield.requestApproval(c.p, str(b, 'decision_id'), str(b, 'action_digest'));
      return { approval_id: a.approval_id, status: a.status, expiry: new Date(a.expires_at).toISOString() };
    }],
    ['GET', '/v1/approvals', (c) => ({ items: J(shield.listApprovals(c.p, c.query.get('status') ?? undefined)) })],
    ['GET', '/v1/approvals/:id', (c) => J(shield.getApproval(c.p, c.params[0]!))],
    ['POST', '/v1/approvals/:id/decide', (c) => {
      const b = obj(c.body);
      return J(shield.decideApproval(c.p, c.params[0]!, str(b, 'verdict') as 'approve' | 'reject', str(b, 'action_digest'), typeof b.reason === 'string' ? b.reason : undefined));
    }],

    // ── tool registry ──
    ['POST', '/v1/tools', (c) => {
      const b = obj(c.body);
      const { tool, warnings } = shield.registerTool(c.p, b.manifest ?? b);
      return { status: 201, body: { tool_id: tool.tool_id, revision: tool.schema_hash, state: tool.state, warnings } };
    }],
    ['GET', '/v1/tools', (c) => {
      anyOf(c.p, 'admin:tools', 'operator:tools', 'auditor:read');
      return { items: J(shield.tools.list(c.p.tenant_id)) };
    }],
    ['GET', '/v1/tools/:id', (c) => {
      anyOf(c.p, 'admin:tools', 'operator:tools', 'auditor:read');
      const t = shield.tools.get(c.p.tenant_id, c.params[0]!);
      if (!t) throw new ShieldError(404, 'tool_not_found', 'No such tool.');
      return J(t);
    }],
    ['POST', '/v1/tools/:id/verify', async (c) => {
      const t = await shield.verifyTool(c.p, c.params[0]!, str(obj(c.body), 'expected_revision'));
      return { verified: true, schema_hash: t.schema_hash, state: t.state, checked_at: new Date(t.checked_at!).toISOString() };
    }],
    ['POST', '/v1/tools/:id/quarantine', (c) => {
      const t = shield.quarantineTool(c.p, c.p.tenant_id, c.params[0]!, String(obj(c.body).reason ?? 'manual quarantine'));
      return { tool_id: t.tool_id, state: t.state };
    }],

    // ── evidence ──
    ['GET', '/v1/events', (c) => J(shield.listEvents(c.p, {
      after: num(c.query, 'after'), limit: num(c.query, 'limit'), agentId: c.query.get('agent_id') ?? undefined,
      actionId: c.query.get('action_id') ?? undefined, type: c.query.get('type') ?? undefined,
    }))],
    ['GET', '/v1/events/:id', (c) => J(shield.getEvent(c.p, c.params[0]!))],
    ['POST', '/v1/reports', (c) => {
      const range = obj(obj(c.body).range ?? null);
      return J(shield.report(c.p, str(range, 'from'), str(range, 'to')));
    }],
    ['POST', '/v1/audit/verify', (c) => {
      const cps = isObject(c.body) && Array.isArray(c.body.checkpoints) ? (c.body.checkpoints as unknown as Checkpoint[]) : [];
      return shield.verifyAudit(c.p, cps);
    }],
    ['POST', '/v1/audit/checkpoint', (c) => J(shield.checkpoint(c.p))],

    // ── agents ──
    ['GET', '/v1/agents', (c) => {
      anyOf(c.p, 'auditor:read', 'operator:suspend', 'admin:principals');
      return { items: J(shield.identity.listAgents(c.p.tenant_id)) };
    }],
    ['GET', '/v1/agents/:id/risks', (c) => J(shield.listAgentRisks(c.p, c.params[0]!, { after: num(c.query, 'cursor'), limit: num(c.query, 'limit') }))],
    ['POST', '/v1/agents/:id/suspend', (c) => {
      const b = obj(c.body);
      const a = shield.suspendAgent(c.p, c.params[0]!, String(b.reason ?? ''), typeof b.expected_epoch === 'number' ? b.expected_epoch : undefined);
      return { state: a.status, revocation_epoch: a.revocation_epoch };
    }],
    ['POST', '/v1/agents/:id/resume', (c) => {
      const a = shield.resumeAgent(c.p, c.params[0]!);
      return { state: a.status, revocation_epoch: a.revocation_epoch };
    }],

    // ── policy ──
    ['POST', '/v1/policies', (c) => {
      const r = shield.createPolicy(c.p, obj(c.body) as unknown as SignedBundle);
      return { status: 201, body: { policy_id: r.policy_id, revision: r.version, state: r.state, bundle_digest: r.bundle_digest } };
    }],
    ['GET', '/v1/policies', (c) => {
      anyOf(c.p, 'admin:policy', 'auditor:read');
      return { items: J(shield.policies.list(c.p.tenant_id)) };
    }],
    ['POST', '/v1/policies/:id/test', (c) => {
      const b = obj(c.body);
      if (typeof b.revision !== 'number') throw new ShieldError(422, 'invalid_field', 'Field "revision" is required.');
      return shield.testPolicy(c.p, c.params[0]!, b.revision, b.synthetic_cases ?? null);
    }],
    ['POST', '/v1/policies/:id/activate', (c) => {
      const b = obj(c.body);
      if (typeof b.version !== 'number') throw new ShieldError(422, 'invalid_field', 'Field "version" is required.');
      const r = shield.activatePolicy(c.p, c.params[0]!, b.version);
      return { policy_id: r.policy_id, revision: r.version, state: r.state };
    }],
    ['POST', '/v1/policies/:id/revoke', (c) => {
      const b = obj(c.body);
      if (typeof b.version !== 'number') throw new ShieldError(422, 'invalid_field', 'Field "version" is required.');
      shield.revokePolicy(c.p, c.params[0]!, b.version);
      return { policy_id: c.params[0]!, revision: b.version, state: 'revoked' };
    }],

    // ── identity, grants, catalog ──
    ['POST', '/v1/principals', (c) => {
      const b = obj(c.body);
      const credential = shield.createPrincipal(c.p, str(b, 'principal_id'), str(b, 'role') as Role, {
        sponsor: typeof b.sponsor === 'string' ? b.sponsor : undefined, displayName: typeof b.display_name === 'string' ? b.display_name : undefined,
      });
      return { status: 201, body: { principal_id: str(b, 'principal_id'), role: str(b, 'role'), credential } };
    }],
    ['POST', '/v1/grants', (c) => ({ status: 201, body: J(shield.createGrant(c.p, obj(c.body) as unknown as GrantRequest)) })],
    ['GET', '/v1/grants', (c) => {
      anyOf(c.p, 'admin:grants', 'auditor:read');
      return { items: J(shield.grants.list(c.p.tenant_id, c.query.get('agent_id') ?? undefined)) };
    }],
    ['POST', '/v1/grants/delegate', (c) => {
      const b = obj(c.body);
      return { status: 201, body: J(shield.delegate(c.p, str(b, 'parent_task_id'), obj(b.grant ?? null) as unknown as GrantRequest)) };
    }],
    ['POST', '/v1/grants/:id/revoke', (c) => J(shield.revokeGrant(c.p, c.params[0]!))],
    ['POST', '/v1/destinations', (c) => {
      requirePermission(c.p, 'admin:catalog');
      return J(shield.catalog.setDestination(c.p.tenant_id, obj(c.body) as never));
    }],
    ['GET', '/v1/destinations', (c) => {
      anyOf(c.p, 'admin:catalog', 'auditor:read');
      return { items: J(shield.catalog.listDestinations(c.p.tenant_id)) };
    }],
    ['POST', '/v1/resource-labels', (c) => {
      requirePermission(c.p, 'admin:catalog');
      const b = obj(c.body);
      shield.catalog.setResourceLabels(c.p.tenant_id, str(b, 'pattern'), b.labels as string[]);
      return { pattern: str(b, 'pattern'), labels: b.labels ?? [] };
    }],
    ['GET', '/v1/resource-labels', (c) => {
      anyOf(c.p, 'admin:catalog', 'auditor:read');
      return { items: J(shield.catalog.listResourceLabels(c.p.tenant_id)) };
    }],
    ['POST', '/v1/vault/reveal', (c) => {
      const b = obj(c.body);
      return { value: shield.revealPlaceholder(c.p, str(b, 'task_id'), str(b, 'scope_ref'), str(b, 'placeholder')) };
    }],

    // ── MCP ──
    ['POST', '/mcp/:id', async (c) => {
      requirePermission(c.p, 'agent:execute');
      const task = c.req.headers['x-agentshield-task'];
      const handle = (m: Json) => handleMcpMessage(shield, c.p, c.params[0]!, typeof task === 'string' ? task : undefined, m);
      if (Array.isArray(c.body)) {
        const replies = (await Promise.all(c.body.map(handle))).filter((r) => r !== null);
        return replies.length ? replies : { status: 202, body: null };
      }
      const reply = await handle(c.body);
      return reply === null ? { status: 202, body: null } : reply;
    }],
  ];
  return table.map(([method, path, handler]) => [
    method,
    new RegExp(`^${path.replace(/:id/g, '([^/]+)')}$`),
    handler,
  ]);
}

/**
 * Read a bounded request body. An oversized body is drained rather than
 * abandoned: leaving unread bytes on a kept-alive connection, or tearing the
 * socket down mid-upload, turns one rejected request into resets on the
 * client's next ones. Past a hard ceiling the connection is simply dropped.
 */
async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY * 8) {
      req.destroy();
      break;
    }
    if (total <= MAX_BODY) chunks.push(chunk as Buffer);
  }
  if (total > MAX_BODY) throw new ShieldError(413, 'payload_too_large', 'Request body exceeds the size limit.');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    throw new ShieldError(400, 'invalid_encoding', 'Request body is not valid UTF-8.');
  }
}

function send(res: ServerResponse, status: number, body: Json): void {
  if (body === null && status === 202) {
    res.writeHead(202).end();
    return;
  }
  const text = JSON.stringify(body);
  const headers: Record<string, string | number> = { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store' };
  if (status === 413) headers.connection = 'close';
  res.writeHead(status, headers);
  res.end(text);
}

export function createHandler(shield: Shield): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const table = routes(shield);
  return async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://gateway');
      if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { status: 'ok' });

      const auth = req.headers.authorization;
      const p = shield.authenticate(auth?.startsWith('Bearer ') ? auth.slice(7) : undefined);
      if (!p) throw new ShieldError(401, 'unauthenticated', 'A valid bearer credential is required.');

      let matched: { handler: Handler; params: string[] } | null = null;
      let pathKnown = false;
      for (const [method, re, handler] of table) {
        const m = re.exec(url.pathname);
        if (!m) continue;
        pathKnown = true;
        if (method !== req.method) continue;
        matched = { handler, params: m.slice(1).map((s) => decodeURIComponent(s)) };
        break;
      }
      if (!matched) throw new ShieldError(pathKnown ? 405 : 404, pathKnown ? 'method_not_allowed' : 'not_found', pathKnown ? 'Method not allowed.' : 'No such route.');

      let body: Json = null;
      if (req.method !== 'GET') {
        const raw = await readBody(req);
        if (raw.length) {
          if (!(req.headers['content-type'] ?? '').includes('application/json')) throw new ShieldError(415, 'unsupported_media_type', 'Content-Type must be application/json.');
          body = parseStrict(raw);
        }
      }
      const reply = await matched.handler({ p, body, params: matched.params, query: url.searchParams, req });
      if (isObject(reply) && typeof reply.status === 'number' && 'body' in reply && Object.keys(reply).length === 2) {
        return send(res, reply.status, reply.body as Json);
      }
      return send(res, 200, reply as Json);
    } catch (err) {
      if (err instanceof ShieldError) {
        return send(res, err.status, { error: { code: err.code, message: err.message, ...(err.details !== undefined ? { details: err.details } : {}) } });
      }
      if (err instanceof JsonError || err instanceof URIError) return send(res, 400, { error: { code: 'invalid_json', message: `Malformed request: ${err.message}` } });
      // Anything unexpected is a 503: the caller must treat a control that could not run as a denial.
      process.stderr.write(`agentshield: unhandled error: ${(err as Error).stack ?? err}\n`);
      return send(res, 503, { error: { code: 'control_unavailable', message: 'A required control could not run; the request was not allowed.' } });
    }
  };
}

export interface ListenOptions {
  host?: string;
  port?: number;
  /** Unix socket path. When set, host and port are ignored and the socket is made owner-only. */
  socket?: string;
}

export function startServer(shield: Shield, opts: ListenOptions = {}): Promise<Server> {
  const server = createServer(createHandler(shield));
  server.requestTimeout = 120_000;
  // Every 30 s: expire stale permits and approvals. Every 5 min, and at shutdown: checkpoint the audit chains.
  let tick = 0;
  const timer = setInterval(() => {
    try {
      shield.housekeeping();
      if (++tick % 10 === 0) shield.audit.checkpointAll();
    } catch {
      /* best effort */
    }
  }, 30_000);
  timer.unref();
  server.on('close', () => {
    clearInterval(timer);
    try {
      shield.audit.checkpointAll();
    } catch {
      /* the store may already be closed */
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    if (opts.socket) {
      if (existsSync(opts.socket)) unlinkSync(opts.socket);
      server.listen(opts.socket, () => {
        chmodSync(opts.socket!, 0o600);
        resolve(server);
      });
    } else {
      server.listen(opts.port ?? 8787, opts.host ?? '127.0.0.1', () => resolve(server));
    }
  });
}

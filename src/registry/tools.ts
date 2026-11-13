/**
 * The private tool registry.
 *
 * A tool is usable only in the exact form someone reviewed. The manifest is
 * hashed; that hash is the pinned revision. Registering a changed manifest
 * puts the tool back to `pending`, and an upstream MCP server whose live tool
 * definitions drift from the pin is quarantined.
 *
 * What a pin proves is narrow: the reviewed artifact and configuration. A
 * server that changes its behaviour without changing its metadata is not
 * caught here — that is what scoped credentials and result validation are for.
 */
import { digest, isObject, parseStrict, type Json } from '../core/json.ts';
import { unsupportedKeywords } from '../core/schema.ts';
import type { OperationSpec, ToolManifest, ToolRecord } from '../core/types.ts';
import { ShieldError, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

function invalid(msg: string): never {
  throw new ShieldError(422, 'invalid_manifest', `Tool manifest rejected: ${msg}`);
}

const NAME = /^[A-Za-z0-9][\w.:/-]{0,127}$/;

export function validateManifest(m: unknown): ToolManifest {
  if (!isObject(m as Json)) invalid('not an object');
  const t = m as unknown as ToolManifest;
  if (typeof t.tool_id !== 'string' || !NAME.test(t.tool_id)) invalid('tool_id');
  if (!['http', 'mcp', 'function', 'external'].includes(t.kind)) invalid('kind must be http, mcp, function or external');
  if (typeof t.owner !== 'string' || !t.owner) invalid('owner is required');
  if (typeof t.destination_id !== 'string' || !t.destination_id) invalid('destination_id is required');
  if (t.credential_ref !== undefined && !/^(env:[A-Za-z_][A-Za-z0-9_]*|file:\/.+)$/.test(t.credential_ref)) invalid('credential_ref must be env:NAME or file:/absolute/path');
  if (t.expires_at !== undefined && !Number.isFinite(Date.parse(t.expires_at))) invalid('expires_at');
  const e = t.endpoint;
  if (t.kind === 'http') {
    if (!e?.base_url) invalid('http tools need endpoint.base_url');
    let u: URL;
    try {
      u = new URL(e.base_url);
    } catch {
      return invalid('endpoint.base_url is not a URL');
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') invalid('endpoint.base_url must be http(s)');
    if (u.username || u.password) invalid('endpoint.base_url must not embed credentials');
  }
  if (t.kind === 'mcp') {
    if (e?.transport === 'http') {
      if (!e.url) invalid('mcp http transport needs endpoint.url');
    } else if (e?.transport === 'stdio') {
      if (!e.command) invalid('mcp stdio transport needs endpoint.command');
      if (e.args !== undefined && (!Array.isArray(e.args) || e.args.some((a) => typeof a !== 'string'))) invalid('endpoint.args');
      if (e.env !== undefined && (!Array.isArray(e.env) || e.env.some((a) => typeof a !== 'string'))) invalid('endpoint.env');
    } else invalid('mcp tools need endpoint.transport of http or stdio');
  }
  if (!isObject(t.operations as unknown as Json) || !Object.keys(t.operations).length) invalid('at least one operation is required');
  for (const [name, op] of Object.entries(t.operations)) {
    // `*` is a catch-all for host-executed tools, whose runtime can gain tools the manifest has never seen.
    if (!(name === '*' && t.kind === 'external') && !NAME.test(name)) invalid(`operation name "${name}"`);
    const o = op as OperationSpec;
    if (!isObject(o as unknown as Json)) invalid(`operation ${name}`);
    if (typeof o.class !== 'string' || !o.class) invalid(`operation ${name}: class is required`);
    if (o.effect !== 'read' && o.effect !== 'write') invalid(`operation ${name}: effect must be read or write`);
    if (o.approval !== undefined && o.approval !== 'always') invalid(`operation ${name}: approval may only be "always"`);
    if (o.destination_id !== undefined && (typeof o.destination_id !== 'string' || !o.destination_id)) invalid(`operation ${name}: destination_id`);
    if (o.destination_from !== undefined && !['value', 'email_domain', 'url_host'].includes(o.destination_from)) invalid(`operation ${name}: destination_from`);
    for (const k of ['input_schema', 'output_schema'] as const) {
      if (o[k] !== undefined && !isObject(o[k] as Json)) invalid(`operation ${name}: ${k} must be an object`);
    }
    if (t.kind === 'http') {
      if (!o.http || typeof o.http.path !== 'string' || !o.http.path.startsWith('/')) invalid(`operation ${name}: http.path must start with /`);
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(o.http.method)) invalid(`operation ${name}: http.method`);
    }
  }
  return t;
}

/** The reviewed spec for an operation. Host-executed tools may declare `*` for operations not listed by name. */
export function operationSpec(tool: ToolRecord | null | undefined, operation: string): OperationSpec | null {
  if (!tool) return null;
  const ops = tool.manifest.operations;
  if (operation !== '*' && Object.hasOwn(ops, operation)) return ops[operation]!;
  return tool.manifest.kind === 'external' && Object.hasOwn(ops, '*') ? ops['*']! : null;
}

/** Schema keywords the validator does not enforce, per operation. Shown to the reviewer at registration. */
export function manifestWarnings(m: ToolManifest): string[] {
  const out: string[] = [];
  for (const [name, op] of Object.entries(m.operations)) {
    for (const k of ['input_schema', 'output_schema'] as const) {
      const schema = op[k];
      if (schema) for (const path of unsupportedKeywords(schema)) out.push(`${name}.${k}${path} is not enforced`);
    }
    if (!op.input_schema && m.kind !== 'external') out.push(`${name} has no input_schema; arguments are unconstrained`);
  }
  return out;
}

/** What an upstream MCP server must still say for a pinned operation to be considered unchanged. */
export function upstreamFingerprint(tool: { name?: Json; description?: Json; inputSchema?: Json }): string {
  return digest({ name: tool.name ?? null, description: tool.description ?? null, inputSchema: tool.inputSchema ?? null });
}
export function pinnedFingerprint(name: string, op: OperationSpec): string {
  return digest({ name, description: op.description ?? null, inputSchema: op.input_schema ?? null });
}

function rowToTool(r: Record<string, unknown>): ToolRecord {
  return { ...(r as unknown as ToolRecord), manifest: parseStrict(r.manifest as string) as unknown as ToolManifest };
}

export class ToolRegistry {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  /** Register or replace a manifest. The tool is unusable until verified, even if an older revision was approved. */
  register(tenant: string, manifest: unknown, registeredBy: string): { tool: ToolRecord; warnings: string[] } {
    const m = validateManifest(manifest);
    const hash = digest(m as unknown as Json);
    this.store.run(
      `INSERT INTO tools (tenant_id, tool_id, state, manifest, schema_hash, registered_by, created_at)
       VALUES (?,?,'pending',?,?,?,?)
       ON CONFLICT (tenant_id, tool_id) DO UPDATE SET state='pending', manifest=excluded.manifest, schema_hash=excluded.schema_hash,
         registered_by=excluded.registered_by, verified_by=NULL, checked_at=NULL, reason=NULL, created_at=excluded.created_at`,
      tenant, m.tool_id, JSON.stringify(m), hash, registeredBy, this.clock.now(),
    );
    return { tool: this.get(tenant, m.tool_id)!, warnings: manifestWarnings(m) };
  }

  get(tenant: string, toolId: string): ToolRecord | undefined {
    const r = this.store.get('SELECT * FROM tools WHERE tenant_id=? AND tool_id=?', tenant, toolId);
    return r ? rowToTool(r) : undefined;
  }

  list(tenant: string): ToolRecord[] {
    return this.store.all('SELECT * FROM tools WHERE tenant_id=? ORDER BY tool_id', tenant).map(rowToTool);
  }

  /**
   * Approve the exact revision the reviewer looked at. `expectedRevision`
   * must match the stored hash, so approving a manifest that was swapped
   * between review and click fails.
   */
  approve(tenant: string, toolId: string, expectedRevision: string, verifiedBy: string, twoPerson: boolean): ToolRecord {
    return this.store.tx(() => {
      const t = this.get(tenant, toolId);
      if (!t) throw new ShieldError(404, 'tool_not_found', 'No such tool.');
      if (t.schema_hash !== expectedRevision) throw new ShieldError(409, 'revision_conflict', 'The registered manifest is not the revision you reviewed.', { schema_hash: t.schema_hash });
      if (t.state === 'revoked') throw new ShieldError(409, 'tool_revoked', 'A revoked tool must be registered again.');
      if (twoPerson && t.registered_by === verifiedBy) throw new ShieldError(403, 'two_person_required', 'A tool must be verified by someone other than whoever registered it.');
      this.store.run(`UPDATE tools SET state='approved', verified_by=?, checked_at=?, reason=NULL WHERE tenant_id=? AND tool_id=?`, verifiedBy, this.clock.now(), tenant, toolId);
      return this.get(tenant, toolId)!;
    });
  }

  touch(tenant: string, toolId: string): void {
    this.store.run('UPDATE tools SET checked_at=? WHERE tenant_id=? AND tool_id=?', this.clock.now(), tenant, toolId);
  }

  setState(tenant: string, toolId: string, state: 'quarantined' | 'revoked', reason: string): ToolRecord {
    const changed = this.store.run('UPDATE tools SET state=?, reason=?, checked_at=? WHERE tenant_id=? AND tool_id=?', state, reason, this.clock.now(), tenant, toolId);
    if (!changed) throw new ShieldError(404, 'tool_not_found', 'No such tool.');
    return this.get(tenant, toolId)!;
  }
}

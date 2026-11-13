/**
 * Execution adapters: the only code that touches a downstream system.
 *
 * Each adapter reports one of three outcomes. `ok` and a definite failure are
 * simple. The third matters most: when a write was sent and we cannot tell
 * whether it landed, the adapter says so (`definite: false`) and the executor
 * records the action as `unknown` instead of retrying — a blind retry of a
 * payment is how duplicates happen.
 */
import { readFileSync } from 'node:fs';
import { isObject, parseStrict, type Json, type JsonObject } from '../core/json.ts';
import type { BoundAction, OperationSpec, ToolRecord } from '../core/types.ts';
import { McpClient, McpError, type UpstreamTool } from '../mcp/client.ts';

export class AdapterError extends Error {
  /** True when the downstream system certainly did not perform the action. */
  definite: boolean;
  code: string;
  /** What the downstream system said, when it said anything. Scanned like any other result before an agent sees it. */
  result?: Json;
  constructor(code: string, message: string, definite: boolean, result?: Json) {
    super(message);
    this.code = code;
    this.definite = definite;
    this.result = result;
  }
}

export interface InvokeContext {
  tool: ToolRecord;
  op: OperationSpec;
  action: BoundAction;
  timeoutMs: number;
  maxResultBytes: number;
}

export interface InvokeResult {
  result: Json;
  provider_ref?: string;
}

export interface ToolAdapter {
  invoke(ctx: InvokeContext): Promise<InvokeResult>;
}

/** Resolve a brokered credential. It exists only inside this process and the outgoing request. */
export function resolveCredential(ref: string | undefined): string | null {
  if (!ref) return null;
  let value: string | undefined;
  if (ref.startsWith('env:')) value = process.env[ref.slice(4)];
  else if (ref.startsWith('file:')) {
    try {
      value = readFileSync(ref.slice(5), 'utf8').trim();
    } catch {
      value = undefined;
    }
  }
  if (!value) throw new AdapterError('credential_unavailable', 'The brokered credential for this tool is not available.', true);
  return value;
}

export type FunctionHandler = (operation: string, args: JsonObject, action: BoundAction) => Promise<Json> | Json;

/** In-process handlers, for embedding the gateway in an application and for tests. */
export class FunctionAdapter implements ToolAdapter {
  private handlers = new Map<string, FunctionHandler>();

  register(toolId: string, handler: FunctionHandler): void {
    this.handlers.set(toolId, handler);
  }

  async invoke(ctx: InvokeContext): Promise<InvokeResult> {
    const handler = this.handlers.get(ctx.tool.tool_id);
    if (!handler) throw new AdapterError('no_handler', 'No handler is registered for this tool.', true);
    return { result: await handler(ctx.action.operation, ctx.action.arguments, ctx.action) };
  }
}

async function readBounded(res: Response, max: number): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > max) throw new AdapterError('result_too_large', 'Downstream response exceeds the size limit.', false);
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (res.body) {
    for await (const chunk of res.body) {
      total += chunk.byteLength;
      if (total > max) throw new AdapterError('result_too_large', 'Downstream response exceeds the size limit.', false);
      chunks.push(chunk);
    }
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * REST adapter. The host comes from the reviewed manifest and the path from
 * the reviewed operation; arguments can fill `{placeholders}` in the path but
 * are percent-encoded, so they cannot redirect the call. Redirects are errors.
 */
export class HttpAdapter implements ToolAdapter {
  async invoke(ctx: InvokeContext): Promise<InvokeResult> {
    const { tool, op, action } = ctx;
    const credential = resolveCredential(tool.manifest.credential_ref);
    const body: JsonObject = { ...action.arguments };
    const path = op.http!.path.replace(/\{(\w+)\}/g, (_m, name: string) => {
      const v = body[name];
      if (typeof v !== 'string' && typeof v !== 'number') throw new AdapterError('missing_path_argument', `Argument "${name}" is required.`, true);
      delete body[name];
      return encodeURIComponent(String(v));
    });
    const base = new URL(tool.manifest.endpoint!.base_url!);
    const url = new URL(base.pathname.replace(/\/$/, '') + path, base);
    const method = op.http!.method;
    const bodyless = method === 'GET' || method === 'DELETE';
    if (bodyless) {
      for (const [k, v] of Object.entries(body)) {
        if (v !== null && typeof v !== 'object') url.searchParams.set(k, String(v));
      }
    }
    if (url.host !== base.host) throw new AdapterError('destination_changed', 'Resolved URL left the registered host.', true);

    const headers: Record<string, string> = { accept: 'application/json' };
    if (!bodyless) headers['content-type'] = 'application/json';
    if (credential) headers[tool.manifest.credential_header ?? 'authorization'] = tool.manifest.credential_header ? credential : `Bearer ${credential}`;
    if (action.idempotency_key) headers['idempotency-key'] = action.idempotency_key;

    let res: Response;
    try {
      res = await fetch(url, {
        method, headers, redirect: 'error', signal: AbortSignal.timeout(ctx.timeoutMs),
        body: bodyless ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      const code = (err as { cause?: { code?: string } }).cause?.code;
      const neverSent = code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EAI_AGAIN';
      throw new AdapterError('downstream_unreachable', neverSent ? 'Downstream system is unreachable.' : 'No response from the downstream system.', neverSent);
    }
    const text = await readBounded(res, ctx.maxResultBytes);
    if (res.status >= 500) throw new AdapterError('downstream_error', `Downstream system answered ${res.status}.`, false);
    if (res.status >= 400) throw new AdapterError('downstream_rejected', `Downstream system rejected the call (${res.status}).`, true);
    let result: Json = null;
    if (text) {
      try {
        result = parseStrict(text);
      } catch {
        result = { text };
      }
    }
    return { result, provider_ref: res.headers.get('x-request-id') ?? undefined };
  }
}

/** Calls a tool on an upstream MCP server, keeping one connection per pinned tool revision. */
export class McpAdapter implements ToolAdapter {
  private clients = new Map<string, Promise<McpClient>>();

  private async client(tool: ToolRecord): Promise<McpClient> {
    const key = `${tool.tenant_id}\0${tool.tool_id}\0${tool.schema_hash}`;
    const existing = this.clients.get(key);
    if (existing) {
      const c = await existing.catch(() => null);
      if (c && !c.closed) return c;
      this.clients.delete(key);
    }
    const credential = resolveCredential(tool.manifest.credential_ref);
    const pending = McpClient.connect(tool.manifest.endpoint!, credential);
    this.clients.set(key, pending);
    try {
      return await pending;
    } catch (err) {
      this.clients.delete(key);
      throw new AdapterError('upstream_unavailable', `MCP server is not reachable: ${(err as Error).message}`.slice(0, 200), true);
    }
  }

  /** Live tool definitions, for comparing against the pin. */
  async listTools(tool: ToolRecord): Promise<UpstreamTool[]> {
    return (await this.client(tool)).listTools();
  }

  async invoke(ctx: InvokeContext): Promise<InvokeResult> {
    const client = await this.client(ctx.tool);
    let result: Json;
    try {
      result = await client.callTool(ctx.action.operation, ctx.action.arguments, ctx.timeoutMs);
    } catch (err) {
      if (err instanceof McpError) throw new AdapterError('upstream_error', err.message, !err.sent);
      throw err;
    }
    if (isObject(result) && result.isError === true) {
      throw new AdapterError('tool_reported_error', 'The MCP tool reported an error.', false, result);
    }
    return { result };
  }

  closeAll(): void {
    for (const p of this.clients.values()) p.then((c) => c.close()).catch(() => {});
    this.clients.clear();
  }
}

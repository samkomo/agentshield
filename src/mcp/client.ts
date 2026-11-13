/**
 * Minimal MCP client for talking to upstream servers (JSON-RPC 2.0 over
 * streamable HTTP or stdio). It implements only what the gateway needs:
 * initialize, tools/list and tools/call.
 *
 * The upstream connection is its own trust relationship. The credential used
 * here comes from the gateway's broker; the agent's token is never forwarded.
 * A stdio server gets a near-empty environment: PATH plus the variables its
 * reviewed manifest names.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { isObject, parseStrict, type Json, type JsonObject } from '../core/json.ts';
import type { ToolManifest } from '../core/types.ts';

export const MCP_PROTOCOL_VERSION = '2025-06-18';

/** `sent` is false only when we know the request never left this process. */
export class McpError extends Error {
  sent: boolean;
  constructor(message: string, sent: boolean) {
    super(message);
    this.sent = sent;
  }
}

export interface UpstreamTool extends JsonObject {
  name: string;
}

interface Transport {
  request(method: string, params: JsonObject, timeoutMs: number): Promise<Json>;
  notify(method: string, params: JsonObject): Promise<void>;
  close(): void;
  readonly closed: boolean;
}

function unwrap(msg: Json): Json {
  if (!isObject(msg)) throw new McpError('malformed JSON-RPC response', true);
  if (msg.error !== undefined) {
    const e = isObject(msg.error) ? msg.error : {};
    throw new McpError(`upstream error ${String(e.code ?? '')}: ${String(e.message ?? 'unknown')}`.slice(0, 300), true);
  }
  return msg.result ?? null;
}

class HttpTransport implements Transport {
  private url: string;
  private credential: string | null;
  private session: string | null = null;
  private nextId = 1;
  closed = false;
  protocolVersion: string | null = null;

  constructor(url: string, credential: string | null) {
    this.url = url;
    this.credential = credential;
  }

  private async post(body: JsonObject, timeoutMs: number): Promise<Response> {
    const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
    if (this.credential) headers.authorization = `Bearer ${this.credential}`;
    if (this.session) headers['mcp-session-id'] = this.session;
    if (this.protocolVersion) headers['mcp-protocol-version'] = this.protocolVersion;
    let res: Response;
    try {
      res = await fetch(this.url, { method: 'POST', headers, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      const code = (err as { cause?: { code?: string } }).cause?.code;
      throw new McpError(`upstream unreachable: ${(err as Error).message}`, !(code === 'ECONNREFUSED' || code === 'ENOTFOUND'));
    }
    const sid = res.headers.get('mcp-session-id');
    if (sid) this.session = sid;
    return res;
  }

  async request(method: string, params: JsonObject, timeoutMs: number): Promise<Json> {
    const id = this.nextId++;
    const res = await this.post({ jsonrpc: '2.0', id, method, params }, timeoutMs);
    if (!res.ok) throw new McpError(`upstream HTTP ${res.status}`, res.status >= 500);
    const text = await res.text();
    if ((res.headers.get('content-type') ?? '').includes('text/event-stream')) {
      for (const block of text.split(/\r?\n\r?\n/)) {
        const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n');
        if (!data) continue;
        const msg = parseStrict(data);
        if (isObject(msg) && msg.id === id) return unwrap(msg);
      }
      throw new McpError('upstream stream ended without a response', true);
    }
    return unwrap(parseStrict(text));
  }

  async notify(method: string, params: JsonObject): Promise<void> {
    await this.post({ jsonrpc: '2.0', method, params }, 10_000);
  }

  close(): void {
    this.closed = true;
  }
}

class StdioTransport implements Transport {
  private child: ChildProcess;
  private buffer = '';
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: Json) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  closed = false;

  constructor(command: string, args: string[], env: Record<string, string>) {
    this.child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'ignore'] });
    this.child.stdout!.setEncoding('utf8');
    this.child.stdout!.on('data', (chunk: string) => this.onData(chunk));
    const end = (why: string) => {
      this.closed = true;
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.reject(new McpError(why, true));
      }
      this.pending.clear();
    };
    this.child.on('error', (err) => end(`upstream process failed: ${err.message}`));
    this.child.on('exit', () => end('upstream process exited'));
    this.child.stdin!.on('error', () => {});
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    if (this.buffer.length > 16 * 1024 * 1024) {
      this.close();
      return;
    }
    let nl: number;
    while ((nl = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;
      let msg: Json;
      try {
        msg = parseStrict(line);
      } catch {
        continue;
      }
      if (!isObject(msg) || typeof msg.id !== 'number') continue;
      const p = this.pending.get(msg.id);
      if (!p) continue;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      try {
        p.resolve(unwrap(msg));
      } catch (err) {
        p.reject(err as Error);
      }
    }
  }

  request(method: string, params: JsonObject, timeoutMs: number): Promise<Json> {
    if (this.closed) return Promise.reject(new McpError('upstream process is not running', false));
    const id = this.nextId++;
    return new Promise<Json>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new McpError('upstream timed out', true));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin!.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  async notify(method: string, params: JsonObject): Promise<void> {
    if (!this.closed) this.child.stdin!.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  close(): void {
    this.closed = true;
    this.child.kill();
  }
}

export class McpClient {
  private transport: Transport;
  private constructor(transport: Transport) {
    this.transport = transport;
  }

  get closed(): boolean {
    return this.transport.closed;
  }

  static async connect(endpoint: NonNullable<ToolManifest['endpoint']>, credential: string | null, timeoutMs = 15_000): Promise<McpClient> {
    let transport: Transport;
    if (endpoint.transport === 'stdio') {
      const env: Record<string, string> = { PATH: process.env.PATH ?? '' };
      for (const name of endpoint.env ?? []) if (process.env[name] !== undefined) env[name] = process.env[name]!;
      transport = new StdioTransport(endpoint.command!, endpoint.args ?? [], env);
    } else {
      transport = new HttpTransport(endpoint.url!, credential);
    }
    const client = new McpClient(transport);
    try {
      const init = await transport.request('initialize', {
        protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'agentshield', version: '0.1.0' },
      }, timeoutMs);
      if (transport instanceof HttpTransport && isObject(init) && typeof init.protocolVersion === 'string') transport.protocolVersion = init.protocolVersion;
      await transport.notify('notifications/initialized', {});
    } catch (err) {
      transport.close();
      throw err;
    }
    return client;
  }

  async listTools(timeoutMs = 15_000): Promise<UpstreamTool[]> {
    const tools: UpstreamTool[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 50; page++) {
      const res = await this.transport.request('tools/list', cursor ? { cursor } : {}, timeoutMs);
      if (!isObject(res) || !Array.isArray(res.tools)) throw new McpError('malformed tools/list result', true);
      for (const t of res.tools) if (isObject(t) && typeof t.name === 'string') tools.push(t as UpstreamTool);
      if (typeof res.nextCursor !== 'string' || !res.nextCursor) return tools;
      cursor = res.nextCursor;
    }
    throw new McpError('tools/list did not terminate', true);
  }

  callTool(name: string, args: JsonObject, timeoutMs: number): Promise<Json> {
    return this.transport.request('tools/call', { name, arguments: args }, timeoutMs);
  }

  close(): void {
    this.transport.close();
  }
}

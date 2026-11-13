/**
 * AgentShield client for TypeScript / JavaScript. No dependencies; needs a
 * runtime with `fetch` and `crypto.randomUUID` (Node 20+, Deno, Bun, browsers).
 *
 * The client is a convenience, not a control. It hands every action to the
 * gateway and returns what the gateway decided. An agent runtime that can
 * reach a tool without going through the gateway is not protected by anything
 * in this file — remove the direct credentials and network paths.
 */

export type Decision = 'allow' | 'redact' | 'require_approval' | 'block';

export interface ExecuteInput {
  toolId: string;
  operation: string;
  taskId: string;
  resourceId: string;
  destinationId: string;
  arguments?: Record<string, unknown>;
  idempotencyKey?: string;
  /** Seconds until the action expires. Keep it long enough for a human if approval is likely. Default 300. */
  ttlSeconds?: number;
}

export interface ExecuteResult {
  decision: Decision;
  reason: string;
  reasonCodes: string[];
  riskLevel: string;
  approvalId: string | null;
  /** `succeeded`, `failed`, `unknown` or `denied` once execution was attempted; null otherwise. */
  state: string | null;
  result: unknown;
  /** True when the result came from outside the trust boundary. Treat it as data, never as instructions. */
  untrustedContent: boolean;
  receiptId: string | null;
  /** The envelope that was submitted. Pass the whole result to `resume` after approval. */
  action: Record<string, unknown>;
  raw: unknown;
}

export class AgentShieldError extends Error {
  status: number;
  code: string;
  details: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'AgentShieldError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export class AgentShieldClient {
  private endpoint: string;
  private credential: string;
  private fetchImpl: typeof fetch;

  constructor(opts: { endpoint: string; credential: string; fetch?: typeof fetch }) {
    this.endpoint = opts.endpoint.replace(/\/$/, '');
    this.credential = opts.credential;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** Low-level call. Resolves with `{ status, body }` for any response that carries a decision or result; throws otherwise. */
  async request(method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
    const res = await this.fetchImpl(`${this.endpoint}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.credential}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    const parsed = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === 'object' && parsed.error && typeof parsed.error.code === 'string') {
      throw new AgentShieldError(res.status, parsed.error.code, parsed.error.message, parsed.error.details);
    }
    return { status: res.status, body: parsed };
  }

  private toResult(action: Record<string, unknown>, body: any): ExecuteResult {
    const d = body.decision;
    const e = body.execution;
    return {
      decision: d.decision,
      reason: d.reason,
      reasonCodes: (d.reasons ?? []).map((r: { code: string }) => r.code),
      riskLevel: d.risk_level,
      approvalId: d.approval_id ?? null,
      state: e?.state ?? null,
      result: e?.result ?? null,
      untrustedContent: e?.untrusted_content ?? false,
      receiptId: e?.receipt?.event_id ?? null,
      action,
      raw: body,
    };
  }

  /**
   * Ask the gateway to authorize and carry out one action.
   * On `block`, do not call the tool some other way. On `require_approval`,
   * keep the result and call `resume` once a person has approved it.
   */
  async execute(input: ExecuteInput): Promise<ExecuteResult> {
    const action: Record<string, unknown> = {
      action_id: `act_${crypto.randomUUID()}`,
      task_id: input.taskId,
      tool_id: input.toolId,
      operation: input.operation,
      resource_id: input.resourceId,
      destination_id: input.destinationId,
      arguments: input.arguments ?? {},
      nonce: crypto.randomUUID(),
      expires_at: new Date(Date.now() + (input.ttlSeconds ?? 300) * 1000).toISOString(),
      ...(input.idempotencyKey ? { idempotency_key: input.idempotencyKey } : {}),
    };
    return this.toResult(action, (await this.request('POST', '/v1/actions/run', { action })).body);
  }

  /** Resubmit the exact action from an earlier `require_approval` result. */
  async resume(pending: ExecuteResult): Promise<ExecuteResult> {
    const body = { action: pending.action, ...(pending.approvalId ? { approval_id: pending.approvalId } : {}) };
    return this.toResult(pending.action, (await this.request('POST', '/v1/actions/run', body)).body);
  }

  /** Would this be allowed? Records nothing and does not consume the action. */
  async inspect(action: Record<string, unknown>): Promise<any> {
    return (await this.request('POST', '/v1/tools/inspect', { action })).body;
  }

  /** Scan content pulled in from outside. Tells the gateway this task has now seen untrusted content. */
  async scanInput(payload: unknown, opts: { taskId?: string; sourceId?: string } = {}): Promise<any> {
    return (await this.request('POST', '/v1/scan/input', { payload, task_id: opts.taskId, source_id: opts.sourceId })).body;
  }

  async scanOutput(payload: unknown, destinationId: string): Promise<any> {
    return (await this.request('POST', '/v1/scan/output', { payload, destination_id: destinationId })).body;
  }

  async detectSensitive(payload: unknown, entityTypes?: string[]): Promise<any> {
    return (await this.request('POST', '/v1/detect/sensitive', { payload, entity_types: entityTypes })).body;
  }

  async redact(payload: unknown, taskId?: string): Promise<any> {
    return (await this.request('POST', '/v1/redact', { payload, task_id: taskId })).body;
  }

  async detectInjection(payload: unknown): Promise<any> {
    return (await this.request('POST', '/v1/detect/injection', { payload })).body;
  }

  /** Hand part of this agent's grant to another agent. Fails with `delegation_denied` if the child would exceed the parent. */
  async delegate(parentTaskId: string, grant: Record<string, unknown>): Promise<any> {
    return (await this.request('POST', '/v1/grants/delegate', { parent_task_id: parentTaskId, grant })).body;
  }
}

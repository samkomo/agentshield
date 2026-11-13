/**
 * The canonical action envelope: validation, binding and digests.
 *
 * Validation is strict on purpose. An unknown field is rejected rather than
 * ignored, because a field the gateway ignores is a field that is not covered
 * by the digest a human approved.
 */
import { canonicalize, digest, isObject, type Json, type JsonObject } from '../core/json.ts';
import type { ActionEnvelope, BoundAction, OperationSpec, Principal, ToolRecord } from '../core/types.ts';
import { ShieldError } from '../core/util.ts';

const FIELDS = new Set(['action_id', 'task_id', 'tool_id', 'tool_revision', 'operation', 'resource_id', 'destination_id', 'arguments', 'nonce', 'expires_at', 'idempotency_key']);
const TOKEN = /^[A-Za-z0-9][\w.:@/-]{0,127}$/;
// eslint-disable-next-line no-control-regex
const PRINTABLE = /^[^\u0000-\u001f\u007f]{1,512}$/;

function reject(code: string, message: string, status = 422): never {
  throw new ShieldError(status, code, message);
}

export interface EnvelopeLimits {
  maxArgumentsBytes: number;
  maxTtlMs: number;
}

export function validateEnvelope(raw: Json, now: number, limits: EnvelopeLimits): ActionEnvelope {
  if (!isObject(raw)) reject('invalid_envelope', 'Action must be a JSON object.', 400);
  for (const k of Object.keys(raw)) if (!FIELDS.has(k)) reject('unknown_field', `Unknown field "${k}".`);
  const str = (k: string, re: RegExp, required = true): string | undefined => {
    const v = raw[k];
    if (v === undefined && !required) return undefined;
    if (typeof v !== 'string' || !re.test(v)) reject('invalid_field', `Field "${k}" is missing or malformed.`);
    return v;
  };
  const env: ActionEnvelope = {
    action_id: str('action_id', TOKEN)!,
    task_id: str('task_id', TOKEN)!,
    tool_id: str('tool_id', TOKEN)!,
    operation: str('operation', TOKEN)!,
    resource_id: str('resource_id', PRINTABLE)!,
    destination_id: str('destination_id', PRINTABLE)!,
    arguments: raw.arguments as JsonObject,
    nonce: str('nonce', /^[\w.:@/+=-]{8,128}$/)!,
    expires_at: str('expires_at', PRINTABLE)!,
  };
  const rev = str('tool_revision', /^sha256:[0-9a-f]{64}$/, false);
  if (rev !== undefined) env.tool_revision = rev;
  const idem = str('idempotency_key', TOKEN, false);
  if (idem !== undefined) env.idempotency_key = idem;
  if (env.task_id === '*') reject('invalid_field', 'Field "task_id" is missing or malformed.');
  if (!isObject(env.arguments)) reject('invalid_field', 'Field "arguments" must be an object.');
  if (Buffer.byteLength(canonicalize(env.arguments)) > limits.maxArgumentsBytes) reject('payload_too_large', 'Arguments exceed the size limit.', 413);

  const expires = Date.parse(env.expires_at);
  if (!Number.isFinite(expires) || !/^\d{4}-\d{2}-\d{2}T/.test(env.expires_at)) reject('invalid_field', 'Field "expires_at" must be an ISO 8601 timestamp.');
  if (expires <= now) reject('action_expired', 'Action has already expired.');
  if (expires > now + limits.maxTtlMs) reject('expiry_too_far', 'Action expiry is further out than policy permits.');
  return env;
}

/** Digest of what the caller submitted, for telling a retry from a conflicting reuse of the same action_id. */
export function requestDigest(p: Principal, env: ActionEnvelope): string {
  return digest({ tenant_id: p.tenant_id, principal_id: p.principal_id, envelope: env as unknown as Json });
}

export function bind(env: ActionEnvelope, p: Principal, actorChain: string[], toolRevision: string): BoundAction {
  return { ...env, tenant_id: p.tenant_id, principal_id: p.principal_id, actor_chain: actorChain, tool_revision: toolRevision };
}

export function actionDigest(a: BoundAction): string {
  return digest(a as unknown as Json);
}

/** Strip the gateway-resolved fields back off, leaving what a caller would submit. */
export function toEnvelope(a: BoundAction): ActionEnvelope {
  const { tenant_id: _t, principal_id: _p, actor_chain: _c, ...env } = a;
  return env;
}

export function destinationOf(value: Json, from: OperationSpec['destination_from']): string | null {
  if (typeof value !== 'string' || !value) return null;
  if (from === 'email_domain') {
    const at = value.lastIndexOf('@');
    return at > 0 && at < value.length - 1 ? value.slice(at + 1).toLowerCase() : null;
  }
  if (from === 'url_host') {
    try {
      return new URL(value).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  return value;
}

/**
 * Check that the envelope's resource and destination are the ones the
 * arguments actually name. Without this an agent could label a call
 * "to partner.example" while the recipient argument says otherwise, and every
 * destination rule downstream would be judging the label.
 */
export function bindingErrors(env: ActionEnvelope, tool: ToolRecord | null, op: OperationSpec | null): string[] {
  if (!tool || !op) return [];
  const errors: string[] = [];
  if (op.resource_arg) {
    // An absent argument names no resource, so there is nothing for the envelope to contradict.
    const v = env.arguments[op.resource_arg];
    if (v !== undefined && v !== env.resource_id) errors.push(`resource_id does not match the "${op.resource_arg}" argument.`);
  }
  if (op.destination_arg) {
    const v = env.arguments[op.destination_arg];
    const values = Array.isArray(v) ? v : [v ?? null];
    const resolved = values.map((x) => destinationOf(x, op.destination_from ?? 'value'));
    if (!resolved.length || resolved.some((d) => d === null)) errors.push(`The "${op.destination_arg}" argument does not name a destination.`);
    else if (resolved.some((d) => d !== env.destination_id.toLowerCase() && d !== env.destination_id)) {
      errors.push(`destination_id does not match the "${op.destination_arg}" argument; send one action per destination.`);
    }
  } else if ((op.destination_id ?? tool.manifest.destination_id) !== env.destination_id) {
    errors.push('destination_id is not where this tool is registered to run.');
  }
  return errors;
}

/**
 * Work out an envelope's resource and destination from the reviewed manifest,
 * for callers (the MCP proxy, host hooks) that only know a tool name and its
 * arguments. It mirrors `bindingErrors`, so what is derived here always passes there.
 */
export function deriveBinding(tool: ToolRecord | null | undefined, op: OperationSpec | null, toolId: string, operation: string, args: JsonObject): { resourceId: string; destinationId: string } {
  const resourceArg = op?.resource_arg ? args[op.resource_arg] : undefined;
  const resourceId = typeof resourceArg === 'string' && resourceArg && resourceArg.length <= 512 ? resourceArg : `${toolId}/${operation}`;
  let destinationId = op?.destination_id ?? tool?.manifest.destination_id ?? toolId;
  if (op?.destination_arg) {
    const v = args[op.destination_arg];
    destinationId = destinationOf(Array.isArray(v) ? (v[0] ?? null) : (v ?? null), op.destination_from ?? 'value') ?? destinationId;
  }
  return { resourceId, destinationId };
}

/** Pull the amount out of the arguments named by the manifest. Amounts are integers in minor units; floats are refused, not rounded. */
export function extractAmount(env: ActionEnvelope, op: OperationSpec | null): { amount: { minor: number; currency: string } | null; error: string | null } {
  const amountArg = op?.amount_arg ?? (op?.class === 'payment' ? 'amount_minor' : undefined);
  if (!amountArg || env.arguments[amountArg] === undefined) return { amount: null, error: null };
  const minor = env.arguments[amountArg];
  const currency = env.arguments[op?.currency_arg ?? 'currency'];
  if (typeof minor !== 'number' || !Number.isSafeInteger(minor) || minor < 0) return { amount: null, error: 'Amount must be a non-negative integer in minor units.' };
  if (typeof currency !== 'string' || !/^[A-Z]{3}$/.test(currency)) return { amount: null, error: 'Currency must be a three-letter code.' };
  return { amount: { minor, currency }, error: null };
}

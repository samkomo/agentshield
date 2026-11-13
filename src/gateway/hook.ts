/**
 * The host-hook interface.
 *
 * Some agent runtimes let a plugin see every tool call before and after it
 * runs (Hermes's `pre_tool_call` / `post_tool_call`, Claude Code's
 * `PreToolUse` / `PostToolUse`). These two calls are what such a plugin
 * needs:
 *
 *   before  — "the model wants to call this tool with these arguments": the
 *             gateway builds the action from the reviewed manifest, decides,
 *             and answers allow, modify (redacted arguments), approve (ask a
 *             person) or block;
 *   after   — "here is what came back": the gateway checks the result, records
 *             the outcome, and returns the version that is safe to show the model.
 *
 * This is decision and evidence without execution. The host still runs the
 * tool with its own credentials, so the boundary is only as strong as the
 * host's willingness to obey its plugin. It is the quick way to cover
 * everything a runtime does; tools that matter most belong behind the gateway
 * proper, where the agent never holds the credential.
 */
import { deriveBinding } from '../actions/envelope.ts';
import { isObject, type Json, type JsonObject } from '../core/json.ts';
import type { Decision, Principal } from '../core/types.ts';
import { ShieldError, iso, newId } from '../core/util.ts';
import { DEFAULT_POLICY } from '../policy/bundle.ts';
import { operationSpec } from '../registry/tools.ts';
import type { Shield } from './shield.ts';

const ACTION: Record<Decision, 'allow' | 'modify' | 'approve' | 'block'> = {
  allow: 'allow', redact: 'modify', require_approval: 'approve', block: 'block',
};

/** Host session ids are whatever the host uses; make one safe to use as a task id. */
function taskIdOf(raw: Json | undefined): string {
  const cleaned = typeof raw === 'string' ? raw.replace(/[^\w.:@/-]/g, '_').slice(0, 120) : '';
  if (!cleaned || cleaned === '*') return 'default';
  return /^[A-Za-z0-9]/.test(cleaned) ? cleaned : `t${cleaned}`;
}

export function hookBefore(shield: Shield, p: Principal, toolId: string, body: Json): JsonObject {
  if (!isObject(body) || typeof body.tool_name !== 'string' || !body.tool_name) {
    throw new ShieldError(422, 'invalid_field', 'Field "tool_name" is required.');
  }
  const name = body.tool_name;
  const args: JsonObject = isObject(body.args) ? body.args : {};
  const tool = shield.tools.get(p.tenant_id, toolId);
  const op = operationSpec(tool, name);
  const { resourceId, destinationId } = deriveBinding(tool, op, toolId, name, args);
  const limits = (shield.policies.active(p.tenant_id)?.bundle ?? DEFAULT_POLICY).limits;
  const envelope: JsonObject = {
    action_id: newId('act'),
    task_id: taskIdOf(body.task_id),
    tool_id: toolId,
    operation: name,
    resource_id: resourceId,
    destination_id: destinationId,
    arguments: args,
    nonce: newId('non'),
    expires_at: iso(shield.clock.now() + limits.max_action_ttl_seconds * 1000 - 1000),
  };

  // A dry run answers "what would happen" and records nothing: for running alongside a host before enforcing.
  if (body.dry_run === true) {
    const r = shield.inspect(p, envelope);
    return {
      action: ACTION[r.decision], dry_run: true, decision: r.decision, risk_level: r.risk.class,
      reason: r.reasons.map((x) => x.message).join(' '), reason_codes: r.reasons.map((x) => x.code),
    };
  }

  const d = shield.authorize(p, envelope);
  const out: JsonObject = {
    action: ACTION[d.decision],
    action_id: d.action_id,
    decision: d.decision,
    decision_id: d.decision_id,
    risk_level: d.risk_level,
    reason: d.reason,
    reason_codes: d.reasons.map((r) => r.code),
    approval_id: d.approval_id,
    finding_categories: d.finding_categories,
  };
  // Present whenever arguments were rewritten, including when a person must still approve the rewritten call.
  if (d.transformed_action) out.args = d.transformed_action.arguments;
  return out;
}

export function hookAfter(shield: Shield, p: Principal, toolId: string, body: Json): JsonObject {
  if (!isObject(body) || typeof body.action_id !== 'string') throw new ShieldError(422, 'invalid_field', 'Field "action_id" is required.');
  const intent = shield.intents.get(p.tenant_id, body.action_id);
  if (intent && intent.action.tool_id !== toolId) throw new ShieldError(404, 'action_not_found', 'No such action.');
  const outcome = shield.reportOutcome(p, body.action_id, body) as unknown as JsonObject;
  // `tainted` tells the host to mark this result as data before the model reads it.
  const threshold = (shield.policies.active(p.tenant_id)?.bundle ?? DEFAULT_POLICY).injection.taint_threshold;
  const injection = outcome.injection;
  outcome.tainted = isObject(injection) && typeof injection.score === 'number' && injection.score >= threshold;
  return outcome;
}

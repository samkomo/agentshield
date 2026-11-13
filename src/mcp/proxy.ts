/**
 * The agent-facing MCP endpoint.
 *
 * To an agent this looks like an ordinary MCP server. Behind it:
 *
 *  - tools/list returns the definitions that were reviewed and pinned, never
 *    the upstream server's live text — so a poisoned or silently edited tool
 *    description cannot reach the model — and only the tools the agent's grant
 *    covers for this task;
 *  - tools/call becomes an action envelope and goes through the same
 *    authorize → execute pipeline as every other action;
 *  - the agent's credential stops here; the upstream call uses a separate,
 *    brokered credential.
 *
 * Any registered tool can be reached this way, not only upstream MCP servers.
 */
import { destinationOf } from '../actions/envelope.ts';
import { digest, isObject, type Json, type JsonObject } from '../core/json.ts';
import type { Principal } from '../core/types.ts';
import { ShieldError, iso, matchAny, newId } from '../core/util.ts';
import type { Shield } from '../gateway/shield.ts';
import { MCP_PROTOCOL_VERSION } from './client.ts';

const SUPPORTED_VERSIONS = [MCP_PROTOCOL_VERSION, '2025-03-26', '2024-11-05'];

const rpcError = (id: Json, code: number, message: string): JsonObject => ({ jsonrpc: '2.0', id, error: { code, message } });
const text = (t: string, isError = false): JsonObject => ({ content: [{ type: 'text', text: t }], isError });

/** Handle one JSON-RPC message. Returns null for notifications, which get no reply. */
export async function handleMcpMessage(shield: Shield, p: Principal, toolId: string, taskId: string | undefined, msg: Json): Promise<Json | null> {
  if (!isObject(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(null, -32600, 'Invalid request');
  if (msg.id === undefined) return null;
  const id = msg.id;
  const params = isObject(msg.params) ? msg.params : {};
  const ok = (result: Json): JsonObject => ({ jsonrpc: '2.0', id, result });

  try {
    switch (msg.method) {
      case 'initialize': {
        const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
        return ok({
          protocolVersion: SUPPORTED_VERSIONS.includes(asked) ? asked : MCP_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'agentshield', version: '0.1.0' },
          instructions: 'Tool calls here are checked by AgentShield. A blocked call is final; do not retry it with altered arguments. A call that needs approval can be repeated unchanged once a person has approved it.',
        });
      }
      case 'ping':
        return ok({});
      case 'tools/list': {
        if (!taskId) return rpcError(id, -32602, 'A task id is required (X-AgentShield-Task header).');
        const tool = await shield.checkDrift(p.tenant_id, toolId);
        const grant = shield.grants.resolve(p.tenant_id, p.principal_id, taskId);
        if (!tool || tool.state !== 'approved' || !grant || !matchAny(grant.scope.tools, toolId)) return ok({ tools: [] });
        const tools = Object.entries(tool.manifest.operations)
          .filter(([name]) => matchAny(grant.scope.operations, name))
          .map(([name, op]) => ({ name, description: op.description ?? '', inputSchema: op.input_schema ?? { type: 'object' } }));
        return ok({ tools });
      }
      case 'tools/call': {
        if (!taskId) return rpcError(id, -32602, 'A task id is required (X-AgentShield-Task header).');
        if (typeof params.name !== 'string') return rpcError(id, -32602, 'Tool name is required.');
        const args: JsonObject = isObject(params.arguments) ? params.arguments : {};
        return ok(await callTool(shield, p, toolId, taskId, params.name, args));
      }
      default:
        return rpcError(id, -32601, `Method not found: ${msg.method}`);
    }
  } catch (err) {
    if (err instanceof ShieldError) return rpcError(id, -32000, err.message);
    return rpcError(id, -32603, 'Internal error');
  }
}

async function callTool(shield: Shield, p: Principal, toolId: string, taskId: string, name: string, args: JsonObject): Promise<JsonObject> {
  const tool = await shield.checkDrift(p.tenant_id, toolId);
  const op = tool && Object.hasOwn(tool.manifest.operations, name) ? tool.manifest.operations[name]! : null;

  // Resource and destination are derived from the reviewed manifest, the same way the policy will check them.
  const resourceArg = op?.resource_arg ? args[op.resource_arg] : undefined;
  const resourceId = typeof resourceArg === 'string' && resourceArg ? resourceArg : `${toolId}/${name}`;
  let destinationId = tool?.manifest.destination_id ?? toolId;
  if (op?.destination_arg) {
    const v = args[op.destination_arg];
    destinationId = destinationOf(Array.isArray(v) ? (v[0] ?? null) : (v ?? null), op.destination_from ?? 'value') ?? destinationId;
  }

  // The same call repeated while approval is pending must land on the same action, or the approval could never be used.
  const reuseKey = digest({ agent: p.principal_id, task: taskId, tool: toolId, name, args });
  const open = shield.intents.findOpenByReuseKey(p.tenant_id, reuseKey);
  const ttl = (shield.policies.active(p.tenant_id)?.bundle.limits.max_action_ttl_seconds ?? 300) * 1000;
  const envelope: JsonObject = {
    action_id: open?.action_id ?? newId('act'),
    task_id: taskId,
    tool_id: toolId,
    operation: name,
    resource_id: resourceId,
    destination_id: destinationId,
    arguments: args,
    nonce: open?.nonce ?? newId('non'),
    expires_at: open?.action.expires_at ?? iso(shield.clock.now() + ttl - 1000),
  };

  const { decision, execution } = await shield.run(p, envelope, { reuseKey });
  if (decision.decision === 'block') {
    return text(`Blocked by AgentShield: ${decision.reason} (decision ${decision.decision_id}). This is final for this action.`, true);
  }
  if (decision.decision === 'require_approval') {
    return text(`Approval required: ${decision.reason} (approval ${decision.approval_id}). After a person approves it, call this tool again with exactly the same arguments.`, true);
  }
  const ex = execution!;
  if (ex.state !== 'succeeded') {
    const out = text(`AgentShield: ${ex.error?.message ?? 'The tool call did not complete.'}`, true);
    if (isObject(ex.result) && Array.isArray(ex.result.content)) (out.content as Json[]).push(...ex.result.content);
    return out;
  }
  const meta: JsonObject = { 'agentshield/action_id': ex.action_id, 'agentshield/receipt': ex.receipt.event_id, 'agentshield/untrusted': ex.untrusted_content };
  if (ex.result_redacted) meta['agentshield/redacted'] = true;
  if (ex.injection) meta['agentshield/injection_score'] = ex.injection.score;
  const result: JsonObject =
    tool?.manifest.kind === 'mcp' && isObject(ex.result) && Array.isArray(ex.result.content)
      ? { ...ex.result }
      : { content: [{ type: 'text', text: typeof ex.result === 'string' ? ex.result : JSON.stringify(ex.result) }], ...(isObject(ex.result) ? { structuredContent: ex.result } : {}), isError: false };
  result._meta = { ...(isObject(result._meta) ? result._meta : {}), ...meta };
  if (ex.error) (result.content as Json[]).push({ type: 'text', text: `AgentShield: ${ex.error.message}` });
  return result;
}

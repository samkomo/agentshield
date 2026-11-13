/**
 * A small synthetic organisation used by the tests and the demo: one tenant,
 * a handful of mock tools that record every call they receive, a destination
 * catalog, resource labels and the default policy.
 *
 * The mock tools are the measuring instrument. A test passes because of what
 * did or did not reach `world.calls`, not because of what a response said.
 */
import { ephemeralKeys, type KeySet } from '../src/core/crypto.ts';
import type { Json, JsonObject } from '../src/core/json.ts';
import type { GrantScope, Principal, Role, ToolManifest } from '../src/core/types.ts';
import { Shield } from '../src/gateway/shield.ts';
import { DEFAULT_POLICY, signBundle, type PolicyBundle } from '../src/policy/bundle.ts';

export const TENANT = 'acme';

export interface World {
  shield: Shield;
  keys: KeySet;
  clock: { t: number; now(): number; advance(ms: number): void };
  admin: Principal;
  admin2: Principal;
  operator: Principal;
  approver: Principal;
  auditor: Principal;
  /** Every call that reached a mock tool. */
  calls: { tool: string; operation: string; args: JsonObject }[];
  /** Override what a mock tool returns or throws. */
  behavior: Map<string, (operation: string, args: JsonObject) => Json | Promise<Json>>;
  agent(id: string, sponsor?: string): Principal;
  grant(agentId: string, taskId: string, scope: Partial<GrantScope>, extra?: { budget_minor?: number; currency?: string; ttlMs?: number }): string;
  action(fields: Partial<JsonObject> & { task_id: string; tool_id: string; operation: string }): JsonObject;
}

const str = { type: 'string' };

export const TOOLS: ToolManifest[] = [
  {
    tool_id: 'email', kind: 'function', owner: 'it', destination_id: 'mail.internal',
    operations: {
      'email.send': {
        class: 'egress', effect: 'write', reversible: false, destination_arg: 'recipient', destination_from: 'email_domain', resource_arg: 'attachment',
        input_schema: { type: 'object', required: ['recipient', 'body', 'attachment'], additionalProperties: false, properties: { recipient: str, subject: str, body: str, attachment: str } },
      },
    },
  },
  {
    tool_id: 'browser', kind: 'function', owner: 'it', destination_id: 'browser.sandbox',
    operations: {
      'browser.upload': { class: 'egress', effect: 'write', reversible: false, destination_arg: 'url', destination_from: 'url_host', resource_arg: 'file' },
      'browser.read': { class: 'data_read', effect: 'read', destination_arg: 'url', destination_from: 'url_host' },
    },
  },
  {
    tool_id: 'invoice', kind: 'function', owner: 'finance', destination_id: 'finance.internal',
    operations: {
      'invoice.approve': { class: 'payment', effect: 'write', reversible: false, approval: 'always', destination_arg: 'beneficiary', resource_arg: 'invoice_id' },
    },
  },
  {
    tool_id: 'payment', kind: 'function', owner: 'finance', destination_id: 'agentpay.internal',
    operations: {
      'payment.execute': { class: 'payment', effect: 'write', reversible: false, destination_arg: 'beneficiary', resource_arg: 'wallet' },
    },
  },
  {
    tool_id: 'model', kind: 'function', owner: 'platform', destination_id: 'approved_model',
    operations: { 'model.infer': { class: 'model', effect: 'read', resource_arg: 'context_ref' } },
  },
  {
    tool_id: 'message', kind: 'function', owner: 'it', destination_id: 'chat.internal',
    operations: { 'message.send': { class: 'egress', effect: 'write', reversible: false, destination_arg: 'channel', resource_arg: 'source' } },
  },
  {
    tool_id: 'crm', kind: 'function', owner: 'sales', destination_id: 'crm.internal',
    operations: {
      'crm.read': { class: 'data_read', effect: 'read', resource_arg: 'customer_id' },
      'crm.export': { class: 'egress', effect: 'write', reversible: false, destination_arg: 'target', resource_arg: 'batch' },
    },
  },
  {
    tool_id: 'tenant', kind: 'function', owner: 'property', destination_id: 'property_db',
    operations: { 'tenant.update': { class: 'data_write', effect: 'write', reversible: true, resource_arg: 'tenant_id' } },
  },
  {
    tool_id: 'der', kind: 'function', owner: 'energy', destination_id: 'ot_controller',
    operations: {
      'der.setpoint': {
        class: 'physical', effect: 'write', reversible: true, resource_arg: 'inverter',
        input_schema: { type: 'object', required: ['inverter', 'setpoint_kw'], additionalProperties: false, properties: { inverter: str, setpoint_kw: { type: 'number', minimum: 0, maximum: 50 } } },
      },
    },
  },
  {
    tool_id: 'audit', kind: 'function', owner: 'security', destination_id: 'audit_store',
    operations: { 'audit.delete': { class: 'audit_admin', effect: 'write', reversible: false, resource_arg: 'event' } },
  },
  {
    tool_id: 'docs', kind: 'function', owner: 'it', destination_id: 'docs.internal',
    operations: { 'docs.read': { class: 'data_read', effect: 'read', resource_arg: 'path' } },
  },
];

const DESTINATIONS: [string, 'internal' | 'external', string, string[]][] = [
  ['mail.internal', 'internal', 'RESTRICTED', []],
  ['partner.example', 'external', 'CONFIDENTIAL', ['PII']],
  ['browser.sandbox', 'internal', 'INTERNAL', []],
  ['docs.example', 'external', 'PUBLIC', []],
  ['finance.internal', 'internal', 'RESTRICTED', []],
  ['supplier_verified', 'external', 'FINANCIAL', []],
  ['agentpay.internal', 'internal', 'RESTRICTED', []],
  ['merchant_42', 'external', 'FINANCIAL', []],
  ['approved_model', 'external', 'INTERNAL', []],
  ['chat.internal', 'internal', 'CONFIDENTIAL', []],
  ['team-research', 'internal', 'CONFIDENTIAL', []],
  ['crm.internal', 'internal', 'RESTRICTED', ['PII']],
  ['property_db', 'internal', 'RESTRICTED', ['PII']],
  ['ot_controller', 'internal', 'CRITICAL', []],
  ['audit_store', 'internal', 'RESTRICTED', []],
  ['docs.internal', 'internal', 'RESTRICTED', []],
];

const LABELS: [string, string[]][] = [
  ['report.pdf', ['CONFIDENTIAL']],
  ['private_notes.txt', ['CONFIDENTIAL']],
  ['research_notes', ['CONFIDENTIAL']],
  ['customer_*', ['RESTRICTED']],
  ['tenant_*', ['PERSONAL']],
  ['invoice_*', ['FINANCIAL']],
  ['wallet_*', ['FINANCIAL']],
  ['inverter_*', ['CRITICAL']],
  ['source_context', ['INTERNAL']],
  ['handbook.md', ['PUBLIC']],
];

let counter = 0;

export function makeWorld(opts: { policy?: PolicyBundle; twoPersonReview?: boolean; bare?: boolean } = {}): World {
  const clock = {
    t: Date.parse('2026-11-13T09:00:00Z'),
    now() {
      return this.t;
    },
    advance(ms: number) {
      this.t += ms;
    },
  };
  const keys = ephemeralKeys();
  const shield = new Shield({ keys, clock, twoPersonReview: opts.twoPersonReview ?? true, rateLimitPerMinute: 100_000 });
  const login = (id: string, role: Role, sponsor?: string): Principal =>
    shield.authenticate(shield.identity.createPrincipal(TENANT, id, role, { sponsor }))!;

  const admin = login('admin', 'admin');
  const admin2 = login('admin2', 'admin');
  const operator = login('security', 'operator');
  const approver = login('manager', 'approver');
  const auditor = login('auditor', 'auditor');
  const calls: World['calls'] = [];
  const behavior: World['behavior'] = new Map();

  if (!opts.bare) {
    const bundle = opts.policy ?? DEFAULT_POLICY;
    shield.createPolicy(admin, signBundle(keys.policySigner!, bundle));
    shield.activatePolicy(admin2, bundle.policy_id, bundle.version);
    for (const [destination_id, cls, max_label, accepts] of DESTINATIONS) {
      shield.catalog.setDestination(TENANT, { destination_id, class: cls, state: 'approved', max_label, accepts });
    }
    for (const [pattern, labels] of LABELS) shield.catalog.setResourceLabels(TENANT, pattern, labels);
    for (const manifest of TOOLS) {
      const { tool } = shield.registerTool(admin, manifest as unknown as Json);
      shield.tools.approve(TENANT, tool.tool_id, tool.schema_hash, operator.principal_id, true);
      shield.functions.register(manifest.tool_id, async (operation, args) => {
        calls.push({ tool: manifest.tool_id, operation, args });
        const custom = behavior.get(manifest.tool_id);
        return custom ? custom(operation, args) : { ok: true };
      });
    }
  }

  return {
    shield, keys, clock, admin, admin2, operator, approver, auditor, calls, behavior,
    agent: (id, sponsor = 'alice') => login(id, 'agent', sponsor),
    grant(agentId, taskId, scope, extra = {}) {
      return shield.createGrant(admin, {
        agent_id: agentId, task_id: taskId,
        scope: { tools: [], operations: [], resources: [], destinations: [], ...scope },
        budget_minor: extra.budget_minor ?? null, currency: extra.currency ?? null,
        expires_at: clock.now() + (extra.ttlMs ?? 3_600_000),
      }).grant_id;
    },
    action(fields) {
      const n = ++counter;
      return {
        action_id: `act_${n}`, resource_id: 'none', destination_id: 'none', arguments: {}, nonce: `nonce_${n}_abcdef`,
        expires_at: new Date(clock.now() + 300_000).toISOString(), ...fields,
      } as JsonObject;
    },
  };
}

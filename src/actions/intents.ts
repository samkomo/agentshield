/**
 * Action intents: the durable record of each action's journey.
 *
 *   pending ──► approved ──► reserved ──► executing ──► succeeded | failed | unknown
 *      │            │           │
 *      └────────────┴───────────┴──► denied | expired
 *
 * State changes are compare-and-set, so "reserved → executing" can succeed for
 * exactly one caller. That single transition is what makes a permit one-use.
 */
import { parseStrict, type Json } from '../core/json.ts';
import type { BoundAction, DecisionResponse } from '../core/types.ts';
import type { Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export type IntentState = 'pending' | 'denied' | 'approved' | 'reserved' | 'executing' | 'succeeded' | 'failed' | 'unknown' | 'expired';

export interface Intent {
  tenant_id: string;
  action_id: string;
  agent_id: string;
  task_id: string;
  nonce: string;
  idempotency_key: string | null;
  reuse_key: string | null;
  request_digest: string;
  action_digest: string;
  action: BoundAction;
  decision_id: string;
  decision: string;
  response: DecisionResponse;
  state: IntentState;
  policy_id: string | null;
  policy_version: number | null;
  grant_id: string | null;
  grant_revision: number | null;
  approval_id: string | null;
  permit_jti: string | null;
  expires_at: number;
  created_at: number;
  updated_at: number;
}

function hydrate(r: Record<string, unknown>): Intent {
  return {
    ...(r as unknown as Intent),
    action: parseStrict(r.action as string) as unknown as BoundAction,
    response: parseStrict(r.response as string) as unknown as DecisionResponse,
  };
}

export class Intents {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  get(tenant: string, actionId: string): Intent | undefined {
    const r = this.store.get('SELECT * FROM action_intents WHERE tenant_id=? AND action_id=?', tenant, actionId);
    return r ? hydrate(r) : undefined;
  }

  /** An open (not yet executed) intent the MCP proxy created for the same call, so a retry after approval lands on it. */
  findOpenByReuseKey(tenant: string, reuseKey: string): Intent | undefined {
    const r = this.store.get(
      `SELECT * FROM action_intents WHERE tenant_id=? AND reuse_key=? AND state IN ('pending','approved') AND expires_at>? ORDER BY created_at DESC LIMIT 1`,
      tenant, reuseKey, this.clock.now(),
    );
    return r ? hydrate(r) : undefined;
  }

  /** Throws a UNIQUE violation when the nonce or idempotency key has been seen before. */
  insert(i: Omit<Intent, 'created_at' | 'updated_at'>): void {
    const now = this.clock.now();
    this.store.run(
      `INSERT INTO action_intents (tenant_id, action_id, agent_id, task_id, nonce, idempotency_key, reuse_key, request_digest, action_digest, action,
         decision_id, decision, response, state, policy_id, policy_version, grant_id, grant_revision, approval_id, permit_jti, expires_at, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      i.tenant_id, i.action_id, i.agent_id, i.task_id, i.nonce, i.idempotency_key, i.reuse_key, i.request_digest, i.action_digest,
      JSON.stringify(i.action), i.decision_id, i.decision, JSON.stringify(i.response), i.state, i.policy_id, i.policy_version,
      i.grant_id, i.grant_revision, i.approval_id, i.permit_jti, i.expires_at, now, now,
    );
  }

  /** Overwrite the decision fields of an intent that is still awaiting approval. */
  redecide(i: Pick<Intent, 'tenant_id' | 'action_id' | 'action_digest' | 'action' | 'decision_id' | 'decision' | 'response' | 'state' | 'policy_id' | 'policy_version' | 'grant_id' | 'grant_revision' | 'approval_id' | 'permit_jti'>): void {
    this.store.run(
      `UPDATE action_intents SET action_digest=?, action=?, decision_id=?, decision=?, response=?, state=?, policy_id=?, policy_version=?,
         grant_id=?, grant_revision=?, approval_id=?, permit_jti=?, updated_at=? WHERE tenant_id=? AND action_id=?`,
      i.action_digest, JSON.stringify(i.action), i.decision_id, i.decision, JSON.stringify(i.response), i.state, i.policy_id, i.policy_version,
      i.grant_id, i.grant_revision, i.approval_id, i.permit_jti, this.clock.now(), i.tenant_id, i.action_id,
    );
  }

  /** Compare-and-set. Returns true only for the caller that made the transition. */
  transition(tenant: string, actionId: string, from: IntentState | IntentState[], to: IntentState): boolean {
    const states = Array.isArray(from) ? from : [from];
    return this.store.run(
      `UPDATE action_intents SET state=?, updated_at=? WHERE tenant_id=? AND action_id=? AND state IN (${states.map(() => '?').join(',')})`,
      to, this.clock.now(), tenant, actionId, ...states,
    ) > 0;
  }

  recentCount(tenant: string, agentId: string, sinceMs: number, deniedOnly = false): number {
    const r = this.store.get<{ n: number }>(
      `SELECT COUNT(*) AS n FROM action_intents WHERE tenant_id=? AND agent_id=? AND created_at>? ${deniedOnly ? "AND state='denied'" : ''}`,
      tenant, agentId, sinceMs,
    );
    return r?.n ?? 0;
  }

  /** Actions that reached an external system and never reported back. These need a human or a provider lookup, not a retry. */
  unresolved(tenant: string): Intent[] {
    return this.store.all(`SELECT * FROM action_intents WHERE tenant_id=? AND state IN ('executing','unknown') ORDER BY updated_at`, tenant).map(hydrate);
  }

  /** Expire permits and approvals nobody used, returning the affected action ids so their budget can be released. */
  expireStale(): { tenant_id: string; action_id: string }[] {
    const now = this.clock.now();
    const rows = this.store.all<{ tenant_id: string; action_id: string }>(
      `SELECT tenant_id, action_id FROM action_intents WHERE state IN ('pending','approved','reserved') AND expires_at<=?`, now,
    );
    this.store.run(`UPDATE action_intents SET state='expired', updated_at=? WHERE state IN ('pending','approved','reserved') AND expires_at<=?`, now, now);
    return rows;
  }
}

export type { Json };

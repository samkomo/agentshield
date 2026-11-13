/**
 * Task grants and delegation.
 *
 * A grant says what one agent may do for one task. A child grant can only
 * narrow its parent: every pattern must be covered by a parent pattern, limits
 * can only shrink, expiry can only come sooner, and the budget is not a new
 * pot of money — a child's spending is counted against every ancestor too
 * (see budget/ledger.ts). That is the non-amplification invariant.
 */
import { parseStrict, type Json } from '../core/json.ts';
import type { Grant, GrantScope } from '../core/types.ts';
import { ShieldError, isValidPattern, newId, patternCovered, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export interface GrantRequest {
  agent_id: string;
  task_id: string;
  scope: GrantScope;
  budget_minor?: number | null;
  currency?: string | null;
  expires_at: string | number;
  sponsor?: string;
}

function rowToGrant(r: Record<string, unknown>): Grant {
  return { ...(r as unknown as Grant), scope: parseStrict(r.scope as string) as unknown as GrantScope };
}

function invalid(msg: string): never {
  throw new ShieldError(422, 'invalid_grant', msg);
}

function normalizeScope(scope: GrantScope): GrantScope {
  if (typeof scope !== 'object' || scope === null) invalid('scope is required.');
  const out: GrantScope = { tools: [], operations: [], resources: [], destinations: [] };
  for (const k of ['tools', 'operations', 'resources', 'destinations'] as const) {
    const list = scope[k];
    if (!Array.isArray(list) || !list.every(isValidPattern)) invalid(`scope.${k} must be a list of literals or prefix* patterns.`);
    out[k] = [...new Set(list)].sort();
  }
  if (scope.max_per_action_minor !== undefined) {
    if (!Number.isSafeInteger(scope.max_per_action_minor) || scope.max_per_action_minor < 0) invalid('scope.max_per_action_minor must be a non-negative integer in minor units.');
    out.max_per_action_minor = scope.max_per_action_minor;
  }
  if (scope.max_delegation_depth !== undefined) {
    if (!Number.isSafeInteger(scope.max_delegation_depth) || scope.max_delegation_depth < 0) invalid('scope.max_delegation_depth must be a non-negative integer.');
    out.max_delegation_depth = scope.max_delegation_depth;
  }
  return out;
}

/** Every way `child` asks for more than `parent` has. Empty means the child is a subset. */
export function attenuationViolations(parent: Grant, child: { scope: GrantScope; budget_minor: number | null; currency: string | null; expires_at: number }): string[] {
  const v: string[] = [];
  for (const k of ['tools', 'operations', 'resources', 'destinations'] as const) {
    const extra = child.scope[k].filter((p) => !patternCovered(p, parent.scope[k]));
    if (extra.length) v.push(`${k} not held by parent: ${extra.join(', ')}`);
  }
  const pCap = parent.scope.max_per_action_minor;
  const cCap = child.scope.max_per_action_minor;
  if (cCap !== undefined && (pCap === undefined || cCap > pCap)) v.push('per-action limit exceeds parent');
  if (child.budget_minor !== null) {
    if (parent.budget_minor === null) v.push('parent has no budget to share');
    else if (child.budget_minor > parent.budget_minor) v.push('budget exceeds parent');
    if (parent.currency !== child.currency) v.push('currency differs from parent');
  }
  if (child.expires_at > parent.expires_at) v.push('expiry is later than parent');
  const remaining = parent.scope.max_delegation_depth ?? 0;
  if (remaining < 1) v.push('parent may not delegate');
  else if ((child.scope.max_delegation_depth ?? 0) > remaining - 1) v.push('delegation depth exceeds what parent may pass on');
  return v;
}

export class Grants {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  private parse(tenant: string, req: GrantRequest) {
    if (typeof req?.agent_id !== 'string' || typeof req.task_id !== 'string' || !req.task_id) invalid('agent_id and task_id are required.');
    if (!this.store.get('SELECT 1 FROM agents WHERE tenant_id=? AND agent_id=?', tenant, req.agent_id)) invalid('agent_id is not a registered agent.');
    const expires = typeof req.expires_at === 'number' ? req.expires_at : Date.parse(req.expires_at);
    if (!Number.isFinite(expires) || expires <= this.clock.now()) invalid('expires_at must be a future time.');
    const budget = req.budget_minor ?? null;
    if (budget !== null && (!Number.isSafeInteger(budget) || budget < 0)) invalid('budget_minor must be a non-negative integer in minor units.');
    const currency = req.currency ?? null;
    if (budget !== null && !/^[A-Z]{3}$/.test(currency ?? '')) invalid('currency must be a three-letter code when a budget is set.');
    const scope = normalizeScope(req.scope);
    return { scope, budget, currency, expires };
  }

  private insert(g: Omit<Grant, 'revision' | 'status'>): Grant {
    this.store.run(
      `INSERT INTO grants (tenant_id, grant_id, agent_id, task_id, parent_grant_id, path, depth, scope, budget_minor, currency, sponsor, expires_at, created_by, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      g.tenant_id, g.grant_id, g.agent_id, g.task_id, g.parent_grant_id, g.path, g.depth, JSON.stringify(g.scope),
      g.budget_minor, g.currency, g.sponsor, g.expires_at, g.created_by, g.created_at,
    );
    return this.get(g.tenant_id, g.grant_id)!;
  }

  /** A top-level grant, issued by an administrator on behalf of a human sponsor. */
  createRoot(tenant: string, req: GrantRequest, createdBy: string): Grant {
    const { scope, budget, currency, expires } = this.parse(tenant, req);
    if (scope.max_per_action_minor !== undefined && budget === null) invalid('a per-action limit needs a budget.');
    const grantId = newId('grt');
    return this.insert({
      tenant_id: tenant, grant_id: grantId, agent_id: req.agent_id, task_id: req.task_id, parent_grant_id: null,
      path: `/${grantId}/`, depth: 0, scope, budget_minor: budget, currency, sponsor: req.sponsor ?? createdBy,
      expires_at: expires, created_by: createdBy, created_at: this.clock.now(),
    });
  }

  /**
   * A parent agent hands part of its grant to another agent. Throws
   * `delegation_denied` with the list of violations if the child would hold
   * anything the parent does not.
   */
  delegate(tenant: string, parentAgent: string, parentTask: string, req: GrantRequest, maxDepth: number): Grant {
    return this.store.tx(() => {
      const parent = this.resolve(tenant, parentAgent, parentTask);
      if (!parent) throw new ShieldError(403, 'delegation_denied', 'No active grant to delegate from.', { violations: ['no active parent grant'] });
      const { scope, budget, currency, expires } = this.parse(tenant, req);
      const violations = attenuationViolations(parent, { scope, budget_minor: budget, currency, expires_at: expires });
      if (parent.depth + 1 > maxDepth) violations.push('delegation chain is too deep');
      if (violations.length) {
        throw new ShieldError(403, 'delegation_denied', 'Child scope is not a subset of the parent grant.', { violations });
      }
      const grantId = newId('grt');
      return this.insert({
        tenant_id: tenant, grant_id: grantId, agent_id: req.agent_id, task_id: req.task_id, parent_grant_id: parent.grant_id,
        path: `${parent.path}${grantId}/`, depth: parent.depth + 1, scope, budget_minor: budget, currency, sponsor: parent.sponsor,
        expires_at: expires, created_by: parentAgent, created_at: this.clock.now(),
      });
    });
  }

  get(tenant: string, grantId: string): Grant | undefined {
    const r = this.store.get('SELECT * FROM grants WHERE tenant_id=? AND grant_id=?', tenant, grantId);
    return r ? rowToGrant(r) : undefined;
  }

  list(tenant: string, agentId?: string): Grant[] {
    const rows = agentId
      ? this.store.all('SELECT * FROM grants WHERE tenant_id=? AND agent_id=? ORDER BY created_at DESC', tenant, agentId)
      : this.store.all('SELECT * FROM grants WHERE tenant_id=? ORDER BY created_at DESC', tenant);
    return rows.map(rowToGrant);
  }

  /** This grant and its ancestors, root first. */
  chain(grant: Grant): Grant[] {
    const ids = grant.path.split('/').filter(Boolean);
    return ids.map((id) => this.get(grant.tenant_id, id)!).filter(Boolean);
  }

  /** A grant is usable only while it and every ancestor are active and unexpired. */
  isLive(grant: Grant): boolean {
    const now = this.clock.now();
    const chain = this.chain(grant);
    return chain.length === grant.depth + 1 && chain.every((g) => g.status === 'active' && g.expires_at > now);
  }

  /** The grant covering this agent and task, preferring one issued for the exact task over a wildcard. */
  resolve(tenant: string, agentId: string, taskId: string): Grant | null {
    const rows = this.store.all(
      `SELECT * FROM grants WHERE tenant_id=? AND agent_id=? AND (task_id=? OR task_id='*') AND status='active' AND expires_at>?
       ORDER BY (task_id=?) DESC, created_at DESC`,
      tenant, agentId, taskId, this.clock.now(), taskId,
    );
    for (const r of rows) {
      const g = rowToGrant(r);
      if (this.isLive(g)) return g;
    }
    return null;
  }

  /** Revoking a grant also cuts off everything delegated from it, because liveness is checked up the chain. */
  revoke(tenant: string, grantId: string): Grant {
    const changed = this.store.run(`UPDATE grants SET status='revoked', revision=revision+1 WHERE tenant_id=? AND grant_id=? AND status='active'`, tenant, grantId);
    const g = this.get(tenant, grantId);
    if (!g) throw new ShieldError(404, 'grant_not_found', 'No such grant.');
    if (!changed) throw new ShieldError(409, 'grant_not_active', 'Grant is already revoked.');
    return g;
  }
}

export type { Json };

/**
 * Human approval, bound to one exact action.
 *
 * An approval names an action digest. It is good for that digest only, once,
 * until it expires. If the action changes by a single byte — or the tool it
 * targets is re-registered — the digest changes and the approval no longer
 * applies. Approvers never see "allow email"; they see the action itself.
 */
import { ShieldError, newId, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export interface Approval {
  tenant_id: string;
  approval_id: string;
  action_id: string;
  decision_id: string;
  action_digest: string;
  requested_by: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'consumed' | 'superseded';
  decided_by: string | null;
  decided_at: number | null;
  reason: string | null;
  expires_at: number;
  created_at: number;
}

export class Approvals {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  /** Read an approval, lazily marking it expired. */
  get(tenant: string, approvalId: string): Approval | undefined {
    const a = this.store.get<Approval>('SELECT * FROM approvals WHERE tenant_id=? AND approval_id=?', tenant, approvalId);
    if (a && (a.status === 'pending' || a.status === 'approved') && a.expires_at <= this.clock.now()) {
      this.store.run(`UPDATE approvals SET status='expired' WHERE tenant_id=? AND approval_id=?`, tenant, approvalId);
      a.status = 'expired';
    }
    return a;
  }

  list(tenant: string, status?: string): Approval[] {
    const rows = status
      ? this.store.all<Approval>('SELECT * FROM approvals WHERE tenant_id=? AND status=? ORDER BY created_at DESC LIMIT 200', tenant, status)
      : this.store.all<Approval>('SELECT * FROM approvals WHERE tenant_id=? ORDER BY created_at DESC LIMIT 200', tenant);
    return rows.map((a) => this.get(tenant, a.approval_id)!);
  }

  /** Open a request for this digest, superseding any earlier request for the same action. */
  request(tenant: string, actionId: string, decisionId: string, actionDigest: string, requestedBy: string, ttlMs: number): Approval {
    return this.store.tx(() => {
      this.store.run(`UPDATE approvals SET status='superseded' WHERE tenant_id=? AND action_id=? AND status IN ('pending','approved')`, tenant, actionId);
      const id = newId('apr');
      const now = this.clock.now();
      this.store.run(
        `INSERT INTO approvals (tenant_id, approval_id, action_id, decision_id, action_digest, requested_by, status, expires_at, created_at)
         VALUES (?,?,?,?,?,?,'pending',?,?)`,
        tenant, id, actionId, decisionId, actionDigest, requestedBy, now + ttlMs, now,
      );
      return this.get(tenant, id)!;
    });
  }

  /**
   * Record a human decision. The approver states the digest they reviewed;
   * if it is not the digest on file, they were shown something else.
   */
  decide(tenant: string, approvalId: string, approver: string, verdict: 'approve' | 'reject', reviewedDigest: string, reason?: string): Approval {
    return this.store.tx(() => {
      const a = this.get(tenant, approvalId);
      if (!a) throw new ShieldError(404, 'approval_not_found', 'No such approval.');
      if (a.status !== 'pending') throw new ShieldError(409, 'approval_not_pending', `Approval is ${a.status}.`);
      if (a.requested_by === approver) throw new ShieldError(403, 'self_approval', 'The requester cannot approve their own action.');
      if (a.action_digest !== reviewedDigest) throw new ShieldError(409, 'digest_mismatch', 'The action you reviewed is not the action awaiting approval.');
      this.store.run(
        `UPDATE approvals SET status=?, decided_by=?, decided_at=?, reason=? WHERE tenant_id=? AND approval_id=?`,
        verdict === 'approve' ? 'approved' : 'rejected', approver, this.clock.now(), reason ?? null, tenant, approvalId,
      );
      return this.get(tenant, approvalId)!;
    });
  }

  /** Spend an approval. Returns false unless it is approved, unexpired and for exactly this digest. */
  consume(tenant: string, approvalId: string, actionDigest: string): boolean {
    return this.store.run(
      `UPDATE approvals SET status='consumed' WHERE tenant_id=? AND approval_id=? AND status='approved' AND action_digest=? AND expires_at>?`,
      tenant, approvalId, actionDigest, this.clock.now(),
    ) > 0;
  }
}

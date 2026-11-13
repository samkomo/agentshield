/**
 * Atomic budget reservations.
 *
 * A policy snapshot that says "there is enough left" is not a control: two
 * requests can both read the same balance. The reservation is the control. It
 * checks and writes inside one write transaction, and it counts against the
 * acting grant and every ancestor, so sibling agents cannot each spend the
 * parent's whole budget.
 *
 * Reserved and committed amounts both count as spent. An action whose outcome
 * is unknown keeps its reservation until someone reconciles it.
 */
import type { Grant } from '../core/types.ts';
import { ShieldError, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export class Ledger {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  /** Amount reserved or committed under this grant and everything delegated from it. */
  spent(grant: Grant): number {
    const r = this.store.get<{ total: number | null }>(
      `SELECT SUM(amount_minor) AS total FROM budget_reservations
       WHERE tenant_id=? AND state IN ('reserved','committed') AND substr(grant_path, 1, ?) = ?`,
      grant.tenant_id, grant.path.length, grant.path,
    );
    return r?.total ?? 0;
  }

  /** The tightest remaining headroom across the chain; null if no grant in the chain carries a budget. */
  remaining(chain: Grant[]): number | null {
    let min: number | null = null;
    for (const g of chain) {
      if (g.budget_minor === null) continue;
      const left = g.budget_minor - this.spent(g);
      if (min === null || left < min) min = left;
    }
    return min;
  }

  /** Reserve or throw `budget_exceeded`. Must be called inside the transaction that issues the permit. */
  reserve(chain: Grant[], actionId: string, amountMinor: number, currency: string): void {
    const leaf = chain[chain.length - 1]!;
    this.store.tx(() => {
      for (const g of chain) {
        if (g.budget_minor === null) continue;
        if (g.currency !== currency || this.spent(g) + amountMinor > g.budget_minor) {
          throw new ShieldError(403, 'budget_exceeded', 'Amount exceeds the remaining shared budget.');
        }
      }
      const now = this.clock.now();
      this.store.run(
        `INSERT INTO budget_reservations (tenant_id, action_id, grant_id, grant_path, amount_minor, currency, state, created_at, updated_at)
         VALUES (?,?,?,?,?,?,'reserved',?,?)`,
        leaf.tenant_id, actionId, leaf.grant_id, leaf.path, amountMinor, currency, now, now,
      );
    });
  }

  private settle(tenant: string, actionId: string, state: 'committed' | 'released'): boolean {
    return this.store.run(
      `UPDATE budget_reservations SET state=?, updated_at=? WHERE tenant_id=? AND action_id=? AND state='reserved'`,
      state, this.clock.now(), tenant, actionId,
    ) > 0;
  }
  commit(tenant: string, actionId: string): boolean {
    return this.settle(tenant, actionId, 'committed');
  }
  release(tenant: string, actionId: string): boolean {
    return this.settle(tenant, actionId, 'released');
  }
}

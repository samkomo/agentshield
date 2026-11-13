/**
 * Trusted metadata the policy reads: where data may go, how sensitive a
 * resource is, and what a task has already been exposed to.
 *
 * None of this is supplied by the agent. Destinations and resource labels are
 * set by an administrator; task context is accumulated by the gateway from
 * what it has itself scanned.
 */
import { parseStrict } from '../core/json.ts';
import type { Destination, TaskContext } from '../core/types.ts';
import { ShieldError, isValidPattern, matchPattern, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export class Catalog {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  setDestination(tenant: string, d: Omit<Destination, 'tenant_id'>): Destination {
    if (typeof d?.destination_id !== 'string' || !d.destination_id) throw new ShieldError(422, 'invalid_destination', 'destination_id is required.');
    if (d.class !== 'internal' && d.class !== 'external') throw new ShieldError(422, 'invalid_destination', 'class must be internal or external.');
    if (!['approved', 'unreviewed', 'blocked'].includes(d.state)) throw new ShieldError(422, 'invalid_destination', 'state must be approved, unreviewed or blocked.');
    if (typeof d.max_label !== 'string' || !d.max_label) throw new ShieldError(422, 'invalid_destination', 'max_label is required.');
    const accepts = Array.isArray(d.accepts) ? d.accepts.filter((a) => typeof a === 'string') : [];
    this.store.run(
      `INSERT INTO destinations (tenant_id, destination_id, class, state, max_label, accepts) VALUES (?,?,?,?,?,?)
       ON CONFLICT (tenant_id, destination_id) DO UPDATE SET class=excluded.class, state=excluded.state, max_label=excluded.max_label, accepts=excluded.accepts`,
      tenant, d.destination_id, d.class, d.state, d.max_label, JSON.stringify(accepts),
    );
    return this.destination(tenant, d.destination_id)!;
  }

  destination(tenant: string, destinationId: string): Destination | null {
    const r = this.store.get('SELECT * FROM destinations WHERE tenant_id=? AND destination_id=?', tenant, destinationId);
    return r ? { ...(r as unknown as Destination), accepts: parseStrict(r.accepts as string) as string[] } : null;
  }

  listDestinations(tenant: string): Destination[] {
    return this.store
      .all('SELECT * FROM destinations WHERE tenant_id=? ORDER BY destination_id', tenant)
      .map((r) => ({ ...(r as unknown as Destination), accepts: parseStrict(r.accepts as string) as string[] }));
  }

  setResourceLabels(tenant: string, pattern: string, labels: string[]): void {
    if (!isValidPattern(pattern)) throw new ShieldError(422, 'invalid_pattern', 'pattern must be a literal or prefix*.');
    if (!Array.isArray(labels) || labels.some((l) => typeof l !== 'string' || !l)) throw new ShieldError(422, 'invalid_labels', 'labels must be a list of strings.');
    if (!labels.length) {
      this.store.run('DELETE FROM resource_labels WHERE tenant_id=? AND pattern=?', tenant, pattern);
      return;
    }
    this.store.run(
      `INSERT INTO resource_labels (tenant_id, pattern, labels) VALUES (?,?,?)
       ON CONFLICT (tenant_id, pattern) DO UPDATE SET labels=excluded.labels`,
      tenant, pattern, JSON.stringify(labels),
    );
  }

  /** Union of the labels of every pattern that matches. */
  labelsFor(tenant: string, resourceId: string): string[] {
    const out = new Set<string>();
    for (const r of this.store.all('SELECT pattern, labels FROM resource_labels WHERE tenant_id=?', tenant)) {
      if (matchPattern(r.pattern as string, resourceId)) for (const l of parseStrict(r.labels as string) as string[]) out.add(l);
    }
    return [...out].sort();
  }

  listResourceLabels(tenant: string): { pattern: string; labels: string[] }[] {
    return this.store
      .all('SELECT pattern, labels FROM resource_labels WHERE tenant_id=? ORDER BY pattern', tenant)
      .map((r) => ({ pattern: r.pattern as string, labels: parseStrict(r.labels as string) as string[] }));
  }

  task(tenant: string, taskId: string): TaskContext {
    const r = this.store.get('SELECT * FROM task_context WHERE tenant_id=? AND task_id=?', tenant, taskId);
    if (!r) return { labels: [], untrusted_sources: 0, max_injection: 0 };
    return { labels: parseStrict(r.labels as string) as string[], untrusted_sources: r.untrusted_sources as number, max_injection: r.max_injection as number };
  }

  /** Task context only ever accumulates. Nothing an agent does later can lower what the task has seen. */
  recordExposure(tenant: string, taskId: string, e: { labels?: string[]; untrusted?: boolean; injection?: number }): TaskContext {
    return this.store.tx(() => {
      const cur = this.task(tenant, taskId);
      const next: TaskContext = {
        labels: [...new Set([...cur.labels, ...(e.labels ?? [])])].sort(),
        untrusted_sources: cur.untrusted_sources + (e.untrusted ? 1 : 0),
        max_injection: Math.max(cur.max_injection, e.injection ?? 0),
      };
      this.store.run(
        `INSERT INTO task_context (tenant_id, task_id, labels, untrusted_sources, max_injection, updated_at) VALUES (?,?,?,?,?,?)
         ON CONFLICT (tenant_id, task_id) DO UPDATE SET labels=excluded.labels, untrusted_sources=excluded.untrusted_sources,
           max_injection=excluded.max_injection, updated_at=excluded.updated_at`,
        tenant, taskId, JSON.stringify(next.labels), next.untrusted_sources, next.max_injection, this.clock.now(),
      );
      return next;
    });
  }
}

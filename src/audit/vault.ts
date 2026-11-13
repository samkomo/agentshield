/**
 * Local vault for reversible redaction mappings.
 *
 * When a value is replaced by a placeholder, the original is sealed here —
 * encrypted, scoped to the task and action, and short-lived. It never appears
 * in a response, an event or a log. Reading it back needs a separate
 * permission that agents do not hold.
 */
import { seal, unseal } from '../core/crypto.ts';
import type { Replacement } from '../detect/redact.ts';
import type { Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export class Vault {
  private store: Store;
  private key: Buffer;
  private clock: Clock;
  constructor(store: Store, key: Buffer, clock: Clock) {
    this.store = store;
    this.key = key;
    this.clock = clock;
  }

  private aad(tenant: string, task: string, scopeRef: string, placeholder: string): string {
    return [tenant, task, scopeRef, placeholder].join('\0');
  }

  put(tenant: string, task: string, scopeRef: string, replacements: Replacement[], ttlMs: number): void {
    const expires = this.clock.now() + ttlMs;
    for (const r of replacements) {
      this.store.run(
        `INSERT INTO vault (tenant_id, task_id, scope_ref, placeholder, sealed, expires_at) VALUES (?,?,?,?,?,?)
         ON CONFLICT (tenant_id, task_id, scope_ref, placeholder) DO UPDATE SET sealed=excluded.sealed, expires_at=excluded.expires_at`,
        tenant, task, scopeRef, r.placeholder, seal(this.key, r.original, this.aad(tenant, task, scopeRef, r.placeholder)), expires,
      );
    }
  }

  reveal(tenant: string, task: string, scopeRef: string, placeholder: string): string | null {
    const r = this.store.get<{ sealed: string }>(
      'SELECT sealed FROM vault WHERE tenant_id=? AND task_id=? AND scope_ref=? AND placeholder=? AND expires_at>?',
      tenant, task, scopeRef, placeholder, this.clock.now(),
    );
    return r ? unseal(this.key, r.sealed, this.aad(tenant, task, scopeRef, placeholder)) : null;
  }

  purgeExpired(): number {
    return this.store.run('DELETE FROM vault WHERE expires_at<=?', this.clock.now());
  }
}

/**
 * Append-only, hash-chained, signed security events.
 *
 * Each event carries the digest of the one before it and is signed with the
 * event key. Editing or removing an event in the middle breaks the chain.
 * Removing the tail does not — a chain cannot vouch for what comes after its
 * last link — so `checkpoint` exports a signed (sequence, digest) pair to a
 * sink the gateway's own database cannot rewrite. Verification against those
 * checkpoints is what detects truncation.
 *
 * Events are metadata only: pseudonymous references, categories, digests,
 * outcomes. No payloads, no matched text, no credentials.
 */
import { appendFileSync } from 'node:fs';
import { pseudonym, signDetached, verifyDetached, type SigningKey } from '../core/crypto.ts';
import { canonicalize, parseStrict, sha256Hex, type Json, type JsonObject } from '../core/json.ts';
import { iso, newId, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export const GENESIS = `sha256:${'0'.repeat(64)}`;

export interface EventInput {
  event_type: string;
  agent_id?: string | null;
  action_id?: string | null;
  decision_id?: string | null;
  policy_version?: number | null;
  grant_revision?: number | null;
  tool_revision?: string | null;
  finding_categories?: string[];
  latency_ms?: number;
  detail?: JsonObject;
}

export interface SecurityEvent extends JsonObject {
  event_id: string;
  tenant_id: string;
  sequence: number;
  event_type: string;
  agent_ref: string | null;
  action_id: string | null;
  decision_id: string | null;
  policy_version: number | null;
  grant_revision: number | null;
  tool_revision: string | null;
  finding_categories: string[];
  latency_ms: number | null;
  detail: JsonObject;
  timestamp: string;
  previous_digest: string;
}

export interface StoredEvent extends SecurityEvent {
  event_digest: string;
  signature: string;
}

export interface Checkpoint {
  tenant_id: string;
  sequence: number;
  event_digest: string;
  timestamp: string;
  key_id: string;
  signature: string;
}

export interface ChainReport {
  ok: boolean;
  events: number;
  head: { sequence: number; event_digest: string } | null;
  error: { sequence: number; problem: string } | null;
}

export class AuditLog {
  private store: Store;
  private key: SigningKey;
  private telemetryKey: Buffer;
  private clock: Clock;
  private sink: string | null;
  private checkpointed = new Map<string, number>();

  constructor(store: Store, key: SigningKey, telemetryKey: Buffer, clock: Clock, checkpointSink: string | null) {
    this.store = store;
    this.key = key;
    this.telemetryKey = telemetryKey;
    this.clock = clock;
    this.sink = checkpointSink;
  }

  ref(tenant: string, value: string): string {
    return pseudonym(this.telemetryKey, tenant, value);
  }

  /**
   * Append one event. Call it inside the transaction that makes the change
   * it records: if the event cannot be written, the change does not happen.
   */
  append(tenant: string, input: EventInput): StoredEvent {
    return this.store.tx(() => {
      const last = this.store.get<{ sequence: number; event_digest: string }>(
        'SELECT sequence, event_digest FROM events WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1', tenant,
      );
      const body: SecurityEvent = {
        event_id: newId('evt'),
        tenant_id: tenant,
        sequence: (last?.sequence ?? 0) + 1,
        event_type: input.event_type,
        agent_ref: input.agent_id ? this.ref(tenant, input.agent_id) : null,
        action_id: input.action_id ?? null,
        decision_id: input.decision_id ?? null,
        policy_version: input.policy_version ?? null,
        grant_revision: input.grant_revision ?? null,
        tool_revision: input.tool_revision ?? null,
        finding_categories: input.finding_categories ?? [],
        latency_ms: input.latency_ms ?? null,
        detail: input.detail ?? {},
        timestamp: iso(this.clock.now()),
        previous_digest: last?.event_digest ?? GENESIS,
      };
      const canonical = canonicalize(body);
      const eventDigest = `sha256:${sha256Hex(canonical)}`;
      const signature = signDetached(this.key, eventDigest);
      this.store.run(
        `INSERT INTO events (tenant_id, sequence, event_id, event_type, agent_ref, action_id, body, event_digest, previous_digest, signature, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        tenant, body.sequence, body.event_id, body.event_type, body.agent_ref, body.action_id, canonical, eventDigest,
        body.previous_digest, signature, this.clock.now(),
      );
      return { ...body, event_digest: eventDigest, signature };
    });
  }

  private hydrate(r: Record<string, unknown>): StoredEvent {
    return { ...(parseStrict(r.body as string) as SecurityEvent), event_digest: r.event_digest as string, signature: r.signature as string };
  }

  get(tenant: string, eventId: string): StoredEvent | undefined {
    const r = this.store.get('SELECT * FROM events WHERE tenant_id=? AND event_id=?', tenant, eventId);
    return r ? this.hydrate(r) : undefined;
  }

  list(tenant: string, opts: { after?: number; limit?: number; agentId?: string; actionId?: string; type?: string } = {}): StoredEvent[] {
    const where = ['tenant_id=?', 'sequence>?'];
    const params: (string | number)[] = [tenant, opts.after ?? 0];
    if (opts.agentId) (where.push('agent_ref=?'), params.push(this.ref(tenant, opts.agentId)));
    if (opts.actionId) (where.push('action_id=?'), params.push(opts.actionId));
    if (opts.type) (where.push('event_type=?'), params.push(opts.type));
    params.push(Math.min(Math.max(opts.limit ?? 100, 1), 1000));
    return this.store.all(`SELECT * FROM events WHERE ${where.join(' AND ')} ORDER BY sequence LIMIT ?`, ...params).map((r) => this.hydrate(r));
  }

  /** Walk the whole chain: contiguous sequence, matching links, recomputed digests, valid signatures. */
  verify(tenant: string): ChainReport {
    let previous = GENESIS;
    let expected = 1;
    let head: ChainReport['head'] = null;
    const fail = (sequence: number, problem: string): ChainReport => ({ ok: false, events: expected - 1, head, error: { sequence, problem } });
    for (const r of this.store.db.prepare('SELECT * FROM events WHERE tenant_id=? ORDER BY sequence').iterate(tenant)) {
      const seq = r.sequence as number;
      if (seq !== expected) return fail(expected, `sequence gap: expected ${expected}, found ${seq}`);
      const body = r.body as string;
      const computed = `sha256:${sha256Hex(body)}`;
      if (computed !== r.event_digest) return fail(seq, 'event body does not match its digest');
      let parsed: SecurityEvent;
      try {
        parsed = parseStrict(body) as SecurityEvent;
      } catch {
        return fail(seq, 'event body is not valid JSON');
      }
      if (parsed.sequence !== seq || parsed.tenant_id !== tenant) return fail(seq, 'event body does not match its position');
      if (parsed.previous_digest !== previous || r.previous_digest !== previous) return fail(seq, 'broken link to previous event');
      if (!verifyDetached(this.key.publicKey, computed, r.signature as string)) return fail(seq, 'invalid signature');
      previous = computed;
      head = { sequence: seq, event_digest: computed };
      expected++;
    }
    return { ok: true, events: expected - 1, head, error: null };
  }

  /** Sign the current head and, if a sink is configured, append it there. */
  checkpoint(tenant: string): Checkpoint | null {
    const last = this.store.get<{ sequence: number; event_digest: string }>(
      'SELECT sequence, event_digest FROM events WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1', tenant,
    );
    if (!last) return null;
    const unsigned = { tenant_id: tenant, sequence: last.sequence, event_digest: last.event_digest, timestamp: iso(this.clock.now()), key_id: this.key.kid };
    const cp: Checkpoint = { ...unsigned, signature: signDetached(this.key, canonicalize(unsigned)) };
    if (this.sink) appendFileSync(this.sink, `${JSON.stringify(cp)}\n`);
    this.checkpointed.set(tenant, last.sequence);
    return cp;
  }

  /** Checkpoint every tenant whose chain has grown since its last checkpoint from this process. */
  checkpointAll(): number {
    let written = 0;
    for (const r of this.store.all<{ tenant_id: string; head: number }>('SELECT tenant_id, MAX(sequence) AS head FROM events GROUP BY tenant_id')) {
      if ((this.checkpointed.get(r.tenant_id) ?? 0) >= r.head) continue;
      if (this.checkpoint(r.tenant_id)) written++;
    }
    return written;
  }

  /**
   * Compare the stored chain with checkpoints held elsewhere. A checkpoint
   * whose sequence is missing, or present with a different digest, means
   * history was truncated or rewritten after the checkpoint was taken.
   */
  verifyCheckpoints(tenant: string, checkpoints: Checkpoint[]): { ok: boolean; checked: number; problems: string[] } {
    const problems: string[] = [];
    let checked = 0;
    for (const cp of checkpoints) {
      if (cp.tenant_id !== tenant) continue;
      checked++;
      const { signature, ...unsigned } = cp;
      if (!verifyDetached(this.key.publicKey, canonicalize(unsigned as unknown as Json), signature)) {
        problems.push(`checkpoint at ${cp.sequence}: invalid signature`);
        continue;
      }
      const r = this.store.get<{ event_digest: string }>('SELECT event_digest FROM events WHERE tenant_id=? AND sequence=?', tenant, cp.sequence);
      if (!r) problems.push(`checkpoint at ${cp.sequence}: event is missing (history truncated)`);
      else if (r.event_digest !== cp.event_digest) problems.push(`checkpoint at ${cp.sequence}: event differs (history rewritten)`);
    }
    return { ok: problems.length === 0, checked, problems };
  }

  counts(tenant: string, fromMs: number, toMs: number): Record<string, number> {
    const out: Record<string, number> = {};
    for (const r of this.store.all('SELECT event_type, COUNT(*) AS n FROM events WHERE tenant_id=? AND created_at>=? AND created_at<? GROUP BY event_type', tenant, fromMs, toMs)) {
      out[r.event_type as string] = r.n as number;
    }
    return out;
  }
}

/**
 * Local transactional state on SQLite (node:sqlite).
 *
 * The design calls for PostgreSQL in a multi-node deployment. For a
 * local-first gateway a single-file database gives the properties that
 * matter — serializable write transactions for budget reservation, unique
 * constraints for nonces, and the audit event written in the same transaction
 * as the decision it records — without a service to run. All access goes
 * through this class so the engine can be swapped.
 */
import { chmodSync, closeSync, openSync } from 'node:fs';
import { DatabaseSync, type SQLInputValue, type StatementSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS principals (
  tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, role TEXT NOT NULL,
  permissions TEXT NOT NULL, credential_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, principal_id)
);
CREATE TABLE IF NOT EXISTS agents (
  tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, display_name TEXT, sponsor TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  revocation_epoch INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, agent_id)
);
CREATE TABLE IF NOT EXISTS grants (
  tenant_id TEXT NOT NULL, grant_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
  parent_grant_id TEXT, path TEXT NOT NULL, depth INTEGER NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  scope TEXT NOT NULL, budget_minor INTEGER CHECK (budget_minor IS NULL OR budget_minor >= 0),
  currency TEXT, sponsor TEXT NOT NULL, expires_at INTEGER NOT NULL,
  created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, grant_id)
);
CREATE INDEX IF NOT EXISTS grants_lookup ON grants (tenant_id, agent_id, task_id);
CREATE TABLE IF NOT EXISTS budget_reservations (
  tenant_id TEXT NOT NULL, action_id TEXT NOT NULL, grant_id TEXT NOT NULL, grant_path TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0), currency TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved','committed','released')),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, action_id)
);
CREATE INDEX IF NOT EXISTS reservations_path ON budget_reservations (tenant_id, grant_path);
CREATE TABLE IF NOT EXISTS tools (
  tenant_id TEXT NOT NULL, tool_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','quarantined','revoked')),
  manifest TEXT NOT NULL, schema_hash TEXT NOT NULL,
  registered_by TEXT NOT NULL, verified_by TEXT, checked_at INTEGER, reason TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, tool_id)
);
CREATE TABLE IF NOT EXISTS destinations (
  tenant_id TEXT NOT NULL, destination_id TEXT NOT NULL,
  class TEXT NOT NULL CHECK (class IN ('internal','external')),
  state TEXT NOT NULL CHECK (state IN ('approved','unreviewed','blocked')),
  max_label TEXT NOT NULL, accepts TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (tenant_id, destination_id)
);
CREATE TABLE IF NOT EXISTS resource_labels (
  tenant_id TEXT NOT NULL, pattern TEXT NOT NULL, labels TEXT NOT NULL,
  PRIMARY KEY (tenant_id, pattern)
);
CREATE TABLE IF NOT EXISTS policies (
  tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, version INTEGER NOT NULL,
  bundle TEXT NOT NULL, bundle_digest TEXT NOT NULL, signature TEXT NOT NULL, key_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('draft','active','retired','revoked')),
  created_by TEXT NOT NULL, activated_by TEXT, created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, policy_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_policy ON policies (tenant_id) WHERE state = 'active';
CREATE TABLE IF NOT EXISTS action_intents (
  tenant_id TEXT NOT NULL, action_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
  nonce TEXT NOT NULL, idempotency_key TEXT, reuse_key TEXT,
  request_digest TEXT NOT NULL, action_digest TEXT NOT NULL, action TEXT NOT NULL,
  decision_id TEXT NOT NULL, decision TEXT NOT NULL, response TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','denied','approved','reserved','executing','succeeded','failed','unknown','expired')),
  policy_id TEXT, policy_version INTEGER, grant_id TEXT, grant_revision INTEGER,
  approval_id TEXT, permit_jti TEXT,
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, action_id),
  UNIQUE (tenant_id, nonce)
);
CREATE UNIQUE INDEX IF NOT EXISTS intents_idempotency ON action_intents (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS intents_agent ON action_intents (tenant_id, agent_id, created_at);
CREATE INDEX IF NOT EXISTS intents_reuse ON action_intents (tenant_id, reuse_key) WHERE reuse_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS approvals (
  tenant_id TEXT NOT NULL, approval_id TEXT NOT NULL, action_id TEXT NOT NULL, decision_id TEXT NOT NULL,
  action_digest TEXT NOT NULL, requested_by TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired','consumed','superseded')),
  decided_by TEXT, decided_at INTEGER, reason TEXT,
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, approval_id)
);
CREATE TABLE IF NOT EXISTS task_context (
  tenant_id TEXT NOT NULL, task_id TEXT NOT NULL, labels TEXT NOT NULL DEFAULT '[]',
  untrusted_sources INTEGER NOT NULL DEFAULT 0, max_injection REAL NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS vault (
  tenant_id TEXT NOT NULL, task_id TEXT NOT NULL, scope_ref TEXT NOT NULL, placeholder TEXT NOT NULL,
  sealed TEXT NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, task_id, scope_ref, placeholder)
);
CREATE TABLE IF NOT EXISTS events (
  tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL, agent_ref TEXT, action_id TEXT,
  body TEXT NOT NULL, event_digest TEXT NOT NULL, previous_digest TEXT NOT NULL, signature TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, sequence)
);
CREATE INDEX IF NOT EXISTS events_agent ON events (tenant_id, agent_ref, sequence);
CREATE INDEX IF NOT EXISTS events_action ON events (tenant_id, action_id);
`;

export type Row = Record<string, SQLInputValue>;

export class Store {
  readonly db: DatabaseSync;
  private statements = new Map<string, StatementSync>();
  private depth = 0;

  constructor(path = ':memory:') {
    if (path !== ':memory:') {
      // Owner-only before SQLite touches it; the -wal and -shm files inherit the main file's mode.
      closeSync(openSync(path, 'a', 0o600));
      chmodSync(path, 0o600);
    }
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
    if (path !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;');
    this.db.exec(SCHEMA);
  }

  private prepare(sql: string): StatementSync {
    let s = this.statements.get(sql);
    if (!s) {
      s = this.db.prepare(sql);
      this.statements.set(sql, s);
    }
    return s;
  }

  run(sql: string, ...params: SQLInputValue[]): number {
    return Number(this.prepare(sql).run(...params).changes);
  }

  get<T = Row>(sql: string, ...params: SQLInputValue[]): T | undefined {
    return this.prepare(sql).get(...params) as T | undefined;
  }

  all<T = Row>(sql: string, ...params: SQLInputValue[]): T[] {
    return this.prepare(sql).all(...params) as T[];
  }

  /**
   * Run `fn` in a write transaction. IMMEDIATE takes the write lock up front,
   * so a check-then-reserve inside `fn` cannot interleave with another writer
   * — including one in another process. Nested calls join the outer transaction.
   */
  tx<T>(fn: () => T): T {
    if (this.depth > 0) return fn();
    this.db.exec('BEGIN IMMEDIATE');
    this.depth++;
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    } finally {
      this.depth--;
    }
  }

  close(): void {
    this.statements.clear();
    this.db.close();
  }
}

export function isUniqueViolation(err: unknown): boolean {
  return err instanceof Error && /UNIQUE constraint failed/.test(err.message);
}

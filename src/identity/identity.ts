/**
 * Principals, the agent inventory and suspension.
 *
 * This is the built-in local identity provider. Tenant and principal come
 * from the credential on the transport and nowhere else. A deployment with
 * AgentIdentity or an enterprise IdP replaces `authenticate`; everything
 * downstream only sees a `Principal`.
 */
import { hashCredential, newCredential } from '../core/crypto.ts';
import { parseStrict } from '../core/json.ts';
import { ROLE_PERMISSIONS, type Permission, type Principal, type Role } from '../core/types.ts';
import { ShieldError, type Clock } from '../core/util.ts';
import { isUniqueViolation, type Store } from '../store/db.ts';

export interface AgentRecord {
  tenant_id: string;
  agent_id: string;
  display_name: string | null;
  sponsor: string;
  status: 'active' | 'suspended';
  revocation_epoch: number;
  created_at: number;
}

const ID = /^[A-Za-z0-9][\w.:@-]{0,127}$/;

export class Identity {
  private store: Store;
  private clock: Clock;
  constructor(store: Store, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }

  /** Create a principal and return its credential. The credential is shown once; only its hash is stored. */
  createPrincipal(tenant: string, principalId: string, role: Role, opts: { sponsor?: string; displayName?: string; extra?: Permission[] } = {}): string {
    if (!ID.test(tenant) || !ID.test(principalId)) throw new ShieldError(422, 'invalid_id', 'Identifiers must be 1–128 characters of letters, digits and . _ : @ -');
    if (!Object.hasOwn(ROLE_PERMISSIONS, role)) throw new ShieldError(422, 'invalid_role', 'Unknown role.');
    const credential = newCredential();
    const permissions = [...new Set([...ROLE_PERMISSIONS[role], ...(opts.extra ?? [])])];
    try {
      this.store.tx(() => {
        this.store.run(
          'INSERT INTO principals (tenant_id, principal_id, role, permissions, credential_hash, created_at) VALUES (?,?,?,?,?,?)',
          tenant, principalId, role, JSON.stringify(permissions), hashCredential(credential), this.clock.now(),
        );
        if (role === 'agent') {
          this.store.run(
            'INSERT INTO agents (tenant_id, agent_id, display_name, sponsor, created_at) VALUES (?,?,?,?,?)',
            tenant, principalId, opts.displayName ?? null, opts.sponsor ?? 'unspecified', this.clock.now(),
          );
        }
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw new ShieldError(409, 'principal_exists', 'A principal with that id already exists.');
      throw err;
    }
    return credential;
  }

  /** Issue a new credential and invalidate the old one. */
  rotateCredential(tenant: string, principalId: string): string {
    const credential = newCredential();
    const changed = this.store.run('UPDATE principals SET credential_hash=? WHERE tenant_id=? AND principal_id=?', hashCredential(credential), tenant, principalId);
    if (!changed) throw new ShieldError(404, 'principal_not_found', 'No such principal.');
    return credential;
  }

  authenticate(credential: string | undefined): Principal | null {
    if (!credential || credential.length > 256) return null;
    const r = this.store.get(`SELECT * FROM principals WHERE credential_hash=? AND status='active'`, hashCredential(credential));
    if (!r) return null;
    return {
      tenant_id: r.tenant_id as string,
      principal_id: r.principal_id as string,
      role: r.role as Role,
      permissions: parseStrict(r.permissions as string) as Permission[],
    };
  }

  agent(tenant: string, agentId: string): AgentRecord | undefined {
    return this.store.get<AgentRecord>('SELECT * FROM agents WHERE tenant_id=? AND agent_id=?', tenant, agentId);
  }

  listAgents(tenant: string): AgentRecord[] {
    return this.store.all<AgentRecord>('SELECT * FROM agents WHERE tenant_id=? ORDER BY agent_id', tenant);
  }

  /**
   * The kill switch. Bumps the revocation epoch, so permits issued a moment
   * ago stop verifying at the executor, not just new requests at the PDP.
   */
  setAgentStatus(tenant: string, agentId: string, status: 'active' | 'suspended', expectedEpoch?: number): AgentRecord {
    return this.store.tx(() => {
      const a = this.agent(tenant, agentId);
      if (!a) throw new ShieldError(404, 'agent_not_found', 'No such agent.');
      if (expectedEpoch !== undefined && expectedEpoch !== a.revocation_epoch) {
        throw new ShieldError(409, 'epoch_conflict', 'Agent state changed since it was read.', { revocation_epoch: a.revocation_epoch });
      }
      this.store.run('UPDATE agents SET status=?, revocation_epoch=revocation_epoch+1 WHERE tenant_id=? AND agent_id=?', status, tenant, agentId);
      return this.agent(tenant, agentId)!;
    });
  }
}

export function requirePermission(p: Principal, permission: Permission): void {
  if (!p.permissions.includes(permission)) {
    throw new ShieldError(403, 'forbidden', `This credential lacks the "${permission}" permission.`);
  }
}

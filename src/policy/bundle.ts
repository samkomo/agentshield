/**
 * Signed policy bundles and their lifecycle.
 *
 * A bundle is data, not code: thresholds, label ordering, and per-class rules
 * interpreted by the fixed evaluator in engine.ts. It is only accepted when
 * signed by a key in the gateway's trust roots, and only activated by explicit
 * version. The version floor stops a rollback to anything older than the
 * oldest version an administrator has chosen to keep valid.
 */
import type { KeyObject } from 'node:crypto';
import { signDetached, verifyDetached, type SigningKey } from '../core/crypto.ts';
import { canonicalize, digest, isObject, parseStrict, type Json, type JsonObject } from '../core/json.ts';
import { ShieldError, type Clock } from '../core/util.ts';
import type { Store } from '../store/db.ts';

export interface ClassRule {
  /** `risk`: approval only when the risk score says so. */
  approval: 'never' | 'risk' | 'always';
  /** Whether arguments may be rewritten. Forbidden where a rewritten argument changes what the action means (a beneficiary, a row). */
  redaction: 'allow' | 'forbid';
  deny?: boolean;
  requires_amount?: boolean;
}

export interface PolicyBundle {
  policy_id: string;
  version: number;
  description?: string;
  /** Ascending sensitivity. A label absent from this list is treated as the most sensitive. */
  label_order: string[];
  detection: {
    min_confidence: number;
    /** Label implied by a finding category in the payload itself. */
    finding_labels: Record<string, string>;
  };
  data_flow: {
    secrets: 'redact' | 'block';
    pii: 'redact' | 'block' | 'allow';
    /** Sending this label or above to an external destination needs a human. */
    external_approval_label: string;
    /** Writing to a resource carrying this label or above needs a human. */
    write_approval_label: string;
    /** Operation classes for which labels the task has already seen count against the destination. */
    propagate_task_labels_to: string[];
    /** Operation classes that require a registered, approved destination. */
    destination_required_for: string[];
  };
  operation_classes: Record<string, ClassRule>;
  default_class: ClassRule;
  injection: {
    taint_threshold: number;
    /** What a write needs once the task has ingested content scoring above the threshold. */
    tainted_write: 'allow' | 'require_approval' | 'block';
  };
  risk: {
    weights: { sensitivity: number; impact: number; destination: number; behavior: number; credential: number };
    thresholds: { moderate: number; high: number; critical: number };
    rate_baseline_per_minute: number;
  };
  limits: {
    max_action_ttl_seconds: number;
    permit_ttl_seconds: number;
    approval_ttl_seconds: number;
    max_arguments_bytes: number;
    max_result_bytes: number;
    max_delegation_depth: number;
    execution_timeout_ms: number;
  };
}

export interface SignedBundle {
  bundle: PolicyBundle;
  signature: string;
  key_id: string;
}

export interface PolicyRecord {
  tenant_id: string;
  policy_id: string;
  version: number;
  bundle: PolicyBundle;
  bundle_digest: string;
  state: 'draft' | 'active' | 'retired' | 'revoked';
  created_by: string;
  activated_by: string | null;
  created_at: number;
}

export const DEFAULT_POLICY: PolicyBundle = {
  policy_id: 'agentshield-default',
  version: 1,
  description: 'Deny by default. Secrets never leave; confidential data and consequential writes need a human.',
  label_order: ['PUBLIC', 'INTERNAL', 'PERSONAL', 'FINANCIAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET', 'CRITICAL'],
  detection: { min_confidence: 0.6, finding_labels: { SECRET: 'SECRET', PII: 'PERSONAL' } },
  data_flow: {
    secrets: 'redact',
    pii: 'redact',
    external_approval_label: 'CONFIDENTIAL',
    write_approval_label: 'PERSONAL',
    propagate_task_labels_to: ['egress', 'model'],
    destination_required_for: ['egress', 'model', 'payment'],
  },
  operation_classes: {
    data_read: { approval: 'risk', redaction: 'allow' },
    data_write: { approval: 'risk', redaction: 'forbid' },
    egress: { approval: 'risk', redaction: 'allow' },
    model: { approval: 'risk', redaction: 'allow' },
    payment: { approval: 'risk', redaction: 'forbid', requires_amount: true },
    admin: { approval: 'always', redaction: 'forbid' },
    physical: { approval: 'always', redaction: 'forbid' },
    audit_admin: { approval: 'always', redaction: 'forbid', deny: true },
  },
  default_class: { approval: 'always', redaction: 'forbid' },
  injection: { taint_threshold: 0.6, tainted_write: 'require_approval' },
  risk: {
    weights: { sensitivity: 25, impact: 25, destination: 20, behavior: 15, credential: 15 },
    thresholds: { moderate: 25, high: 50, critical: 75 },
    rate_baseline_per_minute: 60,
  },
  limits: {
    max_action_ttl_seconds: 900,
    permit_ttl_seconds: 60,
    approval_ttl_seconds: 900,
    max_arguments_bytes: 262_144,
    max_result_bytes: 1_048_576,
    max_delegation_depth: 3,
    execution_timeout_ms: 30_000,
  },
};

function bad(msg: string): never {
  throw new ShieldError(422, 'invalid_policy', `Policy bundle rejected: ${msg}`);
}

const isRule = (r: unknown): r is ClassRule =>
  isObject(r as Json) &&
  ['never', 'risk', 'always'].includes((r as ClassRule).approval) &&
  ['allow', 'forbid'].includes((r as ClassRule).redaction);

/** Structural validation. A bundle that parses but is missing a section would otherwise fail open somewhere downstream. */
export function validateBundle(b: unknown): PolicyBundle {
  if (!isObject(b as Json)) bad('not an object');
  const p = b as unknown as PolicyBundle;
  if (typeof p.policy_id !== 'string' || !/^[\w.-]{1,64}$/.test(p.policy_id)) bad('policy_id');
  if (!Number.isSafeInteger(p.version) || p.version < 1) bad('version must be a positive integer');
  if (!Array.isArray(p.label_order) || !p.label_order.length || p.label_order.some((l) => typeof l !== 'string')) bad('label_order');
  if (new Set(p.label_order).size !== p.label_order.length) bad('label_order has duplicates');
  if (!isObject(p.detection as unknown as Json) || !(p.detection.min_confidence >= 0 && p.detection.min_confidence <= 1)) bad('detection.min_confidence');
  if (!isObject(p.detection.finding_labels as Json)) bad('detection.finding_labels');
  const df = p.data_flow;
  if (!isObject(df as unknown as Json)) bad('data_flow');
  if (!['redact', 'block'].includes(df.secrets)) bad('data_flow.secrets');
  if (!['redact', 'block', 'allow'].includes(df.pii)) bad('data_flow.pii');
  for (const k of ['external_approval_label', 'write_approval_label'] as const) {
    if (!p.label_order.includes(df[k])) bad(`data_flow.${k} is not in label_order`);
  }
  for (const k of ['propagate_task_labels_to', 'destination_required_for'] as const) {
    if (!Array.isArray(df[k]) || df[k].some((c) => typeof c !== 'string')) bad(`data_flow.${k}`);
  }
  if (!isObject(p.operation_classes as unknown as Json)) bad('operation_classes');
  for (const [name, rule] of Object.entries(p.operation_classes)) if (!isRule(rule)) bad(`operation_classes.${name}`);
  if (!isRule(p.default_class)) bad('default_class');
  if (!isObject(p.injection as unknown as Json) || !(p.injection.taint_threshold >= 0 && p.injection.taint_threshold <= 1)) bad('injection.taint_threshold');
  if (!['allow', 'require_approval', 'block'].includes(p.injection.tainted_write)) bad('injection.tainted_write');
  const w = p.risk?.weights;
  if (!w) bad('risk.weights');
  const total = w.sensitivity + w.impact + w.destination + w.behavior + w.credential;
  if (!(Math.abs(total - 100) < 1e-9) || Object.values(w).some((x) => !(x >= 0))) bad('risk.weights must be non-negative and total 100');
  const t = p.risk.thresholds;
  if (!t || !(0 < t.moderate && t.moderate < t.high && t.high < t.critical && t.critical <= 100)) bad('risk.thresholds must ascend within 0–100');
  if (!(p.risk.rate_baseline_per_minute > 0)) bad('risk.rate_baseline_per_minute');
  const l = p.limits;
  if (!isObject(l as unknown as Json)) bad('limits');
  for (const k of ['max_action_ttl_seconds', 'permit_ttl_seconds', 'approval_ttl_seconds', 'max_arguments_bytes', 'max_result_bytes', 'execution_timeout_ms'] as const) {
    if (!Number.isSafeInteger(l[k]) || l[k] <= 0) bad(`limits.${k}`);
  }
  if (!Number.isSafeInteger(l.max_delegation_depth) || l.max_delegation_depth < 0) bad('limits.max_delegation_depth');
  return p;
}

export function signBundle(key: SigningKey, bundle: PolicyBundle): SignedBundle {
  validateBundle(bundle);
  return { bundle, key_id: key.kid, signature: signDetached(key, canonicalize(bundle as unknown as Json)) };
}

export class PolicyStore {
  private store: Store;
  private trust: Map<string, KeyObject>;
  private clock: Clock;
  private cache = new Map<string, PolicyRecord | null>();

  constructor(store: Store, trust: Map<string, KeyObject>, clock: Clock) {
    this.store = store;
    this.trust = trust;
    this.clock = clock;
  }

  private row(r: Record<string, unknown>): PolicyRecord {
    return {
      tenant_id: r.tenant_id as string, policy_id: r.policy_id as string, version: r.version as number,
      bundle: parseStrict(r.bundle as string) as unknown as PolicyBundle, bundle_digest: r.bundle_digest as string,
      state: r.state as PolicyRecord['state'], created_by: r.created_by as string,
      activated_by: (r.activated_by as string) ?? null, created_at: r.created_at as number,
    };
  }

  /** Store a signed bundle as a draft. Rejects unknown signers, bad signatures and reused versions. */
  create(tenant: string, signed: SignedBundle, createdBy: string): PolicyRecord {
    const bundle = validateBundle(signed?.bundle);
    const key = this.trust.get(signed.key_id);
    if (!key || typeof signed.signature !== 'string' || !verifyDetached(key, canonicalize(bundle as unknown as Json), signed.signature)) {
      throw new ShieldError(422, 'policy_signature_invalid', 'Policy bundle is not signed by a trusted policy key.');
    }
    const existing = this.store.get('SELECT 1 FROM policies WHERE tenant_id=? AND policy_id=? AND version=?', tenant, bundle.policy_id, bundle.version);
    if (existing) throw new ShieldError(409, 'policy_version_exists', 'That policy version already exists; versions are immutable.');
    this.store.run(
      `INSERT INTO policies (tenant_id, policy_id, version, bundle, bundle_digest, signature, key_id, state, created_by, created_at)
       VALUES (?,?,?,?,?,?,?,'draft',?,?)`,
      tenant, bundle.policy_id, bundle.version, canonicalize(bundle as unknown as Json), digest(bundle as unknown as Json),
      signed.signature, signed.key_id, createdBy, this.clock.now(),
    );
    return this.get(tenant, bundle.policy_id, bundle.version)!;
  }

  get(tenant: string, policyId: string, version: number): PolicyRecord | undefined {
    const r = this.store.get('SELECT * FROM policies WHERE tenant_id=? AND policy_id=? AND version=?', tenant, policyId, version);
    return r ? this.row(r) : undefined;
  }

  list(tenant: string): Omit<PolicyRecord, 'bundle'>[] {
    return this.store
      .all('SELECT * FROM policies WHERE tenant_id=? ORDER BY created_at DESC', tenant)
      .map((r) => {
        const { bundle: _bundle, ...rest } = this.row(r);
        return rest;
      });
  }

  /** The policy in force. Re-verifies the stored signature on load, so a row edited behind the gateway's back is not trusted. */
  active(tenant: string): PolicyRecord | null {
    if (this.cache.has(tenant)) return this.cache.get(tenant)!;
    const r = this.store.get(`SELECT * FROM policies WHERE tenant_id=? AND state='active'`, tenant);
    let record: PolicyRecord | null = null;
    if (r) {
      const key = this.trust.get(r.key_id as string);
      if (key && verifyDetached(key, r.bundle as string, r.signature as string)) record = this.row(r);
    }
    this.cache.set(tenant, record);
    return record;
  }

  /**
   * Make one version the active one. Activating a lower version than the
   * current one is a rollback and is allowed only to a version that has not
   * been revoked; the author of a version may not be the one to activate it
   * when two-person review is on.
   */
  activate(tenant: string, policyId: string, version: number, activatedBy: string, twoPerson: boolean): PolicyRecord {
    return this.store.tx(() => {
      const target = this.get(tenant, policyId, version);
      if (!target) throw new ShieldError(404, 'policy_not_found', 'No such policy version.');
      if (target.state === 'revoked') throw new ShieldError(409, 'policy_revoked', 'A revoked policy version cannot be activated.');
      if (twoPerson && target.created_by === activatedBy) {
        throw new ShieldError(403, 'two_person_required', 'A policy version must be activated by someone other than its author.');
      }
      this.store.run(`UPDATE policies SET state='retired' WHERE tenant_id=? AND state='active'`, tenant);
      this.store.run(`UPDATE policies SET state='active', activated_by=? WHERE tenant_id=? AND policy_id=? AND version=?`, activatedBy, tenant, policyId, version);
      this.cache.delete(tenant);
      return this.get(tenant, policyId, version)!;
    });
  }

  /** Permanently bar a version. If it was active the tenant has no policy, and every action is denied until one is activated. */
  revoke(tenant: string, policyId: string, version: number): void {
    const changed = this.store.run(`UPDATE policies SET state='revoked' WHERE tenant_id=? AND policy_id=? AND version=?`, tenant, policyId, version);
    if (!changed) throw new ShieldError(404, 'policy_not_found', 'No such policy version.');
    this.cache.delete(tenant);
  }

  isRevoked(tenant: string, policyId: string, version: number): boolean {
    return this.get(tenant, policyId, version)?.state === 'revoked';
  }
}

export type { JsonObject };

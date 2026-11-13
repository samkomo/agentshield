import type { Json, JsonObject } from './json.ts';

export type Decision = 'allow' | 'redact' | 'require_approval' | 'block';
export type RiskClass = 'low' | 'moderate' | 'high' | 'critical';
export const RISK_ORDER: readonly RiskClass[] = ['low', 'moderate', 'high', 'critical'];

export type Permission =
  | 'agent:scan' | 'agent:inspect' | 'agent:execute' | 'agent:request' | 'agent:delegate'
  | 'operator:block' | 'operator:tools' | 'operator:suspend' | 'operator:approve'
  | 'admin:tools' | 'admin:policy' | 'admin:grants' | 'admin:principals' | 'admin:catalog'
  | 'auditor:read' | 'auditor:report' | 'vault:reveal';

export type Role = 'agent' | 'approver' | 'operator' | 'admin' | 'auditor';

export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  agent: ['agent:scan', 'agent:inspect', 'agent:execute', 'agent:request', 'agent:delegate'],
  approver: ['operator:approve'],
  operator: ['operator:block', 'operator:tools', 'operator:suspend', 'operator:approve'],
  admin: ['admin:tools', 'admin:policy', 'admin:grants', 'admin:principals', 'admin:catalog'],
  auditor: ['auditor:read', 'auditor:report'],
};

/** The authenticated caller. Always derived from the transport credential, never from the request body. */
export interface Principal {
  tenant_id: string;
  principal_id: string;
  role: Role;
  permissions: readonly Permission[];
}

/** What an agent submits. */
export interface ActionEnvelope {
  action_id: string;
  task_id: string;
  tool_id: string;
  tool_revision?: string;
  operation: string;
  resource_id: string;
  destination_id: string;
  arguments: JsonObject;
  nonce: string;
  expires_at: string;
  idempotency_key?: string;
}

/**
 * The envelope plus everything the gateway resolved itself. The permit binds
 * the digest of exactly this object.
 */
export interface BoundAction extends ActionEnvelope {
  tenant_id: string;
  principal_id: string;
  /** Sponsor first, then each delegating agent, ending with the acting agent. */
  actor_chain: string[];
  tool_revision: string;
}

export interface GrantScope {
  tools: string[];
  operations: string[];
  resources: string[];
  destinations: string[];
  /** Absent means the grant authorizes no monetary action at all. */
  max_per_action_minor?: number;
  /** How many further levels may be delegated below this grant. */
  max_delegation_depth?: number;
}

export interface Grant {
  tenant_id: string;
  grant_id: string;
  agent_id: string;
  task_id: string;
  parent_grant_id: string | null;
  /** `/root/child/…/self/` — makes "this grant and everything beneath it" a prefix query. */
  path: string;
  depth: number;
  revision: number;
  status: 'active' | 'revoked';
  scope: GrantScope;
  budget_minor: number | null;
  currency: string | null;
  sponsor: string;
  expires_at: number;
  created_by: string;
  created_at: number;
}

export interface OperationSpec {
  description?: string;
  input_schema?: JsonObject;
  output_schema?: JsonObject;
  /** Policy keys approval and redaction rules off this. */
  class: string;
  effect: 'read' | 'write';
  reversible?: boolean;
  privileged?: boolean;
  /** Reviewed, tool-owner requirement that every call needs a human. Policy can add approval, never remove this. */
  approval?: 'always';
  amount_arg?: string;
  currency_arg?: string;
  /**
   * Argument that names the resource being touched. When set, the envelope's
   * resource_id must equal it, so an agent cannot label a call with one
   * resource and act on another.
   */
  resource_arg?: string;
  /**
   * Argument that says where data is being sent (a recipient, a beneficiary, a
   * URL). When set, the envelope's destination_id must equal what it resolves
   * to. When absent, the only valid destination is the tool's own.
   */
  destination_arg?: string;
  /** How to read destination_arg: as-is, the domain of an email address, or the host of a URL. */
  destination_from?: 'value' | 'email_domain' | 'url_host';
  http?: { method: string; path: string };
}

export interface ToolManifest {
  tool_id: string;
  kind: 'http' | 'mcp' | 'function';
  owner: string;
  publisher?: string;
  description?: string;
  /** Where calls to this tool land, as an entry in the destination catalog. */
  destination_id: string;
  endpoint?: {
    base_url?: string;
    transport?: 'http' | 'stdio';
    url?: string;
    command?: string;
    args?: string[];
    /** Names of gateway environment variables to pass to a stdio server. Nothing else is inherited. */
    env?: string[];
  };
  /** `env:NAME` or `file:/path`. Resolved inside the executor; never returned to a caller. */
  credential_ref?: string;
  credential_header?: string;
  operations: Record<string, OperationSpec>;
  expires_at?: string;
}

export interface ToolRecord {
  tenant_id: string;
  tool_id: string;
  state: 'pending' | 'approved' | 'quarantined' | 'revoked';
  manifest: ToolManifest;
  /** sha256 over the canonical manifest: the pinned revision. */
  schema_hash: string;
  registered_by: string;
  verified_by: string | null;
  checked_at: number | null;
  reason: string | null;
  created_at: number;
}

export interface Destination {
  tenant_id: string;
  destination_id: string;
  class: 'internal' | 'external';
  state: 'approved' | 'unreviewed' | 'blocked';
  /** Most sensitive label this destination may receive. */
  max_label: string;
  /** Finding categories it may receive unredacted, e.g. `PII` for the system of record. */
  accepts: string[];
}

export interface Finding {
  category: 'SECRET' | 'PII';
  type: string;
  /** UTF-16 offsets into the scanned string. */
  start: number;
  end: number;
  /** Byte offsets into its UTF-8 encoding. */
  byte_start: number;
  byte_end: number;
  confidence: number;
  detector: string;
  /** JSON pointer of the string inside a scanned document. */
  path?: string;
  /** Found in an object key, which cannot be rewritten without changing the action's shape. */
  in_key?: boolean;
}

export interface InjectionSignal {
  id: string;
  weight: number;
}
export interface InjectionResult {
  score: number;
  signals: InjectionSignal[];
}

export interface TaskContext {
  labels: string[];
  untrusted_sources: number;
  max_injection: number;
}

export interface RiskFactor {
  feature: 'sensitivity' | 'impact' | 'destination' | 'behavior' | 'credential';
  weight: number;
  value: number;
  contribution: number;
  note: string;
}
export interface RiskResult {
  score: number;
  class: RiskClass;
  factors: RiskFactor[];
}

export interface Reason {
  code: string;
  message: string;
}

export interface DecisionResponse {
  decision: Decision;
  decision_id: string;
  action_id: string;
  risk_level: RiskClass;
  risk_score: number;
  reason: string;
  reasons: Reason[];
  policy_id: string | null;
  policy_version: number | null;
  grant_revision: number | null;
  tool_revision: string | null;
  classification: string | null;
  finding_categories: string[];
  action_digest: string;
  expires_at: string | null;
  permit: string | null;
  approval_id: string | null;
  obligations: string[];
  /** Present when arguments were rewritten: this, not the submitted action, is what the permit covers. */
  transformed_action?: ActionEnvelope;
}

export type ExecutionState = 'succeeded' | 'failed' | 'unknown' | 'denied';

export interface ExecutionResponse {
  action_id: string;
  state: ExecutionState;
  result: Json | null;
  /** True when the result came from outside the trust boundary and must be treated as data, not instructions. */
  untrusted_content: boolean;
  injection: InjectionResult | null;
  finding_categories: string[];
  result_redacted: boolean;
  error: Reason | null;
  receipt: {
    event_id: string;
    sequence: number;
    action_digest: string;
    result_digest: string | null;
    provider_ref: string | null;
    timestamp: string;
  };
}

export interface RunResponse {
  decision: DecisionResponse;
  execution: ExecutionResponse | null;
}

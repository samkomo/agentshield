/**
 * AgentShield: the enforcement pipeline.
 *
 *   authorize:  authenticate → validate → resolve grant/tool/labels → scan →
 *               decide → (redact → re-scan → re-decide) → (approval) →
 *               reserve budget → issue permit → durable event
 *   execute:    verify permit → exact-action check → one-use claim →
 *               re-check everything revocable → call tool → scan result →
 *               settle budget → signed receipt
 *
 * The agent proposes; this class decides. Every input to a decision is
 * resolved here from the credential, the registry, the catalog and the grant.
 * Nothing the agent asserts about itself — identity, findings, risk, approval
 * status — is taken as authoritative.
 *
 * Failure is closed: no policy, no grant, an unknown tool, a failed event
 * write or an unverifiable permit all end in "no".
 */
import { performance } from 'node:perf_hooks';
import { actionDigest, bind, bindingErrors, extractAmount, requestDigest, toEnvelope, validateEnvelope } from '../actions/envelope.ts';
import { Intents, type Intent } from '../actions/intents.ts';
import { issuePermit, verifyPermit, type PermitClaims } from '../actions/permit.ts';
import { Approvals, type Approval } from '../approvals/approvals.ts';
import { AuditLog, type Checkpoint, type EventInput, type StoredEvent } from '../audit/events.ts';
import { Vault } from '../audit/vault.ts';
import { Ledger } from '../budget/ledger.ts';
import type { KeySet } from '../core/crypto.ts';
import { canonicalize, digest, isObject, type Json, type JsonObject } from '../core/json.ts';
import { validate } from '../core/schema.ts';
import type {
  ActionEnvelope, BoundAction, Decision, DecisionResponse, Destination, ExecutionResponse, ExecutionState, Finding, Grant,
  InjectionResult, OperationSpec, Permission, Principal, Reason, RiskResult, Role, RunResponse, ToolRecord,
} from '../core/types.ts';
import { RateLimiter, ShieldError, iso, newId, systemClock, type Clock } from '../core/util.ts';
import { detectInjection, detectInjectionJson } from '../detect/injection.ts';
import { PlaceholderAllocator, redactJson, redactText, type Replacement } from '../detect/redact.ts';
import { DETECTOR_VERSION, categoriesOf, scanJson, scanText, type Detector } from '../detect/scanner.ts';
import { AdapterError, FunctionAdapter, HttpAdapter, McpAdapter, type ToolAdapter } from '../executor/adapters.ts';
import { Grants, type GrantRequest } from '../identity/grants.ts';
import { Identity, requirePermission, type AgentRecord } from '../identity/identity.ts';
import { DEFAULT_POLICY, PolicyStore, type PolicyBundle, type PolicyRecord, type SignedBundle } from '../policy/bundle.ts';
import { decide, type PolicyOutcome } from '../policy/engine.ts';
import { ceilingRank, highestLabel, labelRank, scoreRisk } from '../policy/risk.ts';
import { Catalog } from '../registry/catalog.ts';
import { ToolRegistry, pinnedFingerprint, upstreamFingerprint } from '../registry/tools.ts';
import { Store, isUniqueViolation } from '../store/db.ts';

export interface ShieldOptions {
  keys: KeySet;
  store?: Store;
  clock?: Clock;
  /** File that receives signed audit checkpoints. Put it somewhere the gateway's database owner cannot rewrite. */
  checkpointSink?: string | null;
  /** Require a second person to verify tools and activate policy. On by default. */
  twoPersonReview?: boolean;
  rateLimitPerMinute?: number;
  detectors?: Detector[];
}

interface Evaluation {
  record: PolicyRecord | null;
  policy: PolicyBundle;
  env: ActionEnvelope;
  bound: BoundAction;
  digest: string;
  outcome: PolicyOutcome;
  risk: RiskResult;
  agent: AgentRecord | undefined;
  grant: Grant | null;
  chain: Grant[];
  tool: ToolRecord | null;
  op: OperationSpec | null;
  destination: Destination | null;
  amount: { minor: number; currency: string } | null;
  classification: string | null;
  findings: Finding[];
  categories: string[];
  redacted: boolean;
  replacements: Replacement[];
}

const unique = <T>(xs: T[]): T[] => [...new Set(xs)];

export class Shield {
  readonly store: Store;
  readonly keys: KeySet;
  readonly clock: Clock;
  readonly identity: Identity;
  readonly grants: Grants;
  readonly tools: ToolRegistry;
  readonly catalog: Catalog;
  readonly policies: PolicyStore;
  readonly ledger: Ledger;
  readonly approvals: Approvals;
  readonly intents: Intents;
  readonly audit: AuditLog;
  readonly vault: Vault;
  /** In-process tool handlers, for embedding and tests. */
  readonly functions = new FunctionAdapter();
  readonly mcp = new McpAdapter();
  private http = new HttpAdapter();
  private twoPerson: boolean;
  private limiter: RateLimiter;
  private detectors: Detector[];
  private driftChecked = new Map<string, number>();

  constructor(opts: ShieldOptions) {
    this.store = opts.store ?? new Store();
    this.keys = opts.keys;
    this.clock = opts.clock ?? systemClock;
    this.twoPerson = opts.twoPersonReview ?? true;
    this.detectors = opts.detectors ?? [];
    this.limiter = new RateLimiter(opts.rateLimitPerMinute ?? 600, Math.max(20, (opts.rateLimitPerMinute ?? 600) / 6), this.clock);
    this.identity = new Identity(this.store, this.clock);
    this.grants = new Grants(this.store, this.clock);
    this.tools = new ToolRegistry(this.store, this.clock);
    this.catalog = new Catalog(this.store, this.clock);
    this.policies = new PolicyStore(this.store, this.keys.policyTrust, this.clock);
    this.ledger = new Ledger(this.store, this.clock);
    this.approvals = new Approvals(this.store, this.clock);
    this.intents = new Intents(this.store, this.clock);
    this.audit = new AuditLog(this.store, this.keys.event, this.keys.telemetryKey, this.clock, opts.checkpointSink ?? null);
    this.vault = new Vault(this.store, this.keys.vaultKey, this.clock);
  }

  close(): void {
    this.mcp.closeAll();
    this.store.close();
  }

  authenticate(credential: string | undefined): Principal | null {
    return this.identity.authenticate(credential);
  }

  private throttle(p: Principal): void {
    if (!this.limiter.take(`${p.tenant_id}\0${p.principal_id}`)) {
      throw new ShieldError(429, 'rate_limited', 'Too many requests; slow down.');
    }
  }

  private limits(tenant: string): PolicyBundle['limits'] {
    return (this.policies.active(tenant)?.bundle ?? DEFAULT_POLICY).limits;
  }

  // ───────────────────────────── evaluation ─────────────────────────────

  /**
   * Assemble trusted context and run the policy. Pure with respect to stored
   * state: it reads, it never writes. If the policy asks for redaction, the
   * arguments are rewritten and the whole evaluation runs again on the result
   * — redaction changes the action, so the old verdict no longer applies.
   */
  private evaluate(p: Principal, submitted: ActionEnvelope, override?: PolicyRecord): Evaluation {
    const tenant = p.tenant_id;
    const now = this.clock.now();
    const record = override ?? this.policies.active(tenant);
    const policy = record?.bundle ?? DEFAULT_POLICY;
    const agent = this.identity.agent(tenant, p.principal_id);
    const grant = this.grants.resolve(tenant, p.principal_id, submitted.task_id);
    const chain = grant ? this.grants.chain(grant) : [];
    const tool = this.tools.get(tenant, submitted.tool_id) ?? null;
    const op = tool && Object.hasOwn(tool.manifest.operations, submitted.operation) ? tool.manifest.operations[submitted.operation]! : null;
    const destination = this.catalog.destination(tenant, submitted.destination_id);
    const task = this.catalog.task(tenant, submitted.task_id);
    const resourceLabels = this.catalog.labelsFor(tenant, submitted.resource_id);
    const actorChain = grant ? [grant.sponsor, ...chain.map((g) => g.agent_id)] : [p.principal_id];
    const toolRevision = tool?.schema_hash ?? 'unregistered';
    const revisionMismatch = submitted.tool_revision !== undefined && submitted.tool_revision !== toolRevision;
    const recentActions = this.intents.recentCount(tenant, p.principal_id, now - 60_000);
    const recentDenials = this.intents.recentCount(tenant, p.principal_id, now - 600_000, true);
    const budgetRemaining = chain.length ? this.ledger.remaining(chain) : null;
    const budgetCurrency = [...chain].reverse().find((g) => g.budget_minor !== null)?.currency ?? null;

    const alloc = new PlaceholderAllocator();
    let env: ActionEnvelope = { ...submitted, tool_revision: toolRevision };
    let classification: string | null = null;
    let categories: string[] = [];
    let firstFindings: Finding[] = [];

    for (let pass = 0; ; pass++) {
      const bound = bind(env, p, actorChain, toolRevision);
      // The arguments that name the resource and the destination are identifiers the grant and catalog already
      // govern. An email recipient is personal data by construction; redacting it would only break the binding.
      // Credentials found there are still findings.
      const identifierPaths = [op?.resource_arg, op?.destination_arg].filter((a): a is string => !!a).map((a) => `/${a.replace(/~/g, '~0').replace(/\//g, '~1')}`);
      const findings = scanJson(env.arguments, { minConfidence: policy.detection.min_confidence, detectors: this.detectors })
        .filter((f) => !(f.category === 'PII' && identifierPaths.some((ip) => f.path === ip || f.path?.startsWith(`${ip}/`))));
      // Identifier fields travel too (an idempotency key becomes a downstream header), so a credential must not
      // ride in one. They cannot be rewritten without changing what the action is, so this is a block, not a redaction.
      const identifiers = [env.action_id, env.task_id, env.resource_id, env.destination_id, env.nonce, env.idempotency_key ?? ''].join('\n');
      for (const f of scanText(identifiers, { minConfidence: policy.detection.min_confidence, detectors: this.detectors })) {
        if (f.category === 'SECRET') findings.push({ ...f, path: '(envelope)', in_key: true });
      }
      const findingLabels = unique(findings.map((f) => policy.detection.finding_labels[f.category]).filter((l): l is string => typeof l === 'string'));
      const labels = unique([...resourceLabels, ...findingLabels]);
      const { amount, error: amountError } = extractAmount(env, op);
      const risk = scoreRisk(policy, { labels, op, destination, grant, amountMinor: amount?.minor ?? null, task, recentActions, recentDenials, now });
      let outcome: PolicyOutcome = record
        ? decide(policy, {
            action: bound, identityVerified: true, agentStatus: agent ? agent.status : 'unknown', grant, tool, revisionMismatch, op,
            schemaErrors: op?.input_schema ? validate(op.input_schema, env.arguments) : [],
            bindingErrors: bindingErrors(env, tool, op), destination, labels, resourceLabels, findings, task, amount, amountError,
            budgetRemaining, budgetCurrency, risk, now,
          })
        : { effect: 'block', riskLevel: 'critical', redact: [], obligations: [], reasons: [{ code: 'no_active_policy', message: 'No signed policy is active; everything is denied.' }] };

      if (pass === 0) {
        classification = highestLabel(policy, labels);
        categories = categoriesOf(findings);
        firstFindings = findings;
      }
      if (outcome.effect === 'redact') {
        if (pass === 0) {
          env = { ...env, arguments: redactJson(env.arguments, outcome.redact, alloc) as JsonObject };
          continue;
        }
        outcome = { effect: 'block', riskLevel: 'critical', redact: [], obligations: [], reasons: [{ code: 'redaction_unresolved', message: 'Prohibited content remained after redaction.' }] };
      }
      return {
        record, policy, env, bound, digest: actionDigest(bound), outcome, risk, agent, grant, chain, tool, op, destination, amount,
        classification, findings: firstFindings, categories, redacted: pass > 0, replacements: alloc.replacements,
      };
    }
  }

  private response(ev: Evaluation, decision: Decision, decisionId: string, extra: Partial<DecisionResponse> = {}): DecisionResponse {
    const res: DecisionResponse = {
      decision,
      decision_id: decisionId,
      action_id: ev.env.action_id,
      risk_level: ev.outcome.riskLevel,
      risk_score: ev.risk.score,
      reason: ev.outcome.reasons.map((r) => r.message).join(' '),
      reasons: ev.outcome.reasons,
      policy_id: ev.record?.policy_id ?? null,
      policy_version: ev.record?.version ?? null,
      grant_revision: ev.grant?.revision ?? null,
      tool_revision: ev.tool?.schema_hash ?? null,
      classification: ev.classification,
      finding_categories: ev.categories,
      action_digest: ev.digest,
      expires_at: null,
      permit: null,
      approval_id: null,
      obligations: ev.outcome.obligations,
      ...extra,
    };
    if (ev.redacted && decision !== 'block') res.transformed_action = toEnvelope(ev.bound);
    return res;
  }

  private decisionEvent(ev: Evaluation, type: string, res: DecisionResponse, started: number): EventInput {
    return {
      event_type: type,
      agent_id: ev.bound.principal_id,
      action_id: ev.env.action_id,
      decision_id: res.decision_id,
      policy_version: res.policy_version,
      grant_revision: res.grant_revision,
      tool_revision: res.tool_revision,
      finding_categories: res.finding_categories,
      latency_ms: Math.round(performance.now() - started),
      detail: {
        decision: res.decision,
        risk_level: res.risk_level,
        risk_score: res.risk_score,
        reason_codes: res.reasons.map((r) => r.code),
        tool_id: ev.env.tool_id,
        operation: ev.env.operation,
        destination_id: ev.env.destination_id,
        resource_ref: this.audit.ref(ev.bound.tenant_id, ev.env.resource_id),
        task_ref: this.audit.ref(ev.bound.tenant_id, ev.env.task_id),
        action_digest: res.action_digest,
        classification: res.classification,
        finding_types: unique(ev.findings.map((f) => f.type)).sort(),
        approval_id: res.approval_id,
      },
    };
  }

  // ───────────────────────────── authorize ─────────────────────────────

  /**
   * Decide one action. Returns `allow` or `redact` with a permit,
   * `require_approval` with an approval id, or `block`. Resubmitting the same
   * action while approval is pending continues that action; resubmitting
   * anything else under a used action_id, nonce or idempotency key is a 409.
   */
  authorize(p: Principal, raw: Json, opts: { approvalId?: string; reuseKey?: string } = {}): DecisionResponse {
    requirePermission(p, 'agent:execute');
    this.throttle(p);
    const started = performance.now();
    const limits = this.limits(p.tenant_id);
    const env = validateEnvelope(raw, this.clock.now(), { maxArgumentsBytes: limits.max_arguments_bytes, maxTtlMs: limits.max_action_ttl_seconds * 1000 });
    const reqDigest = requestDigest(p, env);

    return this.store.tx(() => {
      const tenant = p.tenant_id;
      const ev = this.evaluate(p, env);
      let existing = this.intents.get(tenant, env.action_id);
      if (existing) {
        if (existing.agent_id !== p.principal_id || existing.request_digest !== reqDigest) {
          throw new ShieldError(409, 'action_conflict', 'This action_id has already been used for a different action.');
        }
        if (existing.state === 'reserved') return existing.response;
        if (existing.state !== 'pending' && existing.state !== 'approved') {
          throw new ShieldError(409, 'action_already_decided', `This action is already ${existing.state}.`, { state: existing.state, decision_id: existing.decision_id });
        }
      }
      if (opts.approvalId && opts.approvalId !== existing?.approval_id) {
        throw new ShieldError(409, 'approval_mismatch', 'That approval does not belong to this action.');
      }
      const decisionId = existing?.decision_id ?? newId('dec');

      const save = (res: DecisionResponse, state: Intent['state'], approvalId: string | null, permitJti: string | null): void => {
        const fields = {
          tenant_id: tenant, action_id: env.action_id, action_digest: ev.digest, action: ev.bound, decision_id: decisionId,
          decision: res.decision, response: res, state, policy_id: ev.record?.policy_id ?? null, policy_version: ev.record?.version ?? null,
          grant_id: ev.grant?.grant_id ?? null, grant_revision: ev.grant?.revision ?? null, approval_id: approvalId, permit_jti: permitJti,
        };
        if (existing) return this.intents.redecide(fields);
        try {
          this.intents.insert({
            ...fields, agent_id: p.principal_id, task_id: env.task_id, nonce: env.nonce, idempotency_key: env.idempotency_key ?? null,
            reuse_key: opts.reuseKey ?? null, request_digest: reqDigest, expires_at: Date.parse(env.expires_at),
          });
        } catch (err) {
          if (!isUniqueViolation(err)) throw err;
          throw (err as Error).message.includes('nonce')
            ? new ShieldError(409, 'nonce_replay', 'This nonce has already been used.')
            : new ShieldError(409, 'idempotency_conflict', 'This idempotency key has already been used for another action.');
        }
      };

      const block = (reasons?: Reason[]): DecisionResponse => {
        if (reasons) ev.outcome = { effect: 'block', riskLevel: 'critical', redact: [], obligations: [], reasons };
        const res = this.response(ev, 'block', decisionId);
        save(res, 'denied', existing?.approval_id ?? null, null);
        this.audit.append(tenant, this.decisionEvent(ev, 'decision.blocked', res, started));
        return res;
      };

      const issue = (approvalId: string | null): DecisionResponse => {
        const now = this.clock.now();
        if (ev.amount) {
          try {
            this.ledger.reserve(ev.chain, env.action_id, ev.amount.minor, ev.amount.currency);
          } catch (err) {
            if (err instanceof ShieldError && err.code === 'budget_exceeded') {
              return block([{ code: 'budget_exceeded', message: 'Amount exceeds the remaining shared budget; routine approval cannot override this.' }]);
            }
            throw err;
          }
        }
        const exp = Math.min(Date.parse(env.expires_at), now + ev.policy.limits.permit_ttl_seconds * 1000);
        const claims: PermitClaims = {
          iss: 'agentshield', jti: newId('pmt'), tenant_id: tenant, sub: p.principal_id, action_id: env.action_id, action_digest: ev.digest,
          decision_id: decisionId, policy_id: ev.record!.policy_id, policy_version: ev.record!.version, grant_id: ev.grant!.grant_id,
          grant_revision: ev.grant!.revision, agent_epoch: ev.agent!.revocation_epoch, tool_id: env.tool_id, tool_revision: ev.tool!.schema_hash,
          nonce: env.nonce, iat: Math.floor(now / 1000), exp: Math.floor(exp / 1000),
        };
        if (ev.replacements.length) {
          this.vault.put(tenant, env.task_id, env.action_id, ev.replacements, ev.policy.limits.max_action_ttl_seconds * 1000);
        }
        const res = this.response(ev, ev.redacted ? 'redact' : 'allow', decisionId, {
          permit: issuePermit(this.keys.permit, claims), expires_at: iso(claims.exp * 1000), approval_id: approvalId,
        });
        save(res, 'reserved', approvalId, claims.jti);
        this.audit.append(tenant, this.decisionEvent(ev, 'permit.issued', res, started));
        return res;
      };

      if (ev.outcome.effect === 'block') return block();
      if (ev.outcome.effect === 'allow') return issue(null);

      // require_approval
      const approval = existing?.approval_id ? this.approvals.get(tenant, existing.approval_id) : undefined;
      if (approval?.status === 'rejected') {
        return block([{ code: 'approval_rejected', message: 'An approver rejected this action.' }]);
      }
      if (approval?.status === 'approved' && this.approvals.consume(tenant, approval.approval_id, ev.digest)) {
        return issue(approval.approval_id);
      }
      if (approval?.status === 'pending' && approval.action_digest === ev.digest) {
        return this.response(ev, 'require_approval', decisionId, { approval_id: approval.approval_id, expires_at: iso(approval.expires_at) });
      }
      // No usable approval: none yet, expired, or granted for an action that has since changed.
      const ttl = Math.min(ev.policy.limits.approval_ttl_seconds * 1000, Date.parse(env.expires_at) - this.clock.now());
      const fresh = this.approvals.request(tenant, env.action_id, decisionId, ev.digest, p.principal_id, ttl);
      const res = this.response(ev, 'require_approval', decisionId, { approval_id: fresh.approval_id, expires_at: iso(fresh.expires_at) });
      save(res, 'pending', fresh.approval_id, null);
      this.audit.append(tenant, this.decisionEvent(ev, 'decision.approval_required', res, started));
      return res;
    });
  }

  /** Evaluate without recording anything or consuming the nonce. For "would this be allowed?" checks. */
  inspect(p: Principal, raw: Json): { decision: Decision; risk: RiskResult; reasons: Reason[]; findings: Finding[]; tool_revision: string | null; classification: string | null; action_digest: string } {
    requirePermission(p, 'agent:inspect');
    this.throttle(p);
    const limits = this.limits(p.tenant_id);
    const env = validateEnvelope(raw, this.clock.now(), { maxArgumentsBytes: limits.max_arguments_bytes, maxTtlMs: limits.max_action_ttl_seconds * 1000 });
    const ev = this.evaluate(p, env);
    const effect = ev.outcome.effect === 'allow' && ev.redacted ? 'redact' : (ev.outcome.effect as Decision);
    return {
      decision: effect, risk: { ...ev.risk, class: ev.outcome.riskLevel }, reasons: ev.outcome.reasons, findings: ev.findings,
      tool_revision: ev.tool?.schema_hash ?? null, classification: ev.classification, action_digest: ev.digest,
    };
  }

  // ───────────────────────────── execute ─────────────────────────────

  private adapterFor(tool: ToolRecord): ToolAdapter {
    return tool.manifest.kind === 'function' ? this.functions : tool.manifest.kind === 'http' ? this.http : this.mcp;
  }

  /** Everything that could have been revoked between the decision and now. Returns the first problem, or null. */
  private revalidate(tenant: string, claims: PermitClaims): Reason | null {
    const agent = this.identity.agent(tenant, claims.sub);
    if (!agent || agent.status !== 'active' || agent.revocation_epoch !== claims.agent_epoch) {
      return { code: 'agent_revoked', message: 'The agent was suspended or its credentials were revoked after this permit was issued.' };
    }
    const grant = this.grants.get(tenant, claims.grant_id);
    if (!grant || grant.revision !== claims.grant_revision || !this.grants.isLive(grant)) {
      return { code: 'grant_revoked', message: 'The grant was revoked, changed or expired after this permit was issued.' };
    }
    const tool = this.tools.get(tenant, claims.tool_id);
    if (!tool || tool.state !== 'approved' || tool.schema_hash !== claims.tool_revision) {
      return { code: 'tool_changed', message: 'The tool was changed, quarantined or revoked after this permit was issued.' };
    }
    if (this.policies.isRevoked(tenant, claims.policy_id, claims.policy_version)) {
      return { code: 'policy_revoked', message: 'The policy version this permit was decided under has been revoked.' };
    }
    return null;
  }

  /**
   * Carry out a permitted action. The caller presents the action again along
   * with the permit; it must be byte-for-byte the action that was authorized.
   */
  async execute(p: Principal, raw: Json, permit: string): Promise<ExecutionResponse> {
    requirePermission(p, 'agent:execute');
    const tenant = p.tenant_id;
    const started = performance.now();
    const claims = typeof permit === 'string' ? verifyPermit(permit, this.keys.permit.publicKey, this.keys.permit.kid) : null;
    if (!claims) throw new ShieldError(403, 'permit_invalid', 'Permit is missing, malformed or not signed by this gateway.');
    if (claims.tenant_id !== tenant || claims.sub !== p.principal_id) throw new ShieldError(403, 'permit_invalid', 'Permit was issued to a different principal.');
    if (claims.exp * 1000 <= this.clock.now()) throw new ShieldError(403, 'permit_expired', 'Permit has expired; authorize the action again.');
    const intent = this.intents.get(tenant, claims.action_id);
    if (!intent || intent.permit_jti !== claims.jti || intent.action_digest !== claims.action_digest) {
      throw new ShieldError(403, 'permit_invalid', 'Permit does not correspond to a current authorization.');
    }
    if (!isObject(raw)) throw new ShieldError(400, 'invalid_envelope', 'Action must be a JSON object.');
    const presented = { ...raw, tenant_id: tenant, principal_id: p.principal_id, actor_chain: intent.action.actor_chain, tool_revision: intent.action.tool_revision };
    let presentedDigest: string;
    try {
      presentedDigest = digest(presented as Json);
    } catch {
      throw new ShieldError(400, 'invalid_envelope', 'Action could not be canonicalized.');
    }
    if (presentedDigest !== claims.action_digest) {
      throw new ShieldError(409, 'action_mismatch', 'The action presented is not the action that was authorized.');
    }

    // One use: only one caller ever moves this intent out of `reserved`.
    if (!this.intents.transition(tenant, claims.action_id, 'reserved', 'executing')) {
      throw new ShieldError(409, 'permit_replayed', 'This permit has already been used.');
    }

    const action = intent.action;
    const base = { agent_id: p.principal_id, action_id: action.action_id, decision_id: intent.decision_id, policy_version: intent.policy_version, grant_revision: intent.grant_revision, tool_revision: action.tool_revision };
    const finish = (state: ExecutionState, body: Partial<ExecutionResponse>, detail: JsonObject, categories: string[] = []): ExecutionResponse => {
      const event = this.store.tx(() => {
        this.intents.transition(tenant, action.action_id, 'executing', state === 'denied' ? 'denied' : state);
        if (state === 'succeeded') this.ledger.commit(tenant, action.action_id);
        else if (state !== 'unknown') this.ledger.release(tenant, action.action_id);
        return this.audit.append(tenant, {
          ...base, event_type: `execution.${state}`, finding_categories: categories, latency_ms: Math.round(performance.now() - started),
          detail: { action_digest: intent.action_digest, tool_id: action.tool_id, operation: action.operation, destination_id: action.destination_id, ...detail },
        });
      });
      return {
        action_id: action.action_id, state, result: null, untrusted_content: false, injection: null, finding_categories: categories,
        result_redacted: false, error: null, ...body,
        receipt: {
          event_id: event.event_id, sequence: event.sequence, action_digest: intent.action_digest,
          result_digest: (detail.result_digest as string) ?? null, provider_ref: (detail.provider_ref as string) ?? null, timestamp: event.timestamp,
        },
      };
    };

    // An upstream MCP server can change after review. Compare it with the pin (at most once a minute) before
    // trusting it with this call; drift quarantines the tool, and the re-check below then refuses the permit.
    await this.checkDrift(tenant, action.tool_id);
    const problem = this.revalidate(tenant, claims);
    if (problem) return finish('denied', { error: problem }, { reason_code: problem.code });

    const tool = this.tools.get(tenant, action.tool_id)!;
    const op = tool.manifest.operations[action.operation]!;
    const policy = this.policies.active(tenant)?.bundle ?? DEFAULT_POLICY;

    let result: Json = null;
    let providerRef: string | null = null;
    let state: ExecutionState = 'succeeded';
    let error: Reason | null = null;
    try {
      const out = await this.adapterFor(tool).invoke({ tool, op, action, timeoutMs: policy.limits.execution_timeout_ms, maxResultBytes: policy.limits.max_result_bytes });
      result = out.result ?? null;
      providerRef = out.provider_ref ?? null;
    } catch (err) {
      const definite = err instanceof AdapterError && err.definite;
      // A failed read changed nothing, whatever the reason. A write that may have landed is unknown, and stays unknown until reconciled.
      state = definite || op.effect === 'read' ? 'failed' : 'unknown';
      error = {
        code: err instanceof AdapterError ? err.code : 'execution_error',
        message: state === 'unknown'
          ? 'The outcome is unknown. Do not retry; this action must be reconciled against the downstream system.'
          : err instanceof AdapterError ? err.message : 'The tool call failed.',
      };
      if (err instanceof AdapterError && err.result !== undefined) result = err.result;
    }

    // The result is data from outside the decision boundary. Check it before the agent sees it.
    let withheld: Reason | null = null;
    let canonical = '';
    try {
      canonical = canonicalize(result);
    } catch {
      withheld = { code: 'invalid_response', message: 'The tool returned a value that is not valid JSON; it was withheld.' };
    }
    if (!withheld && Buffer.byteLength(canonical) > policy.limits.max_result_bytes) {
      withheld = { code: 'result_too_large', message: 'The tool result exceeded the size limit and was withheld.' };
    }
    if (!withheld && state === 'succeeded' && op.output_schema) {
      const violations = validate(op.output_schema, result);
      if (violations.length) withheld = { code: 'invalid_response', message: 'The tool result did not match its reviewed schema and was withheld.' };
    }
    if (withheld) result = null;

    const findings = scanJson(result, { minConfidence: policy.detection.min_confidence, detectors: this.detectors });
    const secrets = findings.filter((f) => f.category === 'SECRET' && !f.in_key);
    const resultRedacted = secrets.length > 0;
    if (resultRedacted) result = redactJson(result, secrets, new PlaceholderAllocator());
    const injection = detectInjectionJson(result);
    const destination = this.catalog.destination(tenant, action.destination_id);
    const untrusted = tool.manifest.kind === 'mcp' || destination?.class !== 'internal' || injection.score >= policy.injection.taint_threshold;
    const labels = unique([
      ...(op.effect === 'read' ? this.catalog.labelsFor(tenant, action.resource_id) : []),
      ...findings.map((f) => policy.detection.finding_labels[f.category]).filter((l): l is string => typeof l === 'string'),
    ]);
    this.catalog.recordExposure(tenant, action.task_id, { labels, untrusted, injection: injection.score });

    const categories = categoriesOf(findings);
    return finish(
      state,
      { result, untrusted_content: untrusted, injection: injection.signals.length ? injection : null, result_redacted: resultRedacted, error: error ?? withheld },
      {
        result_digest: withheld ? null : digest(result),
        provider_ref: providerRef,
        error_code: error?.code ?? withheld?.code ?? null,
        injection_score: injection.score,
        result_redacted: resultRedacted,
      },
      categories,
    );
  }

  /** Authorize and, if permitted, execute. What the SDKs call. */
  async run(p: Principal, raw: Json, opts: { approvalId?: string; reuseKey?: string } = {}): Promise<RunResponse> {
    const decision = this.authorize(p, raw, opts);
    if (decision.decision !== 'allow' && decision.decision !== 'redact') return { decision, execution: null };
    const action = decision.transformed_action ?? { ...(raw as JsonObject) };
    return { decision, execution: await this.execute(p, action as unknown as Json, decision.permit!) };
  }

  /** Settle an action whose outcome was unknown, once someone has checked the downstream system. */
  reconcile(p: Principal, actionId: string, outcome: 'succeeded' | 'failed', evidence: string): StoredEvent {
    requirePermission(p, 'operator:block');
    return this.store.tx(() => {
      if (!this.intents.transition(p.tenant_id, actionId, ['unknown', 'executing'], outcome)) {
        throw new ShieldError(409, 'not_reconcilable', 'Only actions with an unknown outcome can be reconciled.');
      }
      if (outcome === 'succeeded') this.ledger.commit(p.tenant_id, actionId);
      else this.ledger.release(p.tenant_id, actionId);
      return this.audit.append(p.tenant_id, { event_type: 'execution.reconciled', action_id: actionId, detail: { outcome, evidence: String(evidence).slice(0, 500), by: p.principal_id } });
    });
  }

  /** Stop an action that has been decided but not yet executed. */
  blockAction(p: Principal, actionId: string, reason: string): { state: string; event_id: string } {
    requirePermission(p, 'operator:block');
    return this.store.tx(() => {
      if (!this.intents.transition(p.tenant_id, actionId, ['pending', 'approved', 'reserved'], 'denied')) {
        const i = this.intents.get(p.tenant_id, actionId);
        if (!i) throw new ShieldError(404, 'action_not_found', 'No such action.');
        throw new ShieldError(409, 'not_blockable', `Action is already ${i.state}.`, { state: i.state });
      }
      this.ledger.release(p.tenant_id, actionId);
      this.store.run(`UPDATE approvals SET status='superseded' WHERE tenant_id=? AND action_id=? AND status IN ('pending','approved')`, p.tenant_id, actionId);
      const e = this.audit.append(p.tenant_id, { event_type: 'action.blocked', action_id: actionId, detail: { reason: String(reason).slice(0, 500), by: p.principal_id } });
      return { state: 'denied', event_id: e.event_id };
    });
  }

  /** Expire unused permits and approvals, release their reservations, and drop expired vault entries. */
  housekeeping(): { expired: number; purged: number } {
    return this.store.tx(() => {
      const stale = this.intents.expireStale();
      for (const s of stale) this.ledger.release(s.tenant_id, s.action_id);
      return { expired: stale.length, purged: this.vault.purgeExpired() };
    });
  }

  // ───────────────────────────── approvals ─────────────────────────────

  /** What an approver is shown: the approval and the exact action it covers. */
  getApproval(p: Principal, approvalId: string): { approval: Approval; action: BoundAction | null; risk_level: string | null; reasons: Reason[] } {
    const a = this.approvals.get(p.tenant_id, approvalId);
    if (!a) throw new ShieldError(404, 'approval_not_found', 'No such approval.');
    const mine = a.requested_by === p.principal_id;
    if (!mine) requirePermission(p, 'operator:approve');
    const intent = this.intents.get(p.tenant_id, a.action_id);
    const current = intent?.action_digest === a.action_digest ? intent : undefined;
    return { approval: a, action: mine && !p.permissions.includes('operator:approve') ? null : (current?.action ?? null), risk_level: current?.response.risk_level ?? null, reasons: current?.response.reasons ?? [] };
  }

  listApprovals(p: Principal, status?: string): Approval[] {
    requirePermission(p, 'operator:approve');
    return this.approvals.list(p.tenant_id, status);
  }

  /** Look up the approval opened for a decision. Idempotent; the agent-facing `request_human_approval`. */
  requestApproval(p: Principal, decisionId: string, digestClaim: string): Approval {
    requirePermission(p, 'agent:request');
    const r = this.store.get<{ approval_id: string }>(
      `SELECT approval_id FROM approvals WHERE tenant_id=? AND decision_id=? AND action_digest=? AND requested_by=? ORDER BY created_at DESC LIMIT 1`,
      p.tenant_id, decisionId, digestClaim, p.principal_id,
    );
    if (!r) throw new ShieldError(404, 'approval_not_found', 'No approval is open for that decision and action digest.');
    return this.approvals.get(p.tenant_id, r.approval_id)!;
  }

  decideApproval(p: Principal, approvalId: string, verdict: 'approve' | 'reject', reviewedDigest: string, reason?: string): Approval {
    requirePermission(p, 'operator:approve');
    if (verdict !== 'approve' && verdict !== 'reject') throw new ShieldError(422, 'invalid_verdict', 'verdict must be approve or reject.');
    return this.store.tx(() => {
      const a = this.approvals.decide(p.tenant_id, approvalId, p.principal_id, verdict, reviewedDigest, reason);
      if (verdict === 'approve') this.intents.transition(p.tenant_id, a.action_id, 'pending', 'approved');
      else this.intents.transition(p.tenant_id, a.action_id, ['pending', 'approved'], 'denied');
      this.audit.append(p.tenant_id, {
        event_type: verdict === 'approve' ? 'approval.approved' : 'approval.rejected', action_id: a.action_id, decision_id: a.decision_id,
        detail: { approval_id: a.approval_id, action_digest: a.action_digest, approver: p.principal_id },
      });
      return a;
    });
  }

  // ───────────────────────────── scanning ─────────────────────────────

  private payloadOf(tenant: string, body: Json): Json {
    if (!isObject(body) || body.payload === undefined) throw new ShieldError(422, 'invalid_field', 'Field "payload" is required.');
    const size = typeof body.payload === 'string' ? Buffer.byteLength(body.payload) : Buffer.byteLength(canonicalize(body.payload));
    if (size > this.limits(tenant).max_result_bytes) throw new ShieldError(413, 'payload_too_large', 'Payload exceeds the size limit.');
    return body.payload;
  }

  /** Task state may only be written by an agent that holds a grant for that task. Otherwise one agent could taint another's work. */
  private requireTask(p: Principal, taskId: string): void {
    if (!this.grants.resolve(p.tenant_id, p.principal_id, taskId)) {
      throw new ShieldError(403, 'no_active_grant', 'This credential has no active grant for that task.');
    }
  }

  private scanAny(tenant: string, payload: Json): Finding[] {
    const opts = { minConfidence: (this.policies.active(tenant)?.bundle ?? DEFAULT_POLICY).detection.min_confidence, detectors: this.detectors };
    return typeof payload === 'string' ? scanText(payload, opts) : scanJson(payload, opts);
  }

  /**
   * Scan content the agent has pulled in from outside (a web page, an email,
   * a retrieved document). Records against the task that it has now seen
   * untrusted content, and what that content looked like.
   */
  scanInput(p: Principal, body: Json): JsonObject {
    requirePermission(p, 'agent:scan');
    this.throttle(p);
    const payload = this.payloadOf(p.tenant_id, body);
    const b = body as JsonObject;
    const policy = this.policies.active(p.tenant_id)?.bundle ?? DEFAULT_POLICY;
    const findings = this.scanAny(p.tenant_id, payload);
    const injection = typeof payload === 'string' ? detectInjection(payload) : detectInjectionJson(payload);
    const scanId = newId('scn');
    if (typeof b.task_id === 'string' && b.task_id) {
      this.requireTask(p, b.task_id);
      const labels = unique(findings.map((f) => policy.detection.finding_labels[f.category]).filter((l): l is string => typeof l === 'string'));
      this.catalog.recordExposure(p.tenant_id, b.task_id, { labels, untrusted: true, injection: injection.score });
    }
    if (findings.length || injection.score >= policy.injection.taint_threshold) {
      this.audit.append(p.tenant_id, {
        event_type: 'scan.input_flagged', agent_id: p.principal_id, finding_categories: categoriesOf(findings),
        detail: { scan_id: scanId, injection_score: injection.score, signals: injection.signals.map((s) => s.id), source_ref: typeof b.source_id === 'string' ? this.audit.ref(p.tenant_id, b.source_id) : null },
      });
    }
    return {
      scan_id: scanId, findings: findings as unknown as Json, injection: injection as unknown as Json,
      provenance: { source_id: typeof b.source_id === 'string' ? b.source_id : null, trusted: false, tainted: injection.score >= policy.injection.taint_threshold },
      model_version: DETECTOR_VERSION,
    };
  }

  /** Would this content be allowed to go to that destination? A pre-flight check; the binding decision is still `authorize`. */
  scanOutput(p: Principal, body: Json): JsonObject {
    requirePermission(p, 'agent:scan');
    this.throttle(p);
    const payload = this.payloadOf(p.tenant_id, body);
    const b = body as JsonObject;
    const policy = this.policies.active(p.tenant_id)?.bundle ?? DEFAULT_POLICY;
    const findings = this.scanAny(p.tenant_id, payload);
    const dest = typeof b.destination_id === 'string' ? this.catalog.destination(p.tenant_id, b.destination_id) : null;
    const labels = unique(findings.map((f) => policy.detection.finding_labels[f.category]).filter((l): l is string => typeof l === 'string'));
    const top = highestLabel(policy, labels);
    let verdict: 'allow' | 'redact' | 'block' = 'allow';
    const escalate = (v: 'redact' | 'block') => {
      if (v === 'block' || verdict === 'allow') verdict = v;
    };
    if (!dest || dest.state !== 'approved') verdict = 'block';
    else {
      for (const f of findings) {
        if (f.category === 'SECRET') escalate(policy.data_flow.secrets);
        else if (!dest.accepts.includes('PII') && policy.data_flow.pii !== 'allow') escalate(policy.data_flow.pii);
      }
      // After redaction the finding-derived labels would be gone, so they only block when redaction is not on offer.
      if (verdict === 'allow' && top && labelRank(policy, top) > ceilingRank(policy, dest.max_label)) verdict = 'block';
    }
    return { scan_id: newId('scn'), findings: findings as unknown as Json, verdict, model_version: DETECTOR_VERSION };
  }

  detectSensitive(p: Principal, body: Json): JsonObject {
    requirePermission(p, 'agent:scan');
    this.throttle(p);
    const payload = this.payloadOf(p.tenant_id, body);
    const types = isObject(body) && Array.isArray(body.entity_types) ? new Set(body.entity_types) : null;
    const spans = this.scanAny(p.tenant_id, payload).filter((f) => !types || types.has(f.type) || types.has(f.category));
    return { spans: spans as unknown as Json, model_version: DETECTOR_VERSION };
  }

  /** Replace findings with placeholders. With a task_id, the originals are sealed in the local vault under the returned scan_id. */
  redact(p: Principal, body: Json): JsonObject {
    requirePermission(p, 'agent:scan');
    this.throttle(p);
    const payload = this.payloadOf(p.tenant_id, body);
    const findings = this.scanAny(p.tenant_id, payload);
    const alloc = new PlaceholderAllocator();
    const transformed = typeof payload === 'string' ? redactText(payload, findings, alloc) : redactJson(payload, findings.filter((f) => !f.in_key), alloc);
    const unresolved = this.scanAny(p.tenant_id, transformed).length + findings.filter((f) => f.in_key).length;
    const scanId = newId('scn');
    const b = body as JsonObject;
    if (typeof b.task_id === 'string' && b.task_id && alloc.replacements.length) {
      this.requireTask(p, b.task_id);
      this.vault.put(p.tenant_id, b.task_id, scanId, alloc.replacements, this.limits(p.tenant_id).max_action_ttl_seconds * 1000);
    }
    return { scan_id: scanId, transformed_payload: transformed, digest: digest(transformed), findings: findings as unknown as Json, unresolved, model_version: DETECTOR_VERSION };
  }

  detectInjection(p: Principal, body: Json): JsonObject {
    requirePermission(p, 'agent:scan');
    this.throttle(p);
    const payload = this.payloadOf(p.tenant_id, body);
    const r: InjectionResult = typeof payload === 'string' ? detectInjection(payload) : detectInjectionJson(payload);
    return { score: r.score, signals: r.signals as unknown as Json, model_version: 'heuristics-1' };
  }

  revealPlaceholder(p: Principal, taskId: string, scopeRef: string, placeholder: string): string {
    requirePermission(p, 'vault:reveal');
    const value = this.vault.reveal(p.tenant_id, taskId, scopeRef, placeholder);
    this.audit.append(p.tenant_id, { event_type: 'vault.reveal', detail: { by: p.principal_id, scope_ref: scopeRef, placeholder, found: value !== null } });
    if (value === null) throw new ShieldError(404, 'not_found', 'No such placeholder, or it has expired.');
    return value;
  }

  // ───────────────────────────── administration ─────────────────────────────

  createPrincipal(p: Principal, principalId: string, role: Role, opts: { sponsor?: string; displayName?: string; extra?: Permission[] } = {}): string {
    requirePermission(p, 'admin:principals');
    const credential = this.identity.createPrincipal(p.tenant_id, principalId, role, opts);
    this.audit.append(p.tenant_id, { event_type: 'principal.created', agent_id: role === 'agent' ? principalId : null, detail: { principal_id: principalId, role, by: p.principal_id } });
    return credential;
  }

  createGrant(p: Principal, req: GrantRequest): Grant {
    requirePermission(p, 'admin:grants');
    return this.store.tx(() => {
      const g = this.grants.createRoot(p.tenant_id, req, p.principal_id);
      this.audit.append(p.tenant_id, { event_type: 'grant.created', agent_id: g.agent_id, grant_revision: g.revision, detail: { grant_id: g.grant_id, scope_digest: digest(g.scope as unknown as Json), by: p.principal_id } });
      return g;
    });
  }

  /** An agent passes part of its grant to another agent. Refused, and recorded, if the child would exceed the parent. */
  delegate(p: Principal, parentTaskId: string, req: GrantRequest): Grant {
    requirePermission(p, 'agent:delegate');
    try {
      return this.store.tx(() => {
        const g = this.grants.delegate(p.tenant_id, p.principal_id, parentTaskId, req, this.limits(p.tenant_id).max_delegation_depth);
        this.audit.append(p.tenant_id, { event_type: 'grant.delegated', agent_id: g.agent_id, grant_revision: g.revision, detail: { grant_id: g.grant_id, parent_grant_id: g.parent_grant_id, scope_digest: digest(g.scope as unknown as Json), by: p.principal_id } });
        return g;
      });
    } catch (err) {
      if (err instanceof ShieldError && err.code === 'delegation_denied') {
        this.audit.append(p.tenant_id, { event_type: 'delegation.denied', agent_id: p.principal_id, detail: { child_ref: this.audit.ref(p.tenant_id, String(req?.agent_id)), violations: (err.details as JsonObject)?.violations ?? [] } });
      }
      throw err;
    }
  }

  revokeGrant(p: Principal, grantId: string): Grant {
    requirePermission(p, 'admin:grants');
    return this.store.tx(() => {
      const g = this.grants.revoke(p.tenant_id, grantId);
      this.audit.append(p.tenant_id, { event_type: 'grant.revoked', agent_id: g.agent_id, grant_revision: g.revision, detail: { grant_id: grantId, by: p.principal_id } });
      return g;
    });
  }

  suspendAgent(p: Principal, agentId: string, reason: string, expectedEpoch?: number): AgentRecord {
    requirePermission(p, 'operator:suspend');
    return this.store.tx(() => {
      const a = this.identity.setAgentStatus(p.tenant_id, agentId, 'suspended', expectedEpoch);
      this.audit.append(p.tenant_id, { event_type: 'agent.suspended', agent_id: agentId, detail: { reason: String(reason).slice(0, 500), revocation_epoch: a.revocation_epoch, by: p.principal_id } });
      return a;
    });
  }

  resumeAgent(p: Principal, agentId: string): AgentRecord {
    requirePermission(p, 'operator:suspend');
    return this.store.tx(() => {
      const a = this.identity.setAgentStatus(p.tenant_id, agentId, 'active');
      this.audit.append(p.tenant_id, { event_type: 'agent.resumed', agent_id: agentId, detail: { revocation_epoch: a.revocation_epoch, by: p.principal_id } });
      return a;
    });
  }

  registerTool(p: Principal, manifest: Json): { tool: ToolRecord; warnings: string[] } {
    requirePermission(p, 'admin:tools');
    return this.store.tx(() => {
      const out = this.tools.register(p.tenant_id, manifest, p.principal_id);
      this.audit.append(p.tenant_id, { event_type: 'tool.registered', tool_revision: out.tool.schema_hash, detail: { tool_id: out.tool.tool_id, kind: out.tool.manifest.kind, by: p.principal_id } });
      return out;
    });
  }

  /** Operations of a pinned MCP tool whose live upstream definition is missing or different. */
  private async drift(tool: ToolRecord): Promise<string[]> {
    const live = new Map((await this.mcp.listTools(tool)).map((t) => [t.name, upstreamFingerprint(t)]));
    return Object.entries(tool.manifest.operations)
      .filter(([name, op]) => live.get(name) !== pinnedFingerprint(name, op))
      .map(([name]) => (live.has(name) ? `${name}: definition changed` : `${name}: no longer offered`));
  }

  quarantineTool(p: Principal | null, tenant: string, toolId: string, reason: string): ToolRecord {
    if (p) requirePermission(p, 'operator:tools');
    return this.store.tx(() => {
      const t = this.tools.setState(tenant, toolId, 'quarantined', reason.slice(0, 500));
      this.audit.append(tenant, { event_type: 'tool.quarantined', tool_revision: t.schema_hash, detail: { tool_id: toolId, reason: reason.slice(0, 500), by: p?.principal_id ?? 'gateway' } });
      return t;
    });
  }

  /**
   * Approve the reviewed revision of a tool. For an MCP server this first
   * fetches the live tool definitions and refuses if they differ from the
   * manifest under review.
   */
  async verifyTool(p: Principal, toolId: string, expectedRevision: string): Promise<ToolRecord> {
    requirePermission(p, 'operator:tools');
    const tool = this.tools.get(p.tenant_id, toolId);
    if (!tool) throw new ShieldError(404, 'tool_not_found', 'No such tool.');
    if (tool.manifest.kind === 'mcp') {
      let drift: string[];
      try {
        drift = await this.drift(tool);
      } catch (err) {
        throw new ShieldError(503, 'upstream_unavailable', `Could not reach the MCP server to verify it: ${(err as Error).message}`.slice(0, 300));
      }
      if (drift.length) {
        if (tool.state === 'approved') this.quarantineTool(null, p.tenant_id, toolId, `upstream drift: ${drift.join('; ')}`);
        throw new ShieldError(409, 'upstream_drift', 'The live MCP server does not match the manifest under review.', { drift });
      }
    }
    return this.store.tx(() => {
      const t = this.tools.approve(p.tenant_id, toolId, expectedRevision, p.principal_id, this.twoPerson);
      this.audit.append(p.tenant_id, { event_type: 'tool.verified', tool_revision: t.schema_hash, detail: { tool_id: toolId, by: p.principal_id } });
      return t;
    });
  }

  /** Re-check an approved MCP tool against its upstream, at most once a minute. Quarantines on drift. */
  async checkDrift(tenant: string, toolId: string): Promise<ToolRecord | undefined> {
    const tool = this.tools.get(tenant, toolId);
    if (!tool || tool.manifest.kind !== 'mcp' || tool.state !== 'approved') return tool;
    const key = `${tenant}\0${toolId}\0${tool.schema_hash}`;
    if ((this.driftChecked.get(key) ?? 0) > this.clock.now() - 60_000) return tool;
    let drift: string[];
    try {
      drift = await this.drift(tool);
    } catch {
      return tool; // Unreachable is not drift; calls will fail on their own.
    }
    this.driftChecked.set(key, this.clock.now());
    if (!drift.length) {
      this.tools.touch(tenant, toolId);
      return tool;
    }
    return this.quarantineTool(null, tenant, toolId, `upstream drift: ${drift.join('; ')}`);
  }

  createPolicy(p: Principal, signed: SignedBundle): PolicyRecord {
    requirePermission(p, 'admin:policy');
    return this.store.tx(() => {
      const r = this.policies.create(p.tenant_id, signed, p.principal_id);
      this.audit.append(p.tenant_id, { event_type: 'policy.created', policy_version: r.version, detail: { policy_id: r.policy_id, bundle_digest: r.bundle_digest, by: p.principal_id } });
      return r;
    });
  }

  activatePolicy(p: Principal, policyId: string, version: number): PolicyRecord {
    requirePermission(p, 'admin:policy');
    return this.store.tx(() => {
      const previous = this.policies.active(p.tenant_id);
      const r = this.policies.activate(p.tenant_id, policyId, version, p.principal_id, this.twoPerson);
      this.audit.append(p.tenant_id, {
        event_type: previous && previous.policy_id === policyId && previous.version > version ? 'policy.rolled_back' : 'policy.activated',
        policy_version: r.version, detail: { policy_id: r.policy_id, bundle_digest: r.bundle_digest, previous_version: previous?.version ?? null, by: p.principal_id },
      });
      return r;
    });
  }

  revokePolicy(p: Principal, policyId: string, version: number): void {
    requirePermission(p, 'admin:policy');
    this.store.tx(() => {
      this.policies.revoke(p.tenant_id, policyId, version);
      this.audit.append(p.tenant_id, { event_type: 'policy.revoked', policy_version: version, detail: { policy_id: policyId, by: p.principal_id } });
    });
  }

  /**
   * Run synthetic cases against a policy version without activating it and
   * without recording anything. Each case names the agent to evaluate as.
   */
  testPolicy(p: Principal, policyId: string, version: number, cases: Json): JsonObject {
    requirePermission(p, 'admin:policy');
    const record = this.policies.get(p.tenant_id, policyId, version);
    if (!record) throw new ShieldError(404, 'policy_not_found', 'No such policy version.');
    if (!Array.isArray(cases)) throw new ShieldError(422, 'invalid_field', 'synthetic_cases must be a list.');
    const limits = record.bundle.limits;
    const results = cases.slice(0, 500).map((c, i) => {
      const name = isObject(c) && typeof c.name === 'string' ? c.name : `case_${i + 1}`;
      try {
        if (!isObject(c) || typeof c.agent_id !== 'string') throw new Error('each case needs agent_id and action');
        const env = validateEnvelope(c.action ?? null, this.clock.now(), { maxArgumentsBytes: limits.max_arguments_bytes, maxTtlMs: limits.max_action_ttl_seconds * 1000 });
        const as: Principal = { tenant_id: p.tenant_id, principal_id: c.agent_id, role: 'agent', permissions: [] };
        const ev = this.evaluate(as, env, record);
        const actual = ev.outcome.effect === 'allow' && ev.redacted ? 'redact' : ev.outcome.effect;
        const expect = typeof c.expect === 'string' ? c.expect : null;
        return { name, decision: actual, risk_level: ev.outcome.riskLevel, reason_codes: ev.outcome.reasons.map((r) => r.code), expect, passed: expect === null ? null : expect === actual };
      } catch (err) {
        return { name, decision: null, error: (err as Error).message, expect: isObject(c) && typeof c.expect === 'string' ? c.expect : null, passed: false };
      }
    });
    const withExpectation = results.filter((r) => r.expect !== null);
    return { results: results as unknown as Json, total: results.length, passed: withExpectation.filter((r) => r.passed).length, failed: withExpectation.filter((r) => !r.passed).length };
  }

  // ───────────────────────────── evidence ─────────────────────────────

  getEvent(p: Principal, eventId: string): StoredEvent {
    requirePermission(p, 'auditor:read');
    const e = this.audit.get(p.tenant_id, eventId);
    if (!e) throw new ShieldError(404, 'event_not_found', 'No such event.');
    return e;
  }

  listEvents(p: Principal, opts: { after?: number; limit?: number; agentId?: string; actionId?: string; type?: string } = {}): { items: StoredEvent[]; next_cursor: number | null } {
    requirePermission(p, 'auditor:read');
    const limit = Math.min(Math.max(opts.limit ?? 100, 1), 1000);
    const items = this.audit.list(p.tenant_id, { ...opts, limit });
    return { items, next_cursor: items.length === limit ? items[items.length - 1]!.sequence : null };
  }

  /** Decisions about one agent that were not a plain allow, newest sequence last. */
  listAgentRisks(p: Principal, agentId: string, opts: { after?: number; limit?: number } = {}): { items: JsonObject[]; next_cursor: number | null } {
    requirePermission(p, 'auditor:read');
    const limit = Math.min(Math.max(opts.limit ?? 100, 1), 1000);
    const all = this.audit.list(p.tenant_id, { agentId, after: opts.after, limit: 1000 });
    const risky = all.filter((e) => ['decision.blocked', 'decision.approval_required', 'execution.denied', 'execution.unknown', 'delegation.denied', 'scan.input_flagged', 'agent.suspended'].includes(e.event_type)
      || (e.event_type === 'permit.issued' && e.detail.risk_level !== 'low'));
    const items = risky.slice(0, limit).map((e) => ({
      event_id: e.event_id, sequence: e.sequence, timestamp: e.timestamp, event_type: e.event_type, action_id: e.action_id,
      risk_level: (e.detail.risk_level as string) ?? null, risk_score: (e.detail.risk_score as number) ?? null,
      reason_codes: (e.detail.reason_codes as Json) ?? [], finding_categories: e.finding_categories,
    }));
    return { items, next_cursor: risky.length > limit ? items[items.length - 1]!.sequence as number : null };
  }

  verifyAudit(p: Principal, checkpoints: Checkpoint[] = []): JsonObject {
    requirePermission(p, 'auditor:read');
    const chain = this.audit.verify(p.tenant_id);
    const cps = this.audit.verifyCheckpoints(p.tenant_id, checkpoints);
    return { ok: chain.ok && cps.ok, chain: chain as unknown as Json, checkpoints: cps as unknown as Json };
  }

  checkpoint(p: Principal): Checkpoint | null {
    requirePermission(p, 'auditor:report');
    return this.audit.checkpoint(p.tenant_id);
  }

  /** Summary for a time range: event counts, chain integrity, and anything still unresolved. */
  report(p: Principal, from: string, to: string): JsonObject {
    requirePermission(p, 'auditor:report');
    const fromMs = Date.parse(from);
    const toMs = Date.parse(to);
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs <= fromMs) throw new ShieldError(422, 'invalid_range', 'range needs ISO "from" and "to" with to after from.');
    const counts = this.audit.counts(p.tenant_id, fromMs, toMs);
    const sum = (prefix: string) => Object.entries(counts).filter(([k]) => k.startsWith(prefix)).reduce((s, [, n]) => s + n, 0);
    return {
      report_id: newId('rpt'), generated_at: iso(this.clock.now()), range: { from: iso(fromMs), to: iso(toMs) },
      summary: {
        permits_issued: counts['permit.issued'] ?? 0, blocked: counts['decision.blocked'] ?? 0, approvals_required: counts['decision.approval_required'] ?? 0,
        approvals_granted: counts['approval.approved'] ?? 0, approvals_rejected: counts['approval.rejected'] ?? 0, executions: sum('execution.'),
        executions_unknown: counts['execution.unknown'] ?? 0, tools_quarantined: counts['tool.quarantined'] ?? 0, agents_suspended: counts['agent.suspended'] ?? 0,
      },
      event_counts: counts,
      integrity: this.audit.verify(p.tenant_id) as unknown as Json,
      unresolved_actions: this.intents.unresolved(p.tenant_id).map((i) => ({ action_id: i.action_id, state: i.state, tool_id: i.action.tool_id, operation: i.action.operation })),
      policy: (() => {
        const a = this.policies.active(p.tenant_id);
        return a ? { policy_id: a.policy_id, version: a.version, bundle_digest: a.bundle_digest } : null;
      })(),
    };
  }
}

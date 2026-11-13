/**
 * The policy decision point.
 *
 * `decide` is a pure function of trusted context. It starts from "deny" and
 * only reaches "allow" by passing every check; every denial that applies is
 * collected, so the audit record says all the reasons, not just the first.
 *
 * Order matters and encodes the design's invariants:
 *   1. identity, grant, tool and scope — things approval can never override;
 *   2. money and data-flow limits — likewise not overridable;
 *   3. findings — block, or ask the caller to redact and come back;
 *   4. risk and approval — only for actions that survived everything above.
 */
import { matchAny } from '../core/util.ts';
import type { BoundAction, Destination, Finding, Grant, OperationSpec, Reason, RiskClass, RiskResult, TaskContext, ToolRecord } from '../core/types.ts';
import type { ClassRule, PolicyBundle } from './bundle.ts';
import { ceilingRank, highestLabel, labelRank, maxRisk } from './risk.ts';

export interface PolicyInput {
  action: BoundAction;
  identityVerified: boolean;
  agentStatus: 'active' | 'suspended' | 'unknown';
  grant: Grant | null;
  tool: ToolRecord | null;
  /** The caller named a revision and it is not the pinned one. */
  revisionMismatch: boolean;
  op: OperationSpec | null;
  schemaErrors: string[];
  /** The envelope's resource or destination disagrees with what the arguments, or the tool's registration, say. */
  bindingErrors: string[];
  destination: Destination | null;
  /** Labels on the resource and in the payload. */
  labels: string[];
  /** Labels on the resource alone, from the catalog. */
  resourceLabels: string[];
  findings: Finding[];
  task: TaskContext;
  amount: { minor: number; currency: string } | null;
  amountError: string | null;
  /** Unspent budget across the grant and every ancestor; null when the grant carries no budget. */
  budgetRemaining: number | null;
  /** Currency of the nearest budget in the chain. */
  budgetCurrency: string | null;
  risk: RiskResult;
  now: number;
}

export interface PolicyOutcome {
  effect: 'allow' | 'redact' | 'require_approval' | 'block';
  reasons: Reason[];
  /** Findings the caller should redact before re-evaluating. Only set when effect is `redact`. */
  redact: Finding[];
  riskLevel: RiskClass;
  obligations: string[];
}

export function classRule(policy: PolicyBundle, op: OperationSpec | null): ClassRule {
  return op && Object.hasOwn(policy.operation_classes, op.class) ? policy.operation_classes[op.class]! : policy.default_class;
}

export function decide(policy: PolicyBundle, input: PolicyInput): PolicyOutcome {
  const deny: Reason[] = [];
  const no = (code: string, message: string) => deny.push({ code, message });
  const { action, grant, tool, op, destination } = input;
  const rule = classRule(policy, op);

  // 1. Who is asking, and were they ever allowed to.
  if (!input.identityVerified) no('identity_unverified', 'Caller identity could not be verified.');
  if (input.agentStatus === 'suspended') no('agent_suspended', 'Agent is suspended.');
  if (input.agentStatus === 'unknown') no('agent_unknown', 'Agent is not in the inventory.');

  if (!grant) {
    no('no_active_grant', 'No active grant covers this agent and task.');
  } else {
    const outside: string[] = [];
    if (!matchAny(grant.scope.tools, action.tool_id)) outside.push('tool');
    if (!matchAny(grant.scope.operations, action.operation)) outside.push('operation');
    if (!matchAny(grant.scope.resources, action.resource_id)) outside.push('resource');
    if (!matchAny(grant.scope.destinations, action.destination_id)) outside.push('destination');
    if (outside.length) no('outside_grant', `${capitalize(outside.join(', '))} outside the task grant.`);
  }

  if (!tool) no('tool_unregistered', 'Tool is not in the approved registry.');
  else if (tool.state !== 'approved') no('tool_not_approved', `Tool is ${tool.state}.`);
  else if (input.revisionMismatch) no('tool_revision_mismatch', 'Tool revision does not match the reviewed, pinned revision.');
  else if (tool.manifest.expires_at && Date.parse(tool.manifest.expires_at) <= input.now) no('tool_expired', 'Tool approval has expired.');
  if (tool && !op) no('operation_unknown', 'Operation is not part of the reviewed tool manifest.');
  if (input.bindingErrors.length) no('binding_mismatch', input.bindingErrors.join(' '));
  if (op && rule.deny) no('operation_class_denied', `Operations of class "${op.class}" are not available to agents.`);
  if (input.schemaErrors.length) no('invalid_arguments', `Arguments are outside the permitted envelope: ${input.schemaErrors.slice(0, 3).join('; ')}`);

  // 2. Money.
  if (input.amountError) no('invalid_amount', input.amountError);
  if (op && rule.requires_amount && !input.amount && !input.amountError) no('amount_required', 'This operation requires an integer amount in minor units and a currency.');
  if (input.amount && grant) {
    const cap = grant.scope.max_per_action_minor;
    if (cap === undefined || input.budgetRemaining === null) no('no_spending_authority', 'The grant carries no spending authority.');
    else {
      if (input.budgetCurrency !== input.amount.currency) no('currency_mismatch', 'Currency does not match the grant.');
      if (input.amount.minor > cap) no('exceeds_per_action_limit', 'Amount exceeds the verified grant; routine approval cannot override this.');
      if (input.amount.minor > input.budgetRemaining) no('budget_exceeded', 'Amount exceeds the remaining shared budget; routine approval cannot override this.');
    }
  }

  // 2b. Where the data may go.
  const cls = op?.class ?? '';
  if (policy.data_flow.destination_required_for.includes(cls)) {
    if (!destination) no('destination_unknown', 'Destination is not in the catalog; it must be onboarded before it can be used or approved.');
    else if (destination.state !== 'approved') no('destination_not_approved', `Destination is ${destination.state}.`);
  } else if (destination?.state === 'blocked') {
    no('destination_not_approved', 'Destination is blocked.');
  }
  // Labels that travel with the resource and the task. Labels implied by findings in the payload are dealt with
  // in step 3 — a secret that is about to be redacted must not also fail the destination's label ceiling.
  const flowLabels = policy.data_flow.propagate_task_labels_to.includes(cls) ? [...input.resourceLabels, ...input.task.labels] : input.resourceLabels;
  const top = highestLabel(policy, flowLabels);
  if (destination && top && labelRank(policy, top) > ceilingRank(policy, destination.max_label)) {
    no('label_exceeds_destination', `Data labelled ${top} may not be sent to this destination.`);
  }

  // 3. What is in the payload.
  const redact: Finding[] = [];
  for (const f of input.findings) {
    const mode =
      f.category === 'SECRET' ? policy.data_flow.secrets
      : destination?.accepts.includes('PII') ? 'allow'
      : policy.data_flow.pii;
    if (mode === 'allow') continue;
    if (mode === 'redact' && rule.redaction === 'allow' && !f.in_key) redact.push(f);
    else if (f.category === 'SECRET') no('secret_in_payload', 'Payload contains a credential, which is prohibited here.');
    else no('pii_in_payload', 'Payload contains personal data this destination may not receive.');
  }

  if (deny.length) return { effect: 'block', reasons: dedupe(deny), redact: [], riskLevel: 'critical', obligations: [] };
  if (redact.length) {
    return {
      effect: 'redact', redact, riskLevel: input.risk.class, obligations: [],
      reasons: [{ code: 'redaction_required', message: 'Prohibited content must be replaced with placeholders before this can proceed.' }],
    };
  }

  // 4. Risk, then approval.
  if (input.risk.class === 'critical') {
    return { effect: 'block', riskLevel: 'critical', redact: [], obligations: [], reasons: [{ code: 'risk_critical', message: 'Risk score is critical.' }] };
  }
  const approve: Reason[] = [];
  if (rule.approval === 'always') approve.push({ code: 'class_requires_approval', message: `Operations of class "${cls || 'unclassified'}" always need approval.` });
  if (op?.approval === 'always') approve.push({ code: 'tool_requires_approval', message: 'The tool owner requires approval for this operation.' });
  if (input.risk.class === 'high' && rule.approval !== 'never') approve.push({ code: 'risk_high', message: 'Risk score is high.' });
  if (destination?.class === 'external' && top && labelRank(policy, top) >= labelRank(policy, policy.data_flow.external_approval_label)) {
    approve.push({ code: 'sensitive_external_send', message: `Sending ${top} data outside the organisation is permitted only with approval.` });
  }
  // The label on the record being changed, from the catalog. Personal data that merely appears in what is
  // written is governed by whether the destination may receive it, not by this rule.
  const resourceTop = highestLabel(policy, input.resourceLabels);
  if (op?.effect === 'write' && cls === 'data_write' && resourceTop && labelRank(policy, resourceTop) >= labelRank(policy, policy.data_flow.write_approval_label)) {
    approve.push({ code: 'sensitive_write', message: `Changing ${resourceTop} records is permitted only with approval.` });
  }
  if (op?.effect === 'write' && input.task.max_injection >= policy.injection.taint_threshold) {
    if (policy.injection.tainted_write === 'block') {
      return { effect: 'block', riskLevel: 'critical', redact: [], obligations: [], reasons: [{ code: 'tainted_task', message: 'This task ingested content carrying injection signals; writes are blocked.' }] };
    }
    if (policy.injection.tainted_write === 'require_approval') {
      approve.push({ code: 'tainted_task', message: 'This task ingested content carrying injection signals; writes need approval.' });
    }
  }

  const obligations = ['log_result', 'validate_response'];
  if (input.risk.class !== 'low') obligations.push('scan_result');
  if (approve.length) return { effect: 'require_approval', reasons: approve, redact: [], riskLevel: maxRisk(input.risk.class, 'high'), obligations };
  return {
    effect: 'allow', redact: [], riskLevel: input.risk.class, obligations,
    reasons: [{ code: 'within_grant', message: 'Within grant and policy.' }],
  };
}

const capitalize = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

function dedupe(reasons: Reason[]): Reason[] {
  const seen = new Set<string>();
  return reasons.filter((r) => !seen.has(r.code) && seen.add(r.code));
}

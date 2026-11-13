/**
 * Interpretable weighted risk score, R = Σ wᵢ·xᵢ with weights totalling 100.
 *
 * The score only ranks actions that are otherwise permissible. It can add an
 * approval or a block; it can never turn a policy denial into an allow, and a
 * low score never widens a grant. Every input comes from the registry, the
 * catalog, the grant or measured behaviour — never from what the agent says
 * about itself.
 */
import { RISK_ORDER, type Destination, type Grant, type OperationSpec, type RiskClass, type RiskFactor, type RiskResult, type TaskContext } from '../core/types.ts';
import type { PolicyBundle } from './bundle.ts';

export interface RiskInput {
  labels: string[];
  op: OperationSpec | null;
  destination: Destination | null;
  grant: Grant | null;
  amountMinor: number | null;
  task: TaskContext;
  recentActions: number;
  recentDenials: number;
  now: number;
}

export function labelRank(policy: PolicyBundle, label: string): number {
  const i = policy.label_order.indexOf(label);
  return i === -1 ? policy.label_order.length : i;
}

/**
 * Rank of a destination's ceiling. Deliberately the opposite default from
 * `labelRank`: an unrecognised label on data is treated as most sensitive, an
 * unrecognised ceiling on a destination as clearing it for nothing.
 */
export function ceilingRank(policy: PolicyBundle, label: string): number {
  return policy.label_order.indexOf(label);
}

export function highestLabel(policy: PolicyBundle, labels: string[]): string | null {
  let best: string | null = null;
  for (const l of labels) if (best === null || labelRank(policy, l) > labelRank(policy, best)) best = l;
  return best;
}

export function classify(policy: PolicyBundle, score: number): RiskClass {
  const t = policy.risk.thresholds;
  return score >= t.critical ? 'critical' : score >= t.high ? 'high' : score >= t.moderate ? 'moderate' : 'low';
}

export const maxRisk = (a: RiskClass, b: RiskClass): RiskClass =>
  RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;

const clamp = (x: number): number => Math.max(0, Math.min(1, x));

export function scoreRisk(policy: PolicyBundle, input: RiskInput): RiskResult {
  const w = policy.risk.weights;
  const top = Math.max(1, policy.label_order.length - 1);
  const factors: RiskFactor[] = [];
  const add = (feature: RiskFactor['feature'], weight: number, value: number, note: string) => {
    const v = clamp(value);
    factors.push({ feature, weight, value: Math.round(v * 100) / 100, contribution: Math.round(weight * v * 10) / 10, note });
  };

  const label = highestLabel(policy, input.labels);
  const sens = label ? Math.min(1, labelRank(policy, label) / top) : 0;
  add('sensitivity', w.sensitivity, input.op?.privileged ? 1 : sens,
    input.op?.privileged ? 'privileged operation' : label ? `data labelled ${label}` : 'no sensitive label');

  // Unknown operation metadata is treated as the worst case, not the average one.
  let impact = 1;
  let impactNote = 'operation metadata unknown';
  if (input.op) {
    if (input.op.effect === 'read') {
      impact = 0;
      impactNote = 'read only';
    } else {
      const consequential = input.op.class === 'payment' || input.op.class === 'physical';
      impact = consequential ? 0.8 : input.op.reversible ? 0.4 : 0.7;
      impactNote = consequential ? `${input.op.class} action` : input.op.reversible ? 'reversible write' : 'irreversible write';
    }
    const cap = input.grant?.scope.max_per_action_minor;
    if (input.amountMinor !== null && cap) {
      impact = Math.max(impact, 0.5 + 0.5 * clamp(input.amountMinor / cap));
      impactNote += `, ${Math.round(clamp(input.amountMinor / cap) * 100)}% of per-action limit`;
    }
  }
  add('impact', w.impact, impact, impactNote);

  const d = input.destination;
  add('destination', w.destination,
    !d || d.state !== 'approved' ? 1 : d.class === 'internal' ? 0 : 0.5,
    !d ? 'destination not in catalog' : d.state !== 'approved' ? `destination ${d.state}` : `${d.class} destination`);

  const rate = input.recentActions / policy.risk.rate_baseline_per_minute;
  const denials = input.recentDenials / 5;
  const behavior = Math.max(rate, denials, input.task.max_injection);
  add('behavior', w.behavior, behavior,
    behavior === 0 ? 'no anomaly' :
    behavior === input.task.max_injection ? 'task ingested content with injection signals' :
    behavior === denials ? `${input.recentDenials} recent denials` : `${input.recentActions} actions in the last minute`);

  let cred = 0.5;
  let credNote = 'no grant';
  if (input.grant) {
    const life = input.grant.expires_at - input.grant.created_at;
    const left = input.grant.expires_at - input.now;
    cred = life > 0 && left / life < 0.1 ? 0.5 : 0;
    credNote = cred ? 'grant close to expiry' : 'grant in good standing';
  }
  add('credential', w.credential, cred, credNote);

  const score = Math.round(factors.reduce((s, f) => s + f.weight * f.value, 0) * 10) / 10;
  return { score, class: classify(policy, score), factors };
}

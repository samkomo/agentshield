/**
 * Execution permits.
 *
 * A permit is a short-lived signed statement that one exact action was
 * authorized: it carries the action digest, the policy and grant revisions it
 * was decided under, and the agent's revocation epoch. It is not a bearer
 * capability — the executor also checks it against the stored intent, uses it
 * once, and re-checks everything that could have been revoked since.
 */
import type { KeyObject } from 'node:crypto';
import { signToken, verifyToken, type SigningKey } from '../core/crypto.ts';
import type { JsonObject } from '../core/json.ts';

export const PERMIT_TYP = 'agentshield-permit+jwt';

export interface PermitClaims extends JsonObject {
  iss: 'agentshield';
  jti: string;
  tenant_id: string;
  sub: string;
  action_id: string;
  action_digest: string;
  decision_id: string;
  policy_id: string;
  policy_version: number;
  grant_id: string;
  grant_revision: number;
  agent_epoch: number;
  tool_id: string;
  tool_revision: string;
  nonce: string;
  iat: number;
  exp: number;
}

export function issuePermit(key: SigningKey, claims: PermitClaims): string {
  return signToken(key, PERMIT_TYP, claims);
}

/** Signature and shape only. Expiry, replay and revocation are checked by the executor against live state. */
export function verifyPermit(token: string, publicKey: KeyObject, kid: string): PermitClaims | null {
  const claims = verifyToken(token, PERMIT_TYP, (k) => (k === kid ? publicKey : undefined));
  if (!claims || claims.iss !== 'agentshield' || typeof claims.exp !== 'number' || typeof claims.action_digest !== 'string') return null;
  return claims as PermitClaims;
}

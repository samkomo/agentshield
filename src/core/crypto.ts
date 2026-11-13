/**
 * Key handling, Ed25519 signatures and compact signed tokens.
 *
 * Nothing here is novel cryptography: Ed25519 via node:crypto, tokens in JWS
 * compact form (alg EdDSA) so permits can be verified by any standard library,
 * and AES-256-GCM for the redaction vault.
 *
 * Keys are separated by purpose, as the design requires: the key that signs
 * permits is not the key that signs audit events, and neither can sign policy.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, parseStrict, sha256Hex, type Json, type JsonObject } from './json.ts';

export interface SigningKey {
  kid: string;
  publicKey: KeyObject;
  privateKey?: KeyObject;
}

export interface KeySet {
  /** Signs execution permits. */
  permit: SigningKey;
  /** Signs audit events and checkpoints. */
  event: SigningKey;
  /** Public keys trusted to sign policy bundles, by key id. The gateway never holds the private half in production. */
  policyTrust: Map<string, KeyObject>;
  /** Encrypts reversible redaction mappings at rest. */
  vaultKey: Buffer;
  /** Keys the tenant-scoped HMAC used for pseudonyms in events. */
  telemetryKey: Buffer;
  /** Present only where the policy author and the gateway share a machine (development, tests). */
  policySigner?: SigningKey;
}

function kidOf(publicKey: KeyObject): string {
  return sha256Hex(publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16);
}

export function generateSigningKey(): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { kid: kidOf(publicKey), publicKey, privateKey };
}

export function signingKeyFromPem(privatePem: string): SigningKey {
  const privateKey = createPrivateKey(privatePem);
  const publicKey = createPublicKey(privateKey);
  return { kid: kidOf(publicKey), publicKey, privateKey };
}

export function publicKeyFromPem(pem: string): SigningKey {
  const publicKey = createPublicKey(pem);
  return { kid: kidOf(publicKey), publicKey };
}

export const privatePem = (k: SigningKey): string =>
  k.privateKey!.export({ type: 'pkcs8', format: 'pem' }) as string;
export const publicPem = (k: SigningKey): string =>
  k.publicKey.export({ type: 'spki', format: 'pem' }) as string;

export function signDetached(key: SigningKey, data: string): string {
  if (!key.privateKey) throw new Error(`key ${key.kid} has no private half`);
  return edSign(null, Buffer.from(data), key.privateKey).toString('base64url');
}

export function verifyDetached(publicKey: KeyObject, data: string, signature: string): boolean {
  try {
    return edVerify(null, Buffer.from(data), publicKey, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

const b64 = (s: string): string => Buffer.from(s).toString('base64url');

/** JWS compact serialization with a canonical JSON payload. */
export function signToken(key: SigningKey, typ: string, payload: JsonObject): string {
  const header = b64(canonicalize({ alg: 'EdDSA', kid: key.kid, typ }));
  const body = b64(canonicalize(payload));
  return `${header}.${body}.${signDetached(key, `${header}.${body}`)}`;
}

/** Returns the payload when the signature and type check out; otherwise null. Expiry is the caller's concern. */
export function verifyToken(
  token: string,
  typ: string,
  resolve: (kid: string) => KeyObject | undefined,
): JsonObject | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = parseStrict(Buffer.from(parts[0]!, 'base64url').toString()) as JsonObject;
    if (header.alg !== 'EdDSA' || header.typ !== typ || typeof header.kid !== 'string') return null;
    const key = resolve(header.kid);
    if (!key || !verifyDetached(key, `${parts[0]}.${parts[1]}`, parts[2]!)) return null;
    return parseStrict(Buffer.from(parts[1]!, 'base64url').toString()) as JsonObject;
  } catch {
    return null;
  }
}

/** Tenant-scoped keyed pseudonym. A bare hash of a low-entropy identifier would be reversible by enumeration. */
export function pseudonym(key: Buffer, tenant: string, value: string): string {
  return createHmac('sha256', key).update(`${tenant}\0${value}`).digest('hex').slice(0, 24);
}

export function hashCredential(token: string): string {
  return sha256Hex(token);
}

export function newCredential(): string {
  return `as_${randomBytes(32).toString('base64url')}`;
}

export function seal(key: Buffer, plaintext: string, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

export function unseal(key: Buffer, sealed: string, aad: string): string {
  const raw = Buffer.from(sealed, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

/** Fresh in-memory keys, including a policy signer. For tests and the demo. */
export function ephemeralKeys(): KeySet {
  const policySigner = generateSigningKey();
  return {
    permit: generateSigningKey(),
    event: generateSigningKey(),
    policyTrust: new Map([[policySigner.kid, policySigner.publicKey]]),
    vaultKey: randomBytes(32),
    telemetryKey: randomBytes(32),
    policySigner,
  };
}

function writeSecret(path: string, content: string): void {
  writeFileSync(path, content, { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** Create a key directory. Refuses to overwrite an existing one: silently rotating keys would orphan every signed record. */
export function generateKeyDir(dir: string): KeySet {
  if (existsSync(join(dir, 'permit.key'))) throw new Error(`keys already exist in ${dir}`);
  mkdirSync(join(dir, 'trust'), { recursive: true, mode: 0o700 });
  const keys = ephemeralKeys();
  writeSecret(join(dir, 'permit.key'), privatePem(keys.permit));
  writeSecret(join(dir, 'event.key'), privatePem(keys.event));
  writeFileSync(join(dir, 'event.pub'), publicPem(keys.event));
  writeFileSync(join(dir, 'permit.pub'), publicPem(keys.permit));
  writeSecret(join(dir, 'vault.key'), keys.vaultKey.toString('hex'));
  writeSecret(join(dir, 'telemetry.key'), keys.telemetryKey.toString('hex'));
  writeSecret(join(dir, 'policy-signing.key'), privatePem(keys.policySigner!));
  writeFileSync(join(dir, 'trust', `policy-${keys.policySigner!.kid}.pub`), publicPem(keys.policySigner!));
  return keys;
}

export function loadKeyDir(dir: string): KeySet {
  const read = (name: string) => readFileSync(join(dir, name), 'utf8');
  const policyTrust = new Map<string, KeyObject>();
  for (const name of readdirSync(join(dir, 'trust'))) {
    if (!name.endsWith('.pub')) continue;
    const k = publicKeyFromPem(read(join('trust', name)));
    policyTrust.set(k.kid, k.publicKey);
  }
  const signerPath = join(dir, 'policy-signing.key');
  return {
    permit: signingKeyFromPem(read('permit.key')),
    event: signingKeyFromPem(read('event.key')),
    policyTrust,
    vaultKey: Buffer.from(read('vault.key').trim(), 'hex'),
    telemetryKey: Buffer.from(read('telemetry.key').trim(), 'hex'),
    policySigner: existsSync(signerPath) ? signingKeyFromPem(read('policy-signing.key')) : undefined,
  };
}

export type { Json };

import { randomBytes } from 'node:crypto';
import type { Json } from './json.ts';

export interface Clock {
  now(): number;
}
export const systemClock: Clock = { now: () => Date.now() };

export const iso = (ms: number): string => new Date(ms).toISOString();

export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString('hex')}`;
}

/** An error with an HTTP status and a stable machine-readable code. */
export class ShieldError extends Error {
  status: number;
  code: string;
  details?: Json;
  constructor(status: number, code: string, message: string, details?: Json) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/**
 * Scope patterns are literal strings, `*`, or a literal prefix followed by `*`.
 * Nothing richer: subset checks between two pattern sets must stay decidable
 * by inspection, because delegation safety depends on them.
 */
export function isValidPattern(p: unknown): p is string {
  return typeof p === 'string' && p.length > 0 && p.length <= 512 && !p.slice(0, -1).includes('*');
}

export function matchPattern(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return value.startsWith(pattern.slice(0, -1));
  return pattern === value;
}

export function matchAny(patterns: readonly string[], value: string): boolean {
  return patterns.some((p) => matchPattern(p, value));
}

/** True when every value matched by `child` is also matched by some pattern in `parents`. */
export function patternCovered(child: string, parents: readonly string[]): boolean {
  return parents.some(
    (q) => q === '*' || q === child || (q.endsWith('*') && child.startsWith(q.slice(0, -1))),
  );
}

/** Fixed-window-free token bucket; in-memory because it only protects availability. */
export class RateLimiter {
  private buckets = new Map<string, { tokens: number; at: number }>();
  private perMinute: number;
  private burst: number;
  private clock: Clock;
  constructor(perMinute: number, burst: number, clock: Clock) {
    this.perMinute = perMinute;
    this.burst = burst;
    this.clock = clock;
  }
  take(key: string): boolean {
    const now = this.clock.now();
    const b = this.buckets.get(key) ?? { tokens: this.burst, at: now };
    b.tokens = Math.min(this.burst, b.tokens + ((now - b.at) / 60_000) * this.perMinute);
    b.at = now;
    const ok = b.tokens >= 1;
    if (ok) b.tokens -= 1;
    this.buckets.set(key, b);
    return ok;
  }
}

/**
 * Strict JSON parsing and RFC 8785 (JCS) canonicalization.
 *
 * Every digest AgentShield signs is computed over the canonical form, so two
 * parties that agree on the value agree on the bytes. The strict parser exists
 * because `JSON.parse` silently keeps the last of two duplicate keys, which
 * would let a caller show one value to a reviewer and another to the executor.
 */
import { createHash } from 'node:crypto';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

export class JsonError extends Error {}

const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

/** Parse JSON, rejecting duplicate keys, lone surrogates, `__proto__` keys and excessive nesting. */
export function parseStrict(text: string, maxDepth = 64): Json {
  let i = 0;
  const n = text.length;
  const fail = (msg: string): never => {
    throw new JsonError(`${msg} at offset ${i}`);
  };
  const ws = () => {
    for (; i < n; i++) {
      const c = text.charCodeAt(i);
      if (c !== 32 && c !== 9 && c !== 10 && c !== 13) break;
    }
  };
  const str = (): string => {
    const start = i++;
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 34) {
        i++;
        let s: string;
        try {
          s = JSON.parse(text.slice(start, i)) as string;
        } catch {
          return fail('invalid string');
        }
        if (!s.isWellFormed()) fail('lone surrogate in string');
        return s;
      }
      if (c === 92) i += 2;
      else if (c < 32) fail('control character in string');
      else i++;
    }
    return fail('unterminated string');
  };
  const value = (depth: number): Json => {
    if (depth > maxDepth) fail('nesting too deep');
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      const obj: JsonObject = {};
      ws();
      if (text[i] === '}') {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected object key');
        const key = str();
        if (key === '__proto__') fail('forbidden key "__proto__"');
        if (Object.hasOwn(obj, key)) fail(`duplicate key ${JSON.stringify(key)}`);
        ws();
        if (text[i] !== ':') fail('expected ":"');
        i++;
        obj[key] = value(depth + 1);
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return obj;
        }
        fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      i++;
      const arr: Json[] = [];
      ws();
      if (text[i] === ']') {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value(depth + 1));
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return arr;
        }
        fail('expected "," or "]"');
      }
    }
    if (c === '"') return str();
    if (text.startsWith('true', i)) return ((i += 4), true);
    if (text.startsWith('false', i)) return ((i += 5), false);
    if (text.startsWith('null', i)) return ((i += 4), null);
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) return fail('unexpected token');
    i += m[0].length;
    const num = Number(m[0]);
    if (!Number.isFinite(num)) fail('number out of range');
    return num;
  };
  const result = value(0);
  ws();
  if (i < n) fail('trailing characters');
  return result;
}

/** RFC 8785 JSON Canonicalization Scheme. Keys sort by UTF-16 code unit; numbers use ECMAScript formatting. */
export function canonicalize(v: Json): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new JsonError('non-finite number cannot be canonicalized');
      return JSON.stringify(v);
    case 'string':
      if (!v.isWellFormed()) throw new JsonError('lone surrogate cannot be canonicalized');
      return JSON.stringify(v);
    case 'object': {
      if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
      const parts: string[] = [];
      for (const k of Object.keys(v).sort()) {
        const item = v[k];
        if (item === undefined) continue;
        parts.push(`${canonicalize(k)}:${canonicalize(item)}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new JsonError(`unsupported type ${typeof v}`);
  }
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** `sha256:<hex>` over the canonical form of a JSON value. */
export function digest(v: Json): string {
  return `sha256:${sha256Hex(canonicalize(v))}`;
}

export function isObject(v: unknown): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

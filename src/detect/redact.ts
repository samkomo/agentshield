/**
 * Redaction replaces each finding with a scoped placeholder such as [EMAIL_1].
 * The same value always maps to the same placeholder within one document, so
 * a downstream model can still tell that two mentions refer to one thing.
 *
 * Redaction is a transformation, not an authorization. Callers must re-scan
 * and re-evaluate the result before acting on it.
 */
import { isObject, type Json } from '../core/json.ts';
import type { Finding } from '../core/types.ts';

export interface Replacement {
  placeholder: string;
  original: string;
  type: string;
}

export class PlaceholderAllocator {
  private byValue = new Map<string, string>();
  private counters = new Map<string, number>();
  readonly replacements: Replacement[] = [];

  placeholderFor(type: string, original: string): string {
    const key = `${type}\0${original}`;
    let p = this.byValue.get(key);
    if (!p) {
      const n = (this.counters.get(type) ?? 0) + 1;
      this.counters.set(type, n);
      p = `[${type}_${n}]`;
      this.byValue.set(key, p);
      this.replacements.push({ placeholder: p, original, type });
    }
    return p;
  }
}

export function redactText(text: string, findings: Finding[], alloc: PlaceholderAllocator): string {
  const ordered = [...findings].sort((a, b) => a.start - b.start);
  // Allocate in reading order so numbering is stable, then splice from the end so offsets stay valid.
  const placeholders = ordered.map((f) => alloc.placeholderFor(f.type, text.slice(f.start, f.end)));
  let out = text;
  for (let i = ordered.length - 1; i >= 0; i--) {
    out = out.slice(0, ordered[i]!.start) + placeholders[i] + out.slice(ordered[i]!.end);
  }
  return out;
}

/** Returns a rewritten copy. Findings in object keys are not handled here; the caller must refuse those. */
export function redactJson(value: Json, findings: Finding[], alloc: PlaceholderAllocator): Json {
  const byPath = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.in_key) continue;
    const list = byPath.get(f.path ?? '') ?? [];
    list.push(f);
    byPath.set(f.path ?? '', list);
  }
  const esc = (k: string | number) => String(k).replace(/~/g, '~0').replace(/\//g, '~1');
  const walk = (v: Json, path: string): Json => {
    if (typeof v === 'string') {
      const hits = byPath.get(path);
      return hits ? redactText(v, hits, alloc) : v;
    }
    if (Array.isArray(v)) return v.map((item, i) => walk(item, `${path}/${i}`));
    if (isObject(v)) {
      const out: { [k: string]: Json } = {};
      for (const [k, item] of Object.entries(v)) out[k] = walk(item, `${path}/${esc(k)}`);
      return out;
    }
    return v;
  };
  return walk(value, '');
}

/**
 * Local sensitive-data scanner.
 *
 * Text is normalized before matching (compatibility forms folded, invisible
 * characters dropped) so that a key written in fullwidth letters or split by
 * zero-width joiners is still found. Offsets are mapped back to the original
 * string, because redaction has to rewrite what will actually be sent.
 *
 * Findings never carry the matched text. Anything that leaves this module is
 * safe to log.
 */
import { isObject, type Json } from '../core/json.ts';
import type { Finding } from '../core/types.ts';
import { ALL_PATTERNS, type Pattern } from './patterns.ts';

export const DETECTOR_VERSION = 'patterns-1';

export interface RawMatch {
  category: 'SECRET' | 'PII';
  type: string;
  start: number;
  end: number;
  confidence: number;
  detector: string;
}

/** Extension point for a local NER model or tenant fingerprint matcher. Receives normalized text. */
export interface Detector {
  name: string;
  detect(normalized: string): RawMatch[];
}

export interface ScanOptions {
  minConfidence?: number;
  detectors?: Detector[];
  /** Also decode base64 runs and scan what they contain. */
  decode?: boolean;
}

function isInvisible(cp: number): boolean {
  return (
    cp === 0xad || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2064) || cp === 0xfeff || (cp >= 0xe0000 && cp <= 0xe007f)
  );
}

export interface Normalized {
  norm: string;
  /** map[i] is the index in the original string of the character that produced norm[i]. */
  map: number[];
  invisible: number;
}

export function normalizeWithMap(text: string): Normalized {
  const out: string[] = [];
  const map: number[] = [];
  let invisible = 0;
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i)!;
    const len = cp > 0xffff ? 2 : 1;
    if (isInvisible(cp)) {
      invisible++;
    } else {
      const ch = cp < 0x80 ? text[i]! : String.fromCodePoint(cp).normalize('NFKC');
      for (let k = 0; k < ch.length; k++) map.push(i);
      out.push(ch);
    }
    i += len;
  }
  return { norm: out.join(''), map, invisible };
}

function originalSpan(text: string, map: number[], start: number, end: number): [number, number] {
  const last = map[end - 1]!;
  return [map[start]!, last + (text.codePointAt(last)! > 0xffff ? 2 : 1)];
}

function runPatterns(norm: string, patterns: Pattern[]): RawMatch[] {
  const out: RawMatch[] = [];
  for (const p of patterns) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(norm))) {
      if (m[0].length === 0) {
        p.re.lastIndex++;
        continue;
      }
      let start = m.index;
      let value = m[0];
      if (p.group !== undefined) {
        const span = m.indices?.[p.group];
        if (!span) continue;
        start = span[0];
        value = m[p.group]!;
      }
      if (p.validate && !p.validate(value)) continue;
      out.push({ category: p.category, type: p.type, start, end: start + value.length, confidence: p.confidence, detector: DETECTOR_VERSION });
      if (out.length >= 2000) return out;
    }
  }
  return out;
}

const BASE64_RUN = /[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{24,}/g;

/** A base64 run that decodes to text containing a finding is itself a finding, covering the whole run. */
function decodedMatches(norm: string): RawMatch[] {
  const out: RawMatch[] = [];
  BASE64_RUN.lastIndex = 0;
  let m: RegExpExecArray | null;
  let budget = 64;
  while ((m = BASE64_RUN.exec(norm)) && budget-- > 0) {
    const run = m[0];
    if (run.length > 65536) continue;
    const decoded = Buffer.from(run, /[-_]/.test(run) ? 'base64url' : 'base64').toString('latin1');
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const c = decoded.charCodeAt(i);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
    }
    if (decoded.length < 12 || printable / decoded.length < 0.9) continue;
    const inner = runPatterns(decoded, ALL_PATTERNS);
    if (!inner.length) continue;
    const top = inner.reduce((a, b) => (rank(b) > rank(a) ? b : a));
    out.push({
      category: top.category, type: `ENCODED_${top.type}`, start: m.index, end: m.index + run.length,
      confidence: top.confidence * 0.95, detector: `${DETECTOR_VERSION}+base64`,
    });
  }
  return out;
}

const rank = (m: RawMatch): number => (m.category === 'SECRET' ? 2 : 1) + m.confidence;

/** Keep the most sensitive of any overlapping spans; order the result by position. Deterministic. */
function mergeOverlaps(matches: RawMatch[]): RawMatch[] {
  const sorted = [...matches].sort(
    (a, b) => rank(b) - rank(a) || b.end - b.start - (a.end - a.start) || a.start - b.start || a.type.localeCompare(b.type),
  );
  const kept: RawMatch[] = [];
  for (const m of sorted) {
    if (!kept.some((k) => m.start < k.end && k.start < m.end)) kept.push(m);
  }
  return kept.sort((a, b) => a.start - b.start);
}

export function scanText(text: string, opts: ScanOptions = {}): Finding[] {
  if (text.length < 6) return [];
  const { norm, map } = normalizeWithMap(text);
  const raw = runPatterns(norm, ALL_PATTERNS);
  if (opts.decode !== false) raw.push(...decodedMatches(norm));
  for (const d of opts.detectors ?? []) raw.push(...d.detect(norm));
  const min = opts.minConfidence ?? 0.6;
  const merged = mergeOverlaps(raw.filter((m) => m.confidence >= min && m.end > m.start && m.end <= norm.length));

  const findings: Finding[] = [];
  let bytePos = 0;
  let charPos = 0;
  for (const m of merged) {
    const [start, end] = originalSpan(text, map, m.start, m.end);
    bytePos += Buffer.byteLength(text.slice(charPos, start));
    charPos = start;
    const byteLen = Buffer.byteLength(text.slice(start, end));
    findings.push({
      category: m.category, type: m.type, start, end,
      byte_start: bytePos, byte_end: bytePos + byteLen,
      confidence: Math.round(m.confidence * 100) / 100, detector: m.detector,
    });
  }
  return findings;
}

const pointer = (path: string, key: string | number): string =>
  `${path}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`;

/** Scan every string and key in a JSON document. Each finding carries the JSON pointer of its string. */
export function scanJson(value: Json, opts: ScanOptions = {}, path = '', out: Finding[] = []): Finding[] {
  if (typeof value === 'string') {
    for (const f of scanText(value, opts)) out.push({ ...f, path });
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => scanJson(v, opts, pointer(path, i), out));
  } else if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      const p = pointer(path, k);
      for (const f of scanText(k, opts)) out.push({ ...f, path: p, in_key: true });
      scanJson(v, opts, p, out);
    }
  }
  return out;
}

export function categoriesOf(findings: Finding[]): string[] {
  return [...new Set(findings.map((f) => f.category))].sort();
}

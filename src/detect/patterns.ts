/**
 * Deterministic recognizers for credentials and structured personal data.
 *
 * These are format, checksum and context rules. They do not find people's
 * names, free-text addresses or proprietary code: that needs a local NER model
 * or tenant fingerprints, which plug in through `Detector` in scanner.ts.
 */

export interface Pattern {
  type: string;
  category: 'SECRET' | 'PII';
  re: RegExp;
  confidence: number;
  /** Capture group holding the sensitive span; whole match when absent. Requires the `d` flag. */
  group?: number;
  validate?: (value: string) => boolean;
}

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Values that look like a reference to a secret rather than the secret itself. */
const PLACEHOLDER =
  /^(?:\[[A-Z0-9_]+_\d+\]|<[^>]*>|\$\{?[A-Za-z_][\w.]*\}?|\{\{.*\}\}|%\w+%|(?:process\.env|os\.environ|env|secrets?|vault|config)[.[(].*|x{6,}|\*{6,}|\.{6,}|(?:your|my|example|sample|dummy|placeholder|changeme|redacted|null|none|true|false|undefined)[\w-]*)$/i;

const looksRandom = (min: number) => (v: string) => !PLACEHOLDER.test(v) && shannonEntropy(v) >= min;

function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function validCard(v: string): boolean {
  const d = v.replace(/[ -]/g, '');
  return d.length >= 13 && d.length <= 19 && /^[2-6]/.test(d) && !/^(\d)\1+$/.test(d) && luhn(d);
}

function validIban(v: string): boolean {
  const s = v.replace(/ /g, '').toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const n = code >= 65 ? code - 55 : code - 48;
    rem = (rem * (n > 9 ? 100 : 10) + n) % 97;
  }
  return rem === 1;
}

const phoneDigits = (min: number, max: number) => (v: string) => {
  const d = v.replace(/\D/g, '').length;
  return d >= min && d <= max;
};

export const SECRET_PATTERNS: Pattern[] = [
  {
    type: 'PRIVATE_KEY', category: 'SECRET', confidence: 0.99,
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16000}?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g,
  },
  { type: 'AWS_ACCESS_KEY_ID', category: 'SECRET', confidence: 0.95, re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g },
  {
    type: 'AWS_SECRET_ACCESS_KEY', category: 'SECRET', confidence: 0.9, group: 1,
    re: /aws.{0,24}?(?:secret|sk).{0,24}?["'=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/dgi,
    validate: looksRandom(4),
  },
  { type: 'GITHUB_TOKEN', category: 'SECRET', confidence: 0.97, re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { type: 'SLACK_TOKEN', category: 'SECRET', confidence: 0.95, re: /\bxox[abeoprs]-[A-Za-z0-9-]{10,250}\b/g },
  { type: 'STRIPE_KEY', category: 'SECRET', confidence: 0.95, re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { type: 'GOOGLE_API_KEY', category: 'SECRET', confidence: 0.9, re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g },
  { type: 'ANTHROPIC_API_KEY', category: 'SECRET', confidence: 0.97, re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { type: 'OPENAI_API_KEY', category: 'SECRET', confidence: 0.85, re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}/g, validate: looksRandom(3.2) },
  { type: 'JWT', category: 'SECRET', confidence: 0.85, re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  {
    type: 'BEARER_TOKEN', category: 'SECRET', confidence: 0.75, group: 1,
    re: /\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)/dgi,
    validate: looksRandom(3.2),
  },
  {
    type: 'URL_CREDENTIALS', category: 'SECRET', confidence: 0.9, group: 1,
    re: /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s:@/]{1,64}:([^\s@/]{3,128})@[^\s/@]+/dgi,
    validate: (v) => !PLACEHOLDER.test(v),
  },
  {
    type: 'GENERIC_SECRET', category: 'SECRET', confidence: 0.7, group: 1,
    re: /(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]{0,30}["']?\s*[:=]\s*["']?([^\s"'`,;&]{8,256})/dgi,
    validate: looksRandom(3),
  },
];

export const PII_PATTERNS: Pattern[] = [
  { type: 'EMAIL', category: 'PII', confidence: 0.95, re: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b/g },
  {
    type: 'CREDIT_CARD', category: 'PII', confidence: 0.9,
    re: /(?<![\dA-Za-z])\d(?:[ -]?\d){12,18}(?![\dA-Za-z])/g,
    validate: validCard,
  },
  {
    type: 'IBAN', category: 'PII', confidence: 0.95,
    re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
    validate: validIban,
  },
  { type: 'US_SSN', category: 'PII', confidence: 0.85, re: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g },
  { type: 'KE_KRA_PIN', category: 'PII', confidence: 0.9, re: /\b[AP]\d{9}[A-Z]\b/g },
  {
    type: 'KE_NATIONAL_ID', category: 'PII', confidence: 0.8, group: 1,
    re: /(?:national\s+id|id\s*(?:no\.?|number|#)|kitambulisho)\D{0,16}(\d{7,8})(?!\d)/dgi,
  },
  {
    type: 'PHONE', category: 'PII', confidence: 0.8,
    re: /(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\w)/g,
    validate: phoneDigits(9, 15),
  },
  // Kenyan national format: 07xx / 01xx followed by six digits.
  { type: 'PHONE', category: 'PII', confidence: 0.75, re: /(?<![\w+])0[17]\d{2}[\s-]?\d{3}[\s-]?\d{3}(?!\w)/g },
];

export const ALL_PATTERNS: Pattern[] = [...SECRET_PATTERNS, ...PII_PATTERNS];

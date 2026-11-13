/**
 * Heuristic prompt-injection signals.
 *
 * This is advisory by design. It tags content and raises a task's risk; it is
 * never the thing that stops an action. An attacker who evades every pattern
 * here still cannot make a protected action fall outside the grant, because
 * that check does not read the content at all.
 */
import { isObject, type Json } from '../core/json.ts';
import type { InjectionResult, InjectionSignal } from '../core/types.ts';
import { normalizeWithMap } from './scanner.ts';

interface Signal {
  id: string;
  weight: number;
  re: RegExp;
}

const SIGNALS: Signal[] = [
  { id: 'instruction_override', weight: 0.8, re: /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|your|any|safety)\b[^.\n]{0,30}\b(?:instructions?|prompts?|rules?|guidelines?|directions?|polic(?:y|ies)|restrictions?)\b/i },
  { id: 'instruction_override_sw', weight: 0.7, re: /\b(?:puuza|sahau)\b[^.\n]{0,30}\bmaagizo\b/i },
  { id: 'role_reassignment', weight: 0.6, re: /\byou are now\b|\bnew (?:system )?instructions?\s*:|\bact as (?:an? )?(?:unrestricted|jailbroken|uncensored)\b|\bdeveloper mode\b/i },
  { id: 'prompt_extraction', weight: 0.6, re: /\b(?:reveal|print|show|repeat|output|leak)\b[^.\n]{0,30}\b(?:system prompt|hidden instructions?|initial prompt|your instructions)\b/i },
  { id: 'concealment', weight: 0.7, re: /\b(?:do not|don't|never)\b[^.\n]{0,20}\b(?:tell|inform|mention|alert|notify|reveal)\b[^.\n]{0,24}\b(?:user|human|operator|owner|anyone)\b/i },
  { id: 'exfiltration_directive', weight: 0.5, re: /\b(?:send|forward|upload|post|email|exfiltrate|transmit|copy)\b[^.\n]{0,60}\bto\b\s+(?:https?:\/\/|[\w.+-]+@[\w-]+\.)/i },
  { id: 'tool_directive', weight: 0.3, re: /\b(?:call|invoke|use|run|execute)\b[^.\n]{0,20}\b(?:tool|function|command|shell|terminal)\b/i },
  { id: 'role_markers', weight: 0.5, re: /<\/?(?:system|assistant|im_start|im_end)\b[^>]*>|\[\/?(?:INST|SYSTEM)\]|^\s*(?:system|assistant)\s*:/im },
  { id: 'hidden_markup', weight: 0.4, re: /<!--[\s\S]{0,400}?(?:instruction|ignore|assistant|system)[\s\S]{0,400}?-->|display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)\b/i },
  { id: 'addressed_to_model', weight: 0.4, re: /\b(?:IMPORTANT|URGENT|ATTENTION|NOTE)\b[^.\n]{0,40}\b(?:AI|assistant|agent|model|LLM)\b/ },
];

export function detectInjection(text: string): InjectionResult {
  const { norm, invisible } = normalizeWithMap(text);
  const signals: InjectionSignal[] = [];
  for (const s of SIGNALS) {
    if (s.re.test(norm)) signals.push({ id: s.id, weight: s.weight });
  }
  // Invisible characters have legitimate uses (emoji joiners, bidi text); a run of them beside words does not.
  if (invisible >= 4) signals.push({ id: 'invisible_characters', weight: 0.4 });
  const score = 1 - signals.reduce((acc, s) => acc * (1 - s.weight), 1);
  return { score: Math.round(score * 100) / 100, signals };
}

/** Highest-scoring string anywhere in a JSON document. */
export function detectInjectionJson(value: Json): InjectionResult {
  let best: InjectionResult = { score: 0, signals: [] };
  const walk = (v: Json): void => {
    if (typeof v === 'string') {
      if (v.length >= 12) {
        const r = detectInjection(v);
        if (r.score > best.score) best = r;
      }
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (isObject(v)) Object.values(v).forEach(walk);
  };
  walk(value);
  return best;
}

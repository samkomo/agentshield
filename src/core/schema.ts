/**
 * A deliberately small JSON Schema validator for tool arguments and results.
 *
 * It covers the keywords tool manifests actually use. Keywords it does not
 * understand are reported by `unsupportedKeywords` at registration time, so a
 * reviewer knows which constraints are not being enforced rather than
 * assuming they are.
 */
import { isObject, type Json, type JsonObject } from './json.ts';

export type Schema = JsonObject;

const SUPPORTED = new Set([
  'type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const',
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
  'minLength', 'maxLength', 'pattern', 'minItems', 'maxItems', 'uniqueItems',
  'allOf', 'anyOf', 'oneOf', 'not',
]);
/** Annotations that carry no constraint. */
const INERT = new Set([
  'title', 'description', 'default', 'examples', 'format', '$schema', '$id', '$comment', 'deprecated',
  'readOnly', 'writeOnly',
]);

export function unsupportedKeywords(schema: Json, path = '', out: string[] = []): string[] {
  if (!isObject(schema)) return out;
  for (const [k, v] of Object.entries(schema)) {
    if (!SUPPORTED.has(k) && !INERT.has(k)) out.push(`${path}/${k}`);
    if (k === 'properties' && isObject(v)) {
      for (const [name, sub] of Object.entries(v)) unsupportedKeywords(sub, `${path}/properties/${name}`, out);
    } else if (k === 'items' || k === 'additionalProperties' || k === 'not') {
      unsupportedKeywords(v, `${path}/${k}`, out);
    } else if ((k === 'allOf' || k === 'anyOf' || k === 'oneOf') && Array.isArray(v)) {
      v.forEach((sub, i) => unsupportedKeywords(sub, `${path}/${k}/${i}`, out));
    }
  }
  return out;
}

function typeOf(v: Json): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

function equal(a: Json, b: Json): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Returns a list of violations; empty means valid. */
export function validate(schema: Json, value: Json, path = '', errors: string[] = []): string[] {
  if (schema === true || !isObject(schema)) {
    if (schema === false) errors.push(`${path || '/'}: no value permitted`);
    return errors;
  }
  const at = path || '/';
  const t = typeOf(value);

  if (schema.type !== undefined) {
    const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!allowed.some((a) => a === t || (a === 'number' && t === 'integer'))) {
      errors.push(`${at}: expected ${allowed.join('|')}, got ${t}`);
      return errors;
    }
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((e) => equal(e, value))) errors.push(`${at}: not an allowed value`);
  if (schema.const !== undefined && !equal(schema.const, value)) errors.push(`${at}: not the required value`);

  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) errors.push(`${at}: below minimum ${schema.minimum}`);
    if (typeof schema.maximum === 'number' && value > schema.maximum) errors.push(`${at}: above maximum ${schema.maximum}`);
    if (typeof schema.exclusiveMinimum === 'number' && value <= schema.exclusiveMinimum) errors.push(`${at}: not above ${schema.exclusiveMinimum}`);
    if (typeof schema.exclusiveMaximum === 'number' && value >= schema.exclusiveMaximum) errors.push(`${at}: not below ${schema.exclusiveMaximum}`);
    if (typeof schema.multipleOf === 'number' && schema.multipleOf > 0 && !Number.isInteger(value / schema.multipleOf)) errors.push(`${at}: not a multiple of ${schema.multipleOf}`);
  }
  if (typeof value === 'string') {
    const len = [...value].length;
    if (typeof schema.minLength === 'number' && len < schema.minLength) errors.push(`${at}: shorter than ${schema.minLength}`);
    if (typeof schema.maxLength === 'number' && len > schema.maxLength) errors.push(`${at}: longer than ${schema.maxLength}`);
    if (typeof schema.pattern === 'string') {
      let re: RegExp | null = null;
      try {
        re = new RegExp(schema.pattern, 'u');
      } catch {
        errors.push(`${at}: schema pattern is not a valid expression`);
      }
      if (re && !re.test(value)) errors.push(`${at}: does not match required pattern`);
    }
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) errors.push(`${at}: fewer than ${schema.minItems} items`);
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) errors.push(`${at}: more than ${schema.maxItems} items`);
    if (schema.uniqueItems === true && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) errors.push(`${at}: items not unique`);
    if (schema.items !== undefined) value.forEach((item, i) => validate(schema.items!, item, `${path}/${i}`, errors));
  }
  if (isObject(value)) {
    const props = isObject(schema.properties) ? schema.properties : {};
    if (Array.isArray(schema.required)) {
      for (const r of schema.required) {
        if (typeof r === 'string' && !Object.hasOwn(value, r)) errors.push(`${path}/${r}: required`);
      }
    }
    for (const [k, v] of Object.entries(value)) {
      if (Object.hasOwn(props, k)) validate(props[k]!, v, `${path}/${k}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}/${k}: unexpected property`);
      else if (isObject(schema.additionalProperties)) validate(schema.additionalProperties, v, `${path}/${k}`, errors);
    }
  }
  if (Array.isArray(schema.allOf)) for (const s of schema.allOf) validate(s, value, path, errors);
  if (Array.isArray(schema.anyOf) && !schema.anyOf.some((s) => validate(s, value, path).length === 0)) errors.push(`${at}: matches none of the permitted alternatives`);
  if (Array.isArray(schema.oneOf) && schema.oneOf.filter((s) => validate(s, value, path).length === 0).length !== 1) errors.push(`${at}: must match exactly one alternative`);
  if (schema.not !== undefined && validate(schema.not, value, path).length === 0) errors.push(`${at}: matches a forbidden form`);
  return errors;
}

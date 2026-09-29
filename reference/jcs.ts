/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) for the JSON subset AKAC evidence
 * uses: null, booleans, safe integers, well-formed strings, arrays and plain
 * objects with string keys. Everything else (fractions, NaN, infinities, unsafe
 * integers, undefined, lone surrogates, sparse arrays, non-plain objects) is rejected rather than
 * approximated, so a canonical form is never ambiguous.
 *
 * Within this subset JCS reduces to: object members sorted by the UTF-16 code
 * units of their names, no whitespace, strings serialized as ECMAScript
 * JSON.stringify does, integers in their shortest decimal form (-0 as 0).
 */
const DEPTH = 32;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const wellFormed = (s: string) => !LONE_SURROGATE.test(s);
function encode(value: unknown, depth: number): string {
  if (depth > DEPTH) throw new TypeError('JCS: nesting too deep');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean': return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new TypeError('JCS subset: only safe integers');
      return String(value === 0 ? 0 : value);
    case 'string':
      if (!wellFormed(value)) throw new TypeError('JCS: string is not well-formed Unicode');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        // A hole (or an extra member) has no JSON form; JSON.stringify would write null for it.
        if (Object.keys(value).length !== value.length) throw new TypeError('JCS: sparse arrays are not JSON');
        return `[${value.map(v => encode(v, depth + 1)).join(',')}]`;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new TypeError('JCS: only plain objects');
      // Default sort compares UTF-16 code units, which is what RFC 8785 §3.2.3 requires.
      const keys = Object.keys(value).sort();
      return `{${keys.map(k => {
        if (!wellFormed(k)) throw new TypeError('JCS: key is not well-formed Unicode');
        return `${JSON.stringify(k)}:${encode((value as Record<string, unknown>)[k], depth + 1)}`;
      }).join(',')}}`;
    }
    default: throw new TypeError(`JCS: unsupported ${typeof value}`);
  }
}
export function canonicalize(value: unknown): string { return encode(value, 0); }
export const canonicalBytes = (value: unknown): Buffer => Buffer.from(canonicalize(value), 'utf8');

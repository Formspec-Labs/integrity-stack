/**
 * Distinct Rust-authoritative Response handoff and signing byte profiles.
 *
 * Bytes follow `integrity-canonical-json-v1`: RFC 8785 JCS, except that a number
 * is written as its exact decimal value in `Number::toString` layout instead of
 * first being rounded to a double. A JS number serializes exactly as RFC 8785
 * says; a `JSON.rawJSON` number (see {@link parseJsonExact}) keeps every digit.
 */
const HANDOFF_DOMAIN = 'formspec.response.handoff.v1';
const SIGNING_DOMAIN = 'formspec.response.signed-payload.v1';

/** A `JSON.rawJSON` value: a frozen, null-prototype holder of one JSON primitive's text. */
interface RawJson { readonly rawJSON: string }
// JSON.parse source text access (ES2026): Node 21+, Chrome 114+, Firefox 135+, Safari 18.4+.
const json = JSON as unknown as {
  rawJSON?: (text: string) => RawJson;
  isRawJSON?: (value: unknown) => value is RawJson;
};
const isRawJson = (value: unknown): value is RawJson => json.isRawJSON?.(value) ?? false;

/**
 * Parses JSON text without losing number digits.
 *
 * A number stays a JS number when its source text is exactly that number's own
 * text; otherwise it becomes `JSON.rawJSON(source)`, which the canonical byte
 * functions write with every digit. `JSON.parse` keeps the last of repeated
 * member names; Rust's text functions refuse them.
 *
 * @throws SyntaxError for invalid JSON; TypeError where the runtime lacks source text access.
 */
export function parseJsonExact(text: string): unknown {
  const { rawJSON } = json;
  if (!rawJSON) throw new TypeError('runtime lacks JSON.rawJSON');
  return JSON.parse(text, (_key: string, value: unknown, context?: { source?: string }) => {
    if (typeof value !== 'number') return value;
    const source = context?.source;
    if (source === undefined) throw new TypeError('runtime lacks JSON.parse source text access');
    return source === JSON.stringify(value) ? value : rawJSON(source);
  });
}

/**
 * Builds the Rust-authoritative domain, NUL, and canonical JSON handoff bytes.
 *
 * Preserves the complete JSON object, including authoredSignatures. The caller
 * hashes these bytes using genuine SHA-256; this function performs no crypto or
 * Response schema validation. Requires TextEncoder and String.isWellFormed.
 * Matches Rust `canonical_response_handoff_bytes_from_json` on the same JSON text
 * when the object comes from {@link parseJsonExact}.
 *
 * @throws TypeError for a non-object root, non-JSON runtime values, invalid
 * Unicode strings or keys, or a number outside the binary64 range.
 */
export function canonicalResponseHandoffBytes(response: unknown): Uint8Array<ArrayBuffer> {
  return framedBytes(HANDOFF_DOMAIN, responseSnapshot(response));
}

/**
 * Builds the formspec-response-signing-v1 preimage matching the Rust authority.
 *
 * Validates the complete JSON input, then omits only top-level authoredSignatures.
 * Preserves every other member, including nested members of that name. The caller
 * hashes these bytes using genuine SHA-256 for signedPayload.digest (plain hex).
 * Performs no hashing, signing, verification or Response schema validation.
 *
 * @throws TypeError for a non-object root, non-JSON runtime data or malformed Unicode.
 */
export function canonicalResponseSignedPayloadBytes(response: unknown): Uint8Array<ArrayBuffer> {
  const payload = responseSnapshot(response);
  delete payload.authoredSignatures;
  return framedBytes(SIGNING_DOMAIN, payload);
}

/**
 * Serializes any JSON value as canonical JSON, matching Rust `canonical_json_from_bytes`.
 *
 * Applies the same admission rules as the Response profiles (no accessors, hooks, cycles, sparse
 * arrays or malformed Unicode) and adds no domain framing. The root may be any JSON value.
 *
 * @throws TypeError for non-JSON runtime values or malformed Unicode.
 */
export function canonicalJsonBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(serialize(jsonSnapshot(value, new Set())));
}

type JsonValue = null | string | boolean | number | CanonicalNumber | JsonValue[] | { [key: string]: JsonValue };

/** A raw number already laid out canonically by admission, so serialization never lays it out twice. */
class CanonicalNumber {
  constructor(readonly text: string) {}
}

function responseSnapshot(response: unknown): Record<string, JsonValue> {
  if (response === null || typeof response !== 'object' || Array.isArray(response) || isRawJson(response)) {
    throw new TypeError('response must be a JSON object');
  }
  return jsonSnapshot(response, new Set()) as Record<string, JsonValue>;
}

function framedBytes(domain: string, response: JsonValue): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${domain}\0${serialize(response)}`);
}

// Serializes an admitted snapshot. JSON.stringify escapes strings exactly as RFC 8785
// §3.2.2.2 requires, and the default sort orders member names by UTF-16 code units (§3.2.3).
function serialize(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value instanceof CanonicalNumber) return value.text;
  if (Array.isArray(value)) return `[${Array.prototype.map.call(value, serialize).join(',')}]`;
  const object = value as { [key: string]: JsonValue };
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${serialize(object[key])}`).join(',')}}`;
}

// Out of range means a nonzero value that binary64 round-to-nearest-even takes to infinity
// (magnitude >= 2^1024 - 2^970 = 0.OVERFLOW_DIGITS x 10^309) or to zero (magnitude <= 2^-1075
// = 5^1075 / 10^1075 = 0.UNDERFLOW_DIGITS x 10^-323). Rust and Python use the same bounds.
const OVERFLOW_DIGITS = (2n ** 1024n - 2n ** 970n).toString();
const UNDERFLOW_DIGITS = (5n ** 1075n).toString();
// Exponents are read up to this magnitude; a larger one is already far out of range.
const MAX_EXPONENT = 1e15;

/** Compares 0.digits with 0.bound; neither has trailing zeros. */
function compareFraction(digits: string, bound: string): number {
  const common = Math.min(digits.length, bound.length);
  for (let at = 0; at < common; at += 1) {
    const difference = digits.charCodeAt(at) - bound.charCodeAt(at);
    if (difference !== 0) return difference;
  }
  return digits.length - bound.length;
}

/**
 * Lays out JSON number text as its exact decimal value in `Number::toString` layout.
 *
 * ECMA-262 §6.1.6.1.20 lays out the digits `s` (`k` of them, no trailing zeros) of a
 * value `s × 10^(n−k)`; RFC 8785 takes `s` from the nearest double, this takes it
 * from the text. A nonzero value that binary64 rounding takes to zero or infinity is
 * refused, decided from the digits alone, as RFC 8785 refuses non-finite values. One
 * left-to-right scan validates the grammar and finds the parts; work is linear in the text.
 */
function canonicalNumber(text: string): string {
  const refuse = (): never => { throw new TypeError('response contains a non-number raw JSON value'); };
  const isDigit = (index: number): boolean => {
    const code = text.charCodeAt(index);
    return code >= 48 && code <= 57;
  };
  const length = text.length;
  let index = text.charCodeAt(0) === 45 ? 1 : 0;
  const negative = index === 1;
  const integerStart = index;
  if (text.charCodeAt(index) === 48) index += 1;
  else if (isDigit(index)) while (isDigit(index)) index += 1;
  else refuse();
  const integerEnd = index;
  let fractionStart = index;
  let fractionEnd = index;
  if (text.charCodeAt(index) === 46) {
    fractionStart = index + 1;
    index = fractionStart;
    while (isDigit(index)) index += 1;
    fractionEnd = index;
    if (fractionEnd === fractionStart) refuse();
  }
  let exponentSign = 1;
  let exponentStart = index;
  let exponentEnd = index;
  const marker = text.charCodeAt(index);
  if (marker === 101 || marker === 69) {
    index += 1;
    if (text.charCodeAt(index) === 43 || text.charCodeAt(index) === 45) {
      if (text.charCodeAt(index) === 45) exponentSign = -1;
      index += 1;
    }
    exponentStart = index;
    while (isDigit(index)) index += 1;
    exponentEnd = index;
    if (exponentEnd === exponentStart) refuse();
  }
  if (index !== length) refuse();

  const firstNonZero = (from: number, to: number): number => {
    for (let at = from; at < to; at += 1) if (text.charCodeAt(at) !== 48) return at;
    return -1;
  };
  const lastNonZero = (from: number, to: number): number => {
    for (let at = to - 1; at >= from; at -= 1) if (text.charCodeAt(at) !== 48) return at;
    return -1;
  };
  const firstInInteger = firstNonZero(integerStart, integerEnd);
  const first = firstInInteger >= 0 ? firstInInteger : firstNonZero(fractionStart, fractionEnd);
  if (first < 0) return '0';
  const lastInFraction = lastNonZero(fractionStart, fractionEnd);
  const last = lastInFraction >= 0 ? lastInFraction : lastNonZero(integerStart, integerEnd);
  const digits = firstInInteger >= 0 && lastInFraction >= 0
    ? text.slice(first, integerEnd) + text.slice(fractionStart, last + 1)
    : text.slice(first, last + 1);
  const k = digits.length;
  let exponent = 0;
  for (let at = exponentStart; at < exponentEnd && exponent < MAX_EXPONENT; at += 1) {
    exponent = exponent * 10 + text.charCodeAt(at) - 48;
  }
  // value = 0.digits × 10^n
  const n = exponentSign * exponent + (firstInInteger >= 0 ? integerEnd - first : fractionStart - first);
  if (n > 309 || (n === 309 && compareFraction(digits, OVERFLOW_DIGITS) >= 0)
    || n < -323 || (n === -323 && compareFraction(digits, UNDERFLOW_DIGITS) <= 0)) {
    throw new TypeError('response number is outside the binary64 range');
  }
  let body: string;
  if (k <= n && n <= 21) body = digits + '0'.repeat(n - k);
  else if (0 < n && n <= 21) body = `${digits.slice(0, n)}.${digits.slice(n)}`;
  else if (-6 < n && n <= 0) body = `0.${'0'.repeat(-n)}${digits}`;
  else body = `${digits[0]}${k > 1 ? `.${digits.slice(1)}` : ''}e${n > 0 ? '+' : '-'}${Math.abs(n - 1)}`;
  return negative ? `-${body}` : body;
}

// Admission checking: serialize only admitted descriptor values, so runtime
// Proxy reads cannot replace the checked data.
function jsonSnapshot(value: unknown, ancestors: Set<object>): JsonValue {
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new TypeError('response contains invalid Unicode');
    return value;
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (isRawJson(value)) return new CanonicalNumber(canonicalNumber(value.rawJSON));
  if (typeof value !== 'object') {
    throw new TypeError('response contains a non-JSON value');
  }
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('response contains a non-JSON object');
  }
  // Refuse inherited toJSON hooks, inspecting descriptors without executing
  // inherited getters or letting prototype hooks replace data.
  for (let parent = prototype; parent !== null; parent = Object.getPrototypeOf(parent)) {
    const hook = Object.getOwnPropertyDescriptor(parent, 'toJSON');
    if (hook && (!('value' in hook) || typeof hook.value === 'function')) {
      throw new TypeError('response inherits a serialization hook');
    }
  }
  if (ancestors.has(value)) throw new TypeError('response contains a cycle');
  ancestors.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new TypeError('response contains symbol properties');
  }
  const length = array ? descriptors.length?.value : 0;
  if (array && (!Number.isInteger(length) || length < 0 || Object.keys(descriptors).length !== length + 1)) {
    throw new TypeError('response contains a sparse array or extra array properties');
  }
  const snapshot: Record<string, JsonValue> = array ? Object.setPrototypeOf(new Array(length), null) : Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!key.isWellFormed()) throw new TypeError('response contains invalid Unicode');
    if (array && key === 'length') continue;
    if (!descriptor.enumerable || !('value' in descriptor)) {
      throw new TypeError('response contains an accessor or non-JSON property');
    }
    if (array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= length)) {
      throw new TypeError('response contains extra array properties');
    }
    Object.defineProperty(snapshot, key, {
      value: jsonSnapshot(descriptor.value, ancestors), enumerable: true, configurable: true, writable: true,
    });
  }
  ancestors.delete(value);
  return snapshot;
}

/** Distinct Rust-authoritative Response handoff and signing byte profiles. */
import canonicalize from 'canonicalize';

const HANDOFF_DOMAIN = 'formspec.response.handoff.v1';
const SIGNING_DOMAIN = 'formspec.response.signed-payload.v1';

/**
 * Builds the Rust-authoritative domain, NUL, and RFC 8785 JCS handoff bytes.
 *
 * Preserves the complete JSON object, including authoredSignatures. The caller
 * hashes these bytes using genuine SHA-256; this function performs no crypto or
 * Response schema validation. Requires TextEncoder and String.isWellFormed.
 *
 * @throws TypeError for a non-object root or non-JSON runtime values. The
 * maintained canonicalizer also rejects invalid Unicode strings and keys.
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
 * Serializes any JSON value with RFC 8785 JCS, matching Rust `canonical_json_bytes`.
 *
 * Applies the same admission rules as the Response profiles (no accessors, hooks, cycles, sparse
 * arrays or malformed Unicode) and adds no domain framing. The root may be any JSON value.
 *
 * @throws TypeError for non-JSON runtime values or malformed Unicode.
 */
export function canonicalJsonBytes(value: unknown): Uint8Array<ArrayBuffer> {
  const json = canonicalize(jsonSnapshot(value, new Set()));
  if (json === undefined) throw new TypeError('value must have a canonical JSON representation');
  return new TextEncoder().encode(json);
}

type JsonValue = null | string | boolean | number | JsonValue[] | { [key: string]: JsonValue };

function responseSnapshot(response: unknown): Record<string, JsonValue> {
  if (response === null || typeof response !== 'object' || Array.isArray(response)) {
    throw new TypeError('response must be a JSON object');
  }
  return jsonSnapshot(response, new Set()) as Record<string, JsonValue>;
}

function framedBytes(domain: string, response: unknown): Uint8Array<ArrayBuffer> {
  const json = canonicalize(response);
  if (json === undefined) throw new TypeError('response must have a canonical JSON representation');
  return new TextEncoder().encode(`${domain}\0${json}`);
}

// Admission checking only: serialization, ordering, and number formatting all
// belong to the maintained RFC 8785 implementation. Serialize only admitted
// descriptor values, so runtime Proxy reads cannot replace the checked data.
function jsonSnapshot(value: unknown, ancestors: Set<object>): JsonValue {
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new TypeError('response contains invalid Unicode');
    return value;
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') {
    throw new TypeError('response contains a non-JSON value');
  }
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('response contains a non-JSON object');
  }
  // The dependency consults inherited toJSON too. Inspect descriptors without
  // executing inherited getters or allowing prototype hooks to replace data.
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

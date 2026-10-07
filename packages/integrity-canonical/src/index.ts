/** Full-Response handoff bytes; signature preimages remain a distinct profile. */
import canonicalize from 'canonicalize';

const HANDOFF_DOMAIN = 'formspec.response.handoff.v1';

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
  if (response === null || typeof response !== 'object' || Array.isArray(response)) {
    throw new TypeError('response must be a JSON object');
  }
  assertJsonValue(response, new Set());
  const json = canonicalize(response);
  if (json === undefined) {
    throw new TypeError('response must have a canonical JSON representation');
  }
  return new TextEncoder().encode(`${HANDOFF_DOMAIN}\0${json}`);
}

// Admission checking only: serialization, ordering, and number formatting all
// belong to the maintained RFC 8785 implementation. Never drop input values.
function assertJsonValue(value: unknown, ancestors: Set<object>): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
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
  if (array && Object.keys(descriptors).length !== value.length + 1) {
    throw new TypeError('response contains a sparse array or extra array properties');
  }
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (array && key === 'length') continue;
    if (!descriptor.enumerable || !('value' in descriptor)) {
      throw new TypeError('response contains an accessor or non-JSON property');
    }
    if (array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) {
      throw new TypeError('response contains extra array properties');
    }
    assertJsonValue(descriptor.value, ancestors);
  }
  ancestors.delete(value);
}

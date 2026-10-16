import { canonicalJsonBytes } from '@formspec-org/integrity-canonical';
import { fail } from './errors.js';

/** `_sd_alg` value this package issues and accepts. */
export const SD_ALG = 'sha-256';
/** Salt size in bytes: 128 bits, the RFC 9901 §4.2.1 minimum. */
export const SALT_BYTES = 16;
/** Largest accepted presentation in bytes of compact serialization. */
export const MAX_PRESENTATION_BYTES = 4 * 1024 * 1024;
/** Largest number of claims one SD-JWT may commit to. */
export const MAX_CLAIMS = 4096;
/** Largest number of disclosures a presentation may carry. */
export const MAX_DISCLOSURES = MAX_CLAIMS;
/** Largest `_sd` array the verifier reads. */
export const MAX_SD_DIGESTS = 2 * MAX_CLAIMS;
/** Longest claim path in bytes. */
export const MAX_PATH_BYTES = 1024;
/** Longest `iss` in bytes. */
export const MAX_ISS_BYTES = 1024;
/** Longest `kid` or `typ` in bytes. */
export const MAX_NAME_BYTES = 256;
/** Deepest JSON nesting accepted anywhere, checked on text before parsing. */
export const MAX_JSON_DEPTH = 32;

const DIGEST_CHARS = 43;
const encoder = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export const utf8 = (text: string): Uint8Array<ArrayBuffer> => encoder.encode(text);

export function utf8Text(bytes: Uint8Array, code: 'malformed_json' | 'malformed_disclosure'): string {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return fail(code, code === 'malformed_json' ? 'segment is not UTF-8' : 'not UTF-8');
  }
}

export function b64uEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Strict unpadded base64url: alphabet only, no stray bits, canonical re-encoding. */
export function b64uDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    return fail('malformed_base64url', 'not strict unpadded base64url');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  if (b64uEncode(bytes) !== text) return fail('malformed_base64url', 'not strict unpadded base64url');
  return bytes;
}

export async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

/** Computes the RFC 9901 §4.2.3 digest: base64url SHA-256 over the US-ASCII disclosure string. */
export async function disclosureDigest(encoded: string): Promise<string> {
  return b64uEncode(await sha256(utf8(encoded)));
}

export function isDigest(digest: string): boolean {
  if (digest.length !== DIGEST_CHARS) return false;
  try {
    return b64uDecode(digest).length === 32;
  } catch {
    return false;
  }
}

/** JCS bytes of an admissible JSON value. */
export function jcs(value: unknown): Uint8Array {
  try {
    return canonicalJsonBytes(value);
  } catch {
    return fail('malformed_json', 'not canonicalizable JSON');
  }
}

/** `base64url(JCS([salt, path, value]))`, the pinned disclosure encoding. */
export function encodeDisclosure(salt: string, path: string, value: unknown): string {
  return b64uEncode(jcs([salt, path, value]));
}

/** True when the JSON text nests deeper than {@link MAX_JSON_DEPTH}. */
export function tooDeep(text: string): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === 0x5c) escaped = true;
      else if (ch === 0x22) inString = false;
    } else if (ch === 0x22) inString = true;
    else if (ch === 0x5b || ch === 0x7b) {
      depth += 1;
      if (depth > MAX_JSON_DEPTH) return true;
    } else if ((ch === 0x5d || ch === 0x7d) && depth > 0) depth -= 1;
  }
  return false;
}

/** Throws unless every string (and key) is well formed and every number is finite. */
function assertAdmissible(value: unknown): void {
  if (typeof value === 'string') {
    if (!value.isWellFormed()) fail('malformed_json', 'not valid JSON');
  } else if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('malformed_json', 'not valid JSON');
  } else if (Array.isArray(value)) {
    for (const item of value) assertAdmissible(item);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (!key.isWellFormed()) fail('malformed_json', 'not valid JSON');
      assertAdmissible(item);
    }
  }
}

/** Parses JSON text after the depth bound, with the strictness serde_json has natively. */
export function parseJson(text: string): Json {
  if (tooDeep(text)) return fail('malformed_json', 'JSON nests too deeply');
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return fail('malformed_json', 'not valid JSON');
  }
  assertAdmissible(value);
  return value as Json;
}

export type Scan = 'clean' | 'too_deep' | 'reserved_key';

/** Looks for nesting beyond the bound and for `_sd` or `...` keys, which carry RFC 9901 meaning. */
export function scanValue(value: unknown, depth: number): Scan {
  if (depth > MAX_JSON_DEPTH) return 'too_deep';
  if (Array.isArray(value)) {
    for (const item of value) {
      const inner = scanValue(item, depth + 1);
      if (inner !== 'clean') return inner;
    }
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (key === '_sd' || key === '...') return 'reserved_key';
      const inner = scanValue(item, depth + 1);
      if (inner !== 'clean') return inner;
    }
  }
  return 'clean';
}

/**
 * Claim names the issuer refuses and the verifier rejects as disclosure paths. Same list, same
 * order as Rust `REFUSED_CLAIM_NAMES`; the shared vectors pin the equality.
 *
 * A closed set: RFC 9901 structure names, RFC 7519 registered names plus `cnf`, `vct` and
 * `status` (which libraries such as sd-jwt-js read as validity claims or the subject), and every
 * `Object.prototype` member (which JavaScript libraries refuse because they test `key in payload`).
 */
export const REFUSED_CLAIM_NAMES: readonly string[] = [
  '_sd', '_sd_alg', '...', 'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'cnf', 'vct', 'status',
  '__proto__', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__',
  'constructor', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString',
  'valueOf',
];
const refused = new Set(REFUSED_CLAIM_NAMES);
export const isReservedName = (name: string): boolean => refused.has(name);

/** Reads the claim path out of an encoded disclosure, so callers never trust a stored copy. */
export function disclosurePath(encoded: string): string {
  const parsed = parseJson(utf8Text(b64uDecode(encoded), 'malformed_disclosure'));
  if (!Array.isArray(parsed) || parsed.length !== 3) return fail('malformed_disclosure', 'disclosure is not [salt, name, value]');
  const path = parsed[1];
  return typeof path === 'string' ? path : fail('malformed_disclosure', 'claim name must be a string');
}

export const hasOwn = (object: object, key: string): boolean => Object.prototype.hasOwnProperty.call(object, key);

/** Own property read that never reaches `Object.prototype`. */
export const own = (object: object, key: string): unknown => (hasOwn(object, key) ? (object as Record<string, unknown>)[key] : undefined);

/** Assigns an own data property, including the name `__proto__`. */
export function setOwn(object: object, key: string, value: unknown): void {
  Object.defineProperty(object, key, { value, enumerable: true, configurable: true, writable: true });
}

/** Orders strings by their UTF-8 bytes, as Rust `String` ordering does. */
export function compareUtf8(a: string, b: string): number {
  const x = utf8(a);
  const y = utf8(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

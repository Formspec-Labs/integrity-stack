import { fail } from './errors.js';
import {
  MAX_DISCLOSURES, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES, MAX_SD_DIGESTS, SALT_BYTES, SD_ALG,
  b64uDecode, bytesEqual, disclosureDigest, hasOwn, isDigest, isReservedName, jcs, own, parseJson, scanValue,
  setOwn, utf8, utf8Text, type Json,
} from './wire.js';

/** What a relying party pins about an issuer, from the agency's own publication. */
export interface IssuerPin {
  /** Expected payload `iss`. */
  iss: string;
  /** Expected header `kid`. Pins in one call must have distinct `kid`s. */
  kid: string;
  /** Ed25519 public key (32 bytes) for `(iss, kid)`. */
  publicKey: Uint8Array;
}

/**
 * `pinned`: this stack's profile (JCS header, payload and disclosures, 128-bit salts).
 * `rfc9901`: any RFC 9901 encoding, still limited to flat object-property disclosures.
 */
export type Encoding = 'pinned' | 'rfc9901';

export interface VerifyOptions {
  /** Required JWT `typ`, for example `formspec-response+sd-jwt`. */
  expectedTyp: string;
  encoding: Encoding;
}

export interface DisclosedClaim {
  path: string;
  value: Json;
  /** JCS text of the value. Show this, never a re-serialization: JCS numbers are IEEE doubles. */
  valueJcs: string;
}

export interface Verified {
  iss: string;
  kid: string;
  /** Always-visible payload claims, without `iss`, `_sd` and `_sd_alg`. */
  publicClaims: Record<string, Json>;
  /** Disclosed claims in presentation order. */
  disclosed: DisclosedClaim[];
}

type JsonObject = { [key: string]: Json };
const isObject = (value: unknown): value is JsonObject => value !== null && typeof value === 'object' && !Array.isArray(value);

function jwtParts(jwt: string): [string, string, string] {
  const parts = jwt.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return fail('malformed_compact', 'JWT is not header.payload.signature');
  }
  return parts as [string, string, string];
}

/** Reads the `_sd` digests of a JWT without verifying it. Never trust the result for a decision. */
export function jwtSdDigests(jwt: string): Set<string> {
  const [, payload] = jwtParts(jwt);
  return sdDigests(parseJson(utf8Text(b64uDecode(payload), 'malformed_json')));
}

function sdDigests(payload: Json): Set<string> {
  const list = isObject(payload) ? own(payload, '_sd') : undefined;
  if (!Array.isArray(list)) return fail('malformed_sd', '_sd is missing or not an array');
  if (list.length > MAX_SD_DIGESTS) return fail('input_too_large', '_sd is longer than MAX_SD_DIGESTS');
  const digests = new Set<string>();
  for (const entry of list) {
    if (typeof entry !== 'string' || !isDigest(entry)) return fail('malformed_sd', '_sd holds a malformed digest');
    if (digests.has(entry)) return fail('duplicate_digest', '_sd repeats a digest');
    digests.add(entry);
  }
  return digests;
}

function requireCanonical(value: Json, bytes: Uint8Array, code: 'unsupported_header' | 'malformed_json'): void {
  if (!bytesEqual(jcs(value), bytes)) fail(code, 'not canonical (JCS) JSON');
}

function checkHeader(header: Json, expectedTyp: string): string {
  if (!isObject(header)) return fail('unsupported_header', 'header is not an object');
  if (Object.keys(header).length !== 3) return fail('unsupported_header', 'header must be exactly alg, typ, kid');
  const [alg, typ, kid] = [own(header, 'alg'), own(header, 'typ'), own(header, 'kid')];
  if (alg === 'EdDSA' && typeof typ === 'string' && typ === expectedTyp && typeof kid === 'string' && kid.length > 0) {
    return kid;
  }
  return fail('unsupported_header', 'header alg, typ or kid is not accepted');
}

function selectPin(pins: readonly IssuerPin[], kid: string): IssuerPin {
  const seen = new Set<string>();
  for (const pin of pins) {
    if (seen.has(pin.kid)) return fail('ambiguous_pins', 'two pins share a kid');
    seen.add(pin.kid);
  }
  const pin = pins.find((candidate) => candidate.kid === kid);
  return pin ?? fail('unknown_key', 'no pin for this kid');
}

async function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey('raw', publicKey as BufferSource, 'Ed25519', false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, signature as BufferSource, message as BufferSource);
  } catch {
    return false;
  }
}

/** Decodes and shapes one disclosure; the caller has already matched its digest to `_sd`. */
function parseDisclosure(encoded: string, strict: boolean): DisclosedClaim {
  const bytes = b64uDecode(encoded);
  const parsed = parseJson(utf8Text(bytes, 'malformed_disclosure'));
  if (!Array.isArray(parsed)) return fail('malformed_disclosure', 'disclosure is not an array');
  if (parsed.length === 2) return fail('unsupported_structure', 'array-element disclosures are not supported');
  if (parsed.length !== 3) return fail('malformed_disclosure', 'disclosure is not [salt, name, value]');
  const [salt, path, value] = parsed;
  if (typeof salt !== 'string' || typeof path !== 'string') {
    return fail('malformed_disclosure', 'salt and name must be strings');
  }
  if (scanValue(value, 0) !== 'clean') return fail('unsupported_structure', 'disclosed value nests _sd or ...');
  const valueJcs = new TextDecoder().decode(jcs(value));
  if (strict) {
    if (!bytesEqual(jcs([salt, path, value]), bytes)) {
      return fail('non_canonical_disclosure', 'disclosure is not JCS([salt, path, value])');
    }
    let saltLength = -1;
    try {
      saltLength = b64uDecode(salt).length;
    } catch {
      saltLength = -1;
    }
    if (saltLength !== SALT_BYTES) return fail('weak_salt', 'salt is not exactly 128 bits');
  }
  return { path, value, valueJcs };
}

/**
 * Verifies an SD-JWT presentation offline.
 *
 * In order, failing closed on the first problem: size and shape of `jwt~d1~...~` (a trailing
 * key-binding JWT is refused); header exactly `{alg: "EdDSA", typ, kid}` selecting one pin; the
 * Ed25519 signature under that pin; `iss` equals the pin's; `_sd_alg` is `sha-256`; `_sd` holds
 * unique digests; each disclosure's digest is in `_sd`, no digest or path repeats, no path
 * collides with a payload claim, and (pinned encoding) each is canonical with a 128-bit salt.
 *
 * Time claims (`exp`, `nbf`) are not interpreted: freshness is the relying party's policy.
 *
 * @throws DisclosureError naming the first failed rule.
 */
export async function verify(
  presentation: string,
  pins: readonly IssuerPin[],
  options: VerifyOptions,
): Promise<Verified> {
  // Rust measures bytes; measure UTF-8 bytes here too, but only when the text could exceed the bound.
  if (presentation.length * 3 > MAX_PRESENTATION_BYTES && utf8(presentation).length > MAX_PRESENTATION_BYTES) {
    return fail('input_too_large', 'presentation exceeds MAX_PRESENTATION_BYTES');
  }
  if (!/^[A-Za-z0-9_.~-]*$/.test(presentation)) {
    return fail('malformed_compact', 'presentation has a non-compact character');
  }
  const [jwt, ...tail] = presentation.split('~');
  // `jwt~d1~...~` ends in an empty segment; a non-empty last segment is a key-binding JWT or a
  // missing tilde, and the bearer profile accepts neither.
  if (tail.pop() !== '') return fail('malformed_compact', 'presentation must end with ~');
  if (tail.length > MAX_DISCLOSURES) return fail('input_too_large', 'more disclosures than MAX_DISCLOSURES');
  if (tail.some((segment) => segment.length === 0)) return fail('malformed_compact', 'empty disclosure segment');

  const [headerB64, payloadB64, signatureB64] = jwtParts(jwt);
  const strict = options.encoding === 'pinned';

  const headerBytes = b64uDecode(headerB64);
  const header = parseJson(utf8Text(headerBytes, 'malformed_json'));
  if (strict) requireCanonical(header, headerBytes, 'unsupported_header');
  const kid = checkHeader(header, options.expectedTyp);

  const pin = selectPin(pins, kid);

  const signature = b64uDecode(signatureB64);
  if (signature.length !== 64) return fail('bad_signature', 'signature is not 64 bytes');
  const signingInput = utf8(`${headerB64}.${payloadB64}`);
  if (!(await verifyEd25519(pin.publicKey, signingInput, signature))) {
    return fail('bad_signature', 'signature does not verify under the pinned key');
  }

  const payloadBytes = b64uDecode(payloadB64);
  const payload = parseJson(utf8Text(payloadBytes, 'malformed_json'));
  if (strict) requireCanonical(payload, payloadBytes, 'malformed_json');
  if (!isObject(payload)) return fail('malformed_json', 'payload is not an object');
  if (own(payload, 'iss') !== pin.iss) return fail('wrong_issuer', 'iss is not the pinned issuer');
  const sdAlg = own(payload, '_sd_alg');
  if (!(sdAlg === SD_ALG || (sdAlg === undefined && !strict))) {
    return fail('unsupported_sd_alg', '_sd_alg is not sha-256');
  }
  if (hasOwn(payload, 'cnf') || hasOwn(payload, '...')) {
    return fail('unsupported_structure', 'key binding is not supported');
  }
  for (const [name, value] of Object.entries(payload)) {
    if (name !== '_sd' && scanValue(value, 0) !== 'clean') {
      return fail('unsupported_structure', 'payload nests _sd or ...');
    }
  }
  const listed = sdDigests(payload);

  const seenDigests = new Set<string>();
  const seenPaths = new Set<string>();
  const disclosed: DisclosedClaim[] = [];
  for (const encoded of tail) {
    const digest = await disclosureDigest(encoded);
    if (!listed.has(digest)) return fail('unknown_digest', 'a disclosure digest is not in _sd');
    if (seenDigests.has(digest)) return fail('duplicate_disclosure', 'a disclosure is presented twice');
    seenDigests.add(digest);
    const claim = parseDisclosure(encoded, strict);
    if (
      claim.path.length === 0 ||
      utf8(claim.path).length > MAX_PATH_BYTES ||
      isReservedName(claim.path) ||
      hasOwn(payload, claim.path)
    ) {
      return fail('reserved_claim_name', 'a path collides with a payload claim');
    }
    if (seenPaths.has(claim.path)) return fail('duplicate_path', 'two disclosures name the same path');
    seenPaths.add(claim.path);
    disclosed.push(claim);
  }

  const publicClaims: Record<string, Json> = Object.create(null);
  for (const [name, value] of Object.entries(payload)) {
    if (name !== 'iss' && name !== '_sd' && name !== '_sd_alg') setOwn(publicClaims, name, value);
  }
  return { iss: pin.iss, kid: pin.kid, publicClaims, disclosed };
}

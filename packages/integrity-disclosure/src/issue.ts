import { fail } from './errors.js';
import { jwtSdDigests } from './verify.js';
import {
  MAX_CLAIMS, MAX_ISS_BYTES, MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES, SALT_BYTES, SD_ALG,
  b64uDecode, b64uEncode, compareUtf8, disclosurePath, disclosureDigest, encodeDisclosure, hasOwn, isReservedName, jcs, own,
  scanValue, setOwn, utf8, utf8Text, type Json,
} from './wire.js';

/**
 * Test-only issuer: the production issuer is the Rust crate, and this module is excluded from the
 * published build. It exists to prove the TS encoding is byte-identical to Rust.
 */

/** JWS `alg` for Ed25519 (RFC 8037). */
export const ALG_EDDSA = 'EdDSA';

/** Fills a buffer with cryptographically secure random bytes. Mirrors Rust `SecureRandom`. */
export interface SecureRandom {
  fillBytes(dest: Uint8Array): void;
}

/** Reads secure bytes from Web Crypto. */
export const osSecureRandom: SecureRandom = {
  fillBytes(dest) {
    crypto.getRandomValues(dest);
  },
};

/**
 * Returns how many `_sd` entries an SD-JWT with `claims` claims carries.
 *
 * The decoy and padding policy: `_sd` is padded with decoy digests to the next power of two, so a
 * presentation reveals the claim count only to within a factor of two. A decoy is the digest of a
 * fresh 128-bit salt string (RFC 9901 §4.2.5).
 */
export function paddedDigestCount(claims: number): number {
  let size = 1;
  while (size < claims) size *= 2;
  return size;
}

/** Salts for one issuance. Same JSON shape as the Rust `IssuanceSalts`. */
export interface IssuanceSalts {
  /** Salt string (base64url of 128 random bits) by claim path. Own properties only. */
  claims: Record<string, string>;
  /** Salt strings behind the decoy digests. */
  decoys: string[];
}

function freshSalt(rng: SecureRandom): string {
  const bytes = new Uint8Array(SALT_BYTES);
  try {
    rng.fillBytes(bytes);
  } catch {
    return fail('entropy', 'entropy source failed');
  }
  return b64uEncode(bytes);
}

function checkSalt(salt: unknown): void {
  let ok = false;
  try {
    ok = typeof salt === 'string' && b64uDecode(salt).length === SALT_BYTES;
  } catch {
    ok = false;
  }
  if (!ok) fail('invalid_salts', 'salt is not 128 bits of base64url');
}

/** Draws a fresh salt per path and per decoy the padding policy needs. */
export function generateSalts(paths: readonly string[], rng: SecureRandom = osSecureRandom): IssuanceSalts {
  if (paths.length === 0 || paths.length > MAX_CLAIMS) fail('invalid_claims', 'claim count must be between 1 and MAX_CLAIMS');
  const claims: Record<string, string> = Object.create(null);
  for (const path of paths) {
    if (hasOwn(claims, path)) fail('invalid_claims', 'duplicate claim path');
    setOwn(claims, path, freshSalt(rng));
  }
  const decoys: string[] = [];
  for (let i = paths.length; i < paddedDigestCount(paths.length); i++) decoys.push(freshSalt(rng));
  return { claims, decoys };
}

/** Issuer inputs besides the claims, salts and key. */
export interface IssueParams {
  /** Issuer identifier. Derive it from tenant context, never from author input. */
  iss: string;
  /** Key identifier the relying party pins beside `iss`. */
  kid: string;
  /** JWT `typ` header, for example `formspec-response+sd-jwt`. */
  typ: string;
  /** Claims shown to everyone. Must not use `iss`, `cnf`, `_sd`, `_sd_alg` or `...`. */
  publicClaims: Record<string, unknown>;
}

/** One disclosure, ready to present. */
export interface IssuedDisclosure {
  path: string;
  /** `base64url(JCS([salt, path, value]))`. */
  encoded: string;
  /** Base64url SHA-256 digest of `encoded`, as listed in `_sd`. */
  digest: string;
}

/** An issued SD-JWT: the signed issuer JWT and every disclosure, sorted by path. */
export interface Issued {
  jwt: string;
  disclosures: IssuedDisclosure[];
}

export type ClaimInput = readonly [path: string, value: unknown];

/** Builds every claim's disclosure from claims and stored salts, sorted by path (UTF-8 bytes). */
export async function buildDisclosures(
  claims: readonly ClaimInput[],
  salts: IssuanceSalts,
): Promise<IssuedDisclosure[]> {
  const invalid = (message: string): never => fail('invalid_claims', message);
  if (claims.length === 0 || claims.length > MAX_CLAIMS) invalid('claim count must be between 1 and MAX_CLAIMS');
  const sorted = claims
    .map(([path, value]) => ({ path, value }))
    .sort((a, b) => compareUtf8(a.path, b.path));
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i - 1].path === sorted[i].path) invalid('duplicate claim path');
  }
  const admitted: Json[] = [];
  for (const { path, value } of sorted) {
    if (typeof path !== 'string' || path.length === 0 || utf8(path).length > MAX_PATH_BYTES || isReservedName(path)) {
      invalid('claim path is empty, too long or a refused name');
    }
    // Round-trip through JCS so only admissible JSON survives; later steps never see accessors.
    const snapshot = JSON.parse(utf8Text(jcsOrInvalid(value), 'malformed_json')) as Json;
    if (scanValue(snapshot, 0) !== 'clean') invalid('claim value nests too deeply or uses _sd or ...');
    admitted.push(snapshot);
  }
  if (
    Object.keys(salts.claims).length !== sorted.length ||
    salts.decoys.length !== paddedDigestCount(sorted.length) - sorted.length
  ) {
    fail('invalid_salts', 'salts do not match the claims and padding policy');
  }
  const out: IssuedDisclosure[] = [];
  for (const [i, { path }] of sorted.entries()) {
    const salt = own(salts.claims, path);
    if (salt === undefined) fail('invalid_salts', 'no salt for a claim path');
    checkSalt(salt);
    const encoded = encodeDisclosure(salt as string, path, admitted[i]);
    out.push({ path, encoded, digest: await disclosureDigest(encoded) });
  }
  return out;
}

function jcsOrInvalid(value: unknown): Uint8Array {
  try {
    return jcs(value);
  } catch {
    return fail('invalid_claims', 'claim value is not JSON');
  }
}

function checkParams(params: IssueParams): Record<string, Json> {
  const bad = (message: string): never => fail('invalid_params', message);
  if (params.iss.length === 0 || utf8(params.iss).length > MAX_ISS_BYTES) bad('iss is empty or too long');
  if (params.kid.length === 0 || utf8(params.kid).length > MAX_NAME_BYTES) bad('kid is empty or too long');
  if (params.typ.length === 0 || utf8(params.typ).length > MAX_NAME_BYTES) bad('typ is empty or too long');
  let snapshot: Record<string, Json>;
  try {
    snapshot = JSON.parse(utf8Text(jcs(params.publicClaims), 'malformed_json')) as Record<string, Json>;
  } catch {
    return bad('public claims are not a JSON object');
  }
  for (const [name, value] of Object.entries(snapshot)) {
    if (['iss', 'cnf', '_sd', '_sd_alg', '...'].includes(name)) bad('public claim uses a reserved name');
    if (scanValue(value, 0) !== 'clean') bad('public claim nests too deeply or uses _sd or ...');
  }
  return snapshot;
}

/** Signs `message` with an Ed25519 seed through Web Crypto. */
async function signEd25519(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  if (seed.length !== 32) fail('invalid_params', 'signing seed must be 32 bytes');
  // PKCS#8 wrapper for a raw Ed25519 seed (RFC 8410).
  const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
  const pkcs8 = new Uint8Array(prefix.length + 32);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, 'Ed25519', false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('Ed25519', key, message as BufferSource));
}

/**
 * Issues an SD-JWT over `claims` using stored `salts`.
 *
 * The issuer JWT is Ed25519 over `b64(header).b64(payload)` with header `{alg, kid, typ}` and
 * payload `{...publicClaims, iss, _sd_alg, _sd}`, both JCS. `_sd` holds one digest per claim plus
 * decoys up to {@link paddedDigestCount}, sorted.
 */
export async function issue(
  params: IssueParams,
  claims: readonly ClaimInput[],
  salts: IssuanceSalts,
  signingSeed: Uint8Array,
): Promise<Issued> {
  const publicClaims = checkParams(params);
  const disclosures = await buildDisclosures(claims, salts);
  if (disclosures.some((d) => hasOwn(publicClaims, d.path) || d.path === 'iss' || d.path === 'cnf')) {
    fail('reserved_claim_name', 'a claim path collides with a public claim');
  }
  const digests = disclosures.map((d) => d.digest);
  for (const decoy of salts.decoys) {
    checkSalt(decoy);
    digests.push(await disclosureDigest(decoy));
  }
  digests.sort();
  if (digests.some((digest, i) => i > 0 && digests[i - 1] === digest)) {
    fail('invalid_salts', 'two salts produce the same digest');
  }
  const payload: Record<string, unknown> = Object.create(null);
  for (const [name, value] of Object.entries(publicClaims)) setOwn(payload, name, value);
  setOwn(payload, 'iss', params.iss);
  setOwn(payload, '_sd_alg', SD_ALG);
  setOwn(payload, '_sd', digests);
  const header = { alg: ALG_EDDSA, kid: params.kid, typ: params.typ };

  const signingInput = `${b64uEncode(jcs(header))}.${b64uEncode(jcs(payload))}`;
  const signature = await signEd25519(signingSeed, utf8(signingInput));
  const jwt = `${signingInput}.${b64uEncode(signature)}`;

  const total = jwt.length + disclosures.reduce((sum, d) => sum + d.encoded.length + 1, 0) + 1;
  if (total > MAX_PRESENTATION_BYTES) fail('input_too_large', 'issued SD-JWT exceeds MAX_PRESENTATION_BYTES');
  return { jwt, disclosures };
}

/** Issues with fresh random salts and returns them for storage. */
export async function issueWithRandom(
  params: IssueParams,
  claims: readonly ClaimInput[],
  signingSeed: Uint8Array,
  rng: SecureRandom = osSecureRandom,
): Promise<{ issued: Issued; salts: IssuanceSalts }> {
  const salts = generateSalts(claims.map(([path]) => path), rng);
  return { issued: await issue(params, claims, salts, signingSeed), salts };
}

/**
 * Presents `issuerJwt` with only the disclosures whose paths are in `paths`.
 *
 * `paths` is an allowlist of exact claim paths. Disclosures keep issuance order regardless of the
 * order of `paths`. Output is `<issuer-jwt>~<disclosure>~...~`.
 */
export async function present(issuerJwt: string, disclosures: readonly IssuedDisclosure[], paths: readonly string[]): Promise<string> {
  const wanted = new Set<string>();
  for (const path of paths) {
    if (wanted.has(path)) fail('duplicate_path', 'a path is requested twice');
    wanted.add(path);
  }
  // Path and digest come from `encoded`, never from the struct: a mismatched struct must not be
  // able to steer the allowlist or the membership check.
  const derived: { path: string; digest: string; encoded: string }[] = [];
  for (const disclosure of disclosures) {
    const path = disclosurePath(disclosure.encoded);
    const digest = await disclosureDigest(disclosure.encoded);
    if (path !== disclosure.path || digest !== disclosure.digest) {
      fail('malformed_disclosure', 'a disclosure struct does not match its encoded form');
    }
    derived.push({ path, digest, encoded: disclosure.encoded });
  }
  const known = new Set(derived.map((d) => d.path));
  for (const path of wanted) if (!known.has(path)) fail('unknown_path', 'a requested path is not a disclosure');
  const listed = jwtSdDigests(issuerJwt);
  let out = `${issuerJwt}~`;
  for (const disclosure of derived) {
    if (!wanted.has(disclosure.path)) continue;
    if (!listed.has(disclosure.digest)) fail('unknown_digest', 'a disclosure does not belong to this issuer JWT');
    out += `${disclosure.encoded}~`;
  }
  return out;
}

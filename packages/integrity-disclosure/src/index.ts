/**
 * RFC 9901 SD-JWT selective disclosure verification over generic JSON claims. Mirrors the Rust
 * `integrity-disclosure` crate; shared vectors prove the two agree byte for byte. Issuing and
 * presenting are the Rust crate's job; the TS issuer exists only inside this package's tests.
 */
export { DisclosureError, type ErrorCode } from './errors.js';
export {
  verify, type DisclosedClaim, type Encoding, type IssuerPin, type Verified, type VerifyOptions,
} from './verify.js';
export {
  MAX_CLAIMS, MAX_DISCLOSURES, MAX_JSON_DEPTH, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES, MAX_SD_DIGESTS,
  REFUSED_CLAIM_NAMES, SALT_BYTES, SD_ALG, disclosureDigest, type Json,
} from './wire.js';

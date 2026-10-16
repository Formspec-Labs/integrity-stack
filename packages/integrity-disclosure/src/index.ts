/**
 * RFC 9901 SD-JWT selective disclosure over generic JSON claims. Mirrors the Rust
 * `integrity-disclosure` crate; shared vectors prove the two produce identical bytes.
 */
export { DisclosureError, type ErrorCode } from './errors.js';
export {
  ALG_EDDSA, buildDisclosures, generateSalts, issue, issueWithRandom, osSecureRandom, paddedDigestCount, present,
  type ClaimInput, type IssuanceSalts, type IssueParams, type Issued, type IssuedDisclosure, type SecureRandom,
} from './issue.js';
export {
  verify, type DisclosedClaim, type Encoding, type IssuerPin, type Verified, type VerifyOptions,
} from './verify.js';
export {
  MAX_CLAIMS, MAX_DISCLOSURES, MAX_JSON_DEPTH, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES, MAX_SD_DIGESTS, SALT_BYTES,
  SD_ALG, disclosureDigest, type Json,
} from './wire.js';

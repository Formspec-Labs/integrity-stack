// Rust guideline compliant 2026-02-21

//! RFC 9901 SD-JWT selective disclosure over generic JSON claims.
//!
//! The crate issues an SD-JWT from `path -> value` claims, presents an allowlisted subset, and
//! verifies a presentation offline against a pinned `(iss, kid, key)`. It knows nothing about
//! Formspec types.
//!
//! # Profile
//!
//! - **Wire:** RFC 9901 `application/sd-jwt`, `<issuer-jwt>~<disclosure>~...~`. Flat object-property
//!   disclosures only; no key binding, nested or array-element disclosures.
//! - **Issuer JWT:** header `{alg: "EdDSA", kid, typ}`, payload `{iss, _sd_alg: "sha-256", _sd, ...public}`,
//!   both JCS, signed Ed25519 over `b64(header).b64(payload)`.
//! - **Disclosure:** `base64url(JCS([salt, path, value]))`, where `salt` is the base64url text of
//!   [`SALT_BYTES`] (128 bits) of CSPRNG output and `value` is the answer's canonical JSON.
//! - **Padding:** `_sd` is sorted and padded with decoy digests to the next power of two
//!   ([`padded_digest_count`]). A decoy is the digest of a fresh 128-bit salt string.
//! - **Crypto ownership:** hashing is `integrity-canonical`, Ed25519 is `integrity-cose`, entropy is
//!   `integrity-seam`. This crate depends on no hash or signature crate.
//!
//! # Examples
//!
//! ```
//! use integrity_disclosure::{
//!     Encoding, IssueParams, IssuerPin, VerifyOptions, issue_with_random, verify,
//! };
//! use integrity_seam::OsSecureRandom;
//! use serde_json::{Map, json};
//!
//! // RFC 8032 test vector 1: seed and public key.
//! let seed = [
//!     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
//!     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
//! ];
//! let public_key = [
//!     0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
//!     0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
//! ];
//! let params = IssueParams {
//!     iss: "https://issuer.example/t1".into(),
//!     kid: "k1".into(),
//!     typ: "example+sd-jwt".into(),
//!     public_claims: Map::new(),
//! };
//! let claims = vec![
//!     ("name".to_owned(), json!("Ada")),
//!     ("income".to_owned(), json!(42000)),
//! ];
//! let (issued, _salts) = issue_with_random(&params, &claims, &OsSecureRandom, &seed)?;
//! let presentation = issued.present(&["name"])?;
//!
//! let pin = IssuerPin { iss: params.iss, kid: params.kid, public_key };
//! let options = VerifyOptions { expected_typ: "example+sd-jwt", encoding: Encoding::Pinned };
//! let verified = verify(&presentation, &[pin], &options)?;
//! assert_eq!(verified.disclosed.len(), 1);
//! assert_eq!(verified.disclosed[0].value_jcs, "\"Ada\"");
//! # Ok::<(), integrity_disclosure::DisclosureError>(())
//! ```

mod error;
mod issue;
mod verify;
mod wire;

pub use error::{DisclosureError, ErrorCode, Result};
pub use issue::{
    IssuanceSalts, IssueParams, Issued, IssuedDisclosure, PreparedIssue, build_disclosures,
    check_claims, issue, issue_with_random, padded_digest_count, prepare, present,
};
pub use verify::{DisclosedClaim, Encoding, IssuerPin, Verified, VerifyOptions, verify};
pub use wire::{
    MAX_CLAIMS, MAX_DISCLOSURES, MAX_JSON_DEPTH, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES,
    MAX_SD_DIGESTS, REFUSED_CLAIM_NAMES, SALT_BYTES, SD_ALG, disclosure_digest,
};

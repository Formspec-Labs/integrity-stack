// Rust guideline compliant 2026-02-21

//! Error type shared by issuing, presenting and verifying.

use std::fmt;

/// Stable failure classes, identical in the Rust and TypeScript implementations.
///
/// Callers and the cross-language vectors match on [`ErrorCode::as_str`], never on messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The input exceeds a size or count bound.
    InputTooLarge,
    /// The compact serialization is not `jwt~disclosure~...~`.
    MalformedCompact,
    /// A segment is not strict unpadded base64url.
    MalformedBase64,
    /// A segment is not the JSON shape this profile accepts.
    MalformedJson,
    /// The JWT header is not `{alg: EdDSA, typ, kid}`.
    UnsupportedHeader,
    /// No pinned key matches the header `kid`.
    UnknownKey,
    /// Two pins share a `kid`.
    AmbiguousPins,
    /// The signature does not verify under the pinned key.
    BadSignature,
    /// The payload `iss` is not the pinned issuer.
    WrongIssuer,
    /// `_sd_alg` is not `sha-256`.
    UnsupportedSdAlg,
    /// `_sd` is missing, mistyped or holds a malformed digest.
    MalformedSd,
    /// `_sd` holds the same digest twice.
    DuplicateDigest,
    /// A feature outside the flat object-property profile is present.
    UnsupportedStructure,
    /// A disclosure is not `[salt, name, value]`.
    MalformedDisclosure,
    /// A disclosure is not `base64url(JCS([salt, path, value]))`.
    NonCanonicalDisclosure,
    /// A salt is not exactly 128 bits.
    WeakSalt,
    /// A disclosure digest is not in `_sd`.
    UnknownDigest,
    /// The same disclosure is presented twice.
    DuplicateDisclosure,
    /// Two disclosures name the same path.
    DuplicatePath,
    /// A path collides with a payload claim or a reserved name.
    ReservedClaimName,
    /// Issuer claims are empty, too many, duplicated or malformed.
    InvalidClaims,
    /// Salts do not match the claims.
    InvalidSalts,
    /// Issuer parameters are malformed.
    InvalidParams,
    /// A requested path is not an issued claim.
    UnknownPath,
    /// The entropy source failed.
    Entropy,
}

impl ErrorCode {
    /// Returns the wire-stable name of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::MalformedCompact => "malformed_compact",
            Self::MalformedBase64 => "malformed_base64url",
            Self::MalformedJson => "malformed_json",
            Self::UnsupportedHeader => "unsupported_header",
            Self::UnknownKey => "unknown_key",
            Self::AmbiguousPins => "ambiguous_pins",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::UnsupportedSdAlg => "unsupported_sd_alg",
            Self::MalformedSd => "malformed_sd",
            Self::DuplicateDigest => "duplicate_digest",
            Self::UnsupportedStructure => "unsupported_structure",
            Self::MalformedDisclosure => "malformed_disclosure",
            Self::NonCanonicalDisclosure => "non_canonical_disclosure",
            Self::WeakSalt => "weak_salt",
            Self::UnknownDigest => "unknown_digest",
            Self::DuplicateDisclosure => "duplicate_disclosure",
            Self::DuplicatePath => "duplicate_path",
            Self::ReservedClaimName => "reserved_claim_name",
            Self::InvalidClaims => "invalid_claims",
            Self::InvalidSalts => "invalid_salts",
            Self::InvalidParams => "invalid_params",
            Self::UnknownPath => "unknown_path",
            Self::Entropy => "entropy",
        }
    }
}

/// A failed disclosure operation.
///
/// The message names the failed rule and never echoes a claim value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureError {
    code: ErrorCode,
    message: String,
}

impl DisclosureError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

impl fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for DisclosureError {}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, DisclosureError>;

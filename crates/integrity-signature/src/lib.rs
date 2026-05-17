// Rust guideline compliant 2026-02-21
//! Generic signature verification and receipt-signing ports.
//!
//! This crate owns method-URI dispatch machinery, verification receipt DTOs,
//! key-resolution traits, and receipt-signing traits that are not specific to
//! Formspec or WOS. Consumer domains own the actual method URI subspaces,
//! signature meanings, admission policy, and semantic request facades.

#![forbid(unsafe_code)]

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, ops::Deref, sync::Arc};
use thiserror::Error;

/// Provides the current UTC time.
pub trait ClockPort: Send + Sync + 'static {
    /// Returns the current UTC instant.
    fn now_utc(&self) -> DateTime<Utc>;

    /// Returns the current UTC instant as Unix milliseconds.
    fn now_unix_millis(&self) -> i64 {
        self.now_utc().timestamp_millis()
    }
}

/// Shared clock handle.
pub type ClockHandle = Arc<dyn ClockPort>;

/// System UTC clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl ClockPort for SystemClock {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Fixed UTC clock for deterministic tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedClock {
    now: DateTime<Utc>,
}

impl FixedClock {
    /// Builds a fixed clock from an RFC 3339 timestamp.
    ///
    /// # Errors
    /// Returns [`chrono::ParseError`] when `rfc3339` is not a valid timestamp.
    pub fn at_rfc3339(rfc3339: &str) -> Result<Self, chrono::ParseError> {
        let parsed = chrono::DateTime::parse_from_rfc3339(rfc3339)?.with_timezone(&chrono::Utc);
        Ok(Self { now: parsed })
    }
}

impl ClockPort for FixedClock {
    fn now_utc(&self) -> DateTime<Utc> {
        self.now
    }
}

/// Formats a UTC timestamp as second-precision RFC 3339.
#[must_use]
pub fn utc_to_rfc3339_seconds(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Formats a UTC timestamp as millisecond-precision RFC 3339.
#[must_use]
pub fn utc_to_rfc3339_millis(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Semantic-version string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct SemVer(pub String);

/// URI string used by method registries and adapter identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct Uri(pub String);

/// Key identifier or thumbprint string for receipt rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct KidOrThumbprint(pub String);

macro_rules! string_newtype {
    ($type:ident) => {
        impl $type {
            /// Returns the string form.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $type {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $type {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl AsRef<str> for $type {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Deref for $type {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                self.as_str()
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl PartialEq<&str> for $type {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl PartialEq<$type> for &str {
            fn eq(&self, other: &$type) -> bool {
                *self == other.as_str()
            }
        }
    };
}

string_newtype!(SemVer);
string_newtype!(Uri);
string_newtype!(KidOrThumbprint);

/// Verifier-issued receipt for a reached signature verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceipt {
    /// Reached verifier result.
    pub result: VerificationResult,
    /// Signature method URI that selected the adapter path.
    pub method: Uri,
    /// Method-registry version used during verification.
    pub method_registry_version: SemVer,
    /// Adapter that reached the verdict.
    pub adapter: AdapterInfo,
    /// Key reference rendered into the receipt.
    pub key: KeyInfo,
    /// UTC timestamp when the verdict was reached.
    pub verified_at: String,
    /// Optional verification context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<VerificationContext>,
    /// Optional COSE_Sign1 receipt bytes, base64 encoded by serde.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_bytes: Option<String>,
}

/// Reached signature-verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationResult {
    /// Signature verified under the selected method.
    Verified,
    /// Signature was checked and failed cryptographically.
    Failed,
    /// Method, key, or envelope was unsupported before cryptographic verify.
    Unsupported,
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::Failed => write!(f, "failed"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

impl VerificationReceipt {
    /// Returns `true` when the verdict is verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self.result, VerificationResult::Verified)
    }

    /// Returns `true` when cryptographic verification was reached and failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self.result, VerificationResult::Failed)
    }

    /// Returns `true` when verification could not reach the crypto primitive.
    #[must_use]
    pub fn is_unsupported(&self) -> bool {
        matches!(self.result, VerificationResult::Unsupported)
    }
}

/// Verifier adapter metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterInfo {
    /// Stable adapter URI.
    pub id: Uri,
    /// Adapter version.
    pub version: SemVer,
}

/// Key metadata rendered into receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    /// Key reference.
    pub r#ref: KidOrThumbprint,
    /// Optional key version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional key snapshot reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
}

/// Optional verification context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationContext {
    /// Revocation context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationContext>,
    /// Timestamping context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamping: Option<TimestampingContext>,
    /// Witness context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessContext>,
}

/// Revocation evidence context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationContext {
    /// Revocation mechanism.
    pub kind: String,
    /// Hash of the revocation response.
    #[serde(rename = "responseHash")]
    pub response_hash: String,
}

/// Timestamping evidence context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampingContext {
    /// Timestamping authority URI.
    pub authority: Uri,
    /// Hash of the timestamping receipt.
    #[serde(rename = "receiptHash")]
    pub receipt_hash: String,
}

/// Witness evidence context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessContext {
    /// Trellis anchor reference.
    pub anchor: TrellisAnchorRef,
}

/// Trellis witness anchor reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrellisAnchorRef {
    /// Event hash.
    #[serde(rename = "eventHash")]
    pub event_hash: String,
    /// Ledger scope.
    #[serde(rename = "ledgerScope")]
    pub ledger_scope: String,
}

/// Typed key reference passed to a verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum KeyRef {
    /// COSE `kid` bytes resolved through the configured key resolver.
    Kid(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Raw public-key bytes supplied directly by the caller.
    RawPublicKey(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// Resolves a key reference to raw public-key bytes.
pub trait KeyResolver: Send + Sync + 'static {
    /// Returns raw public-key bytes for `key_ref`.
    ///
    /// # Errors
    /// Returns [`KeyResolverError`] when the key reference cannot resolve.
    fn resolve(&self, key_ref: &KeyRef) -> Result<Vec<u8>, KeyResolverError>;

    /// Returns a stable resolver identifier.
    fn resolver_id(&self) -> &str;
}

/// Shared key-resolver handle.
pub type KeyResolverHandle = Arc<dyn KeyResolver>;

/// Key-resolution failure.
#[derive(Debug, Error)]
pub enum KeyResolverError {
    /// Key material was not found for a COSE `kid`.
    #[error("key not found for kid: {} bytes", kid.len())]
    KeyNotFound {
        /// Missing `kid` bytes.
        kid: Vec<u8>,
    },
    /// The resolver does not support this key-reference variant.
    #[error("unsupported key reference: {0}")]
    UnsupportedKeyRef(String),
    /// Resolver-internal failure.
    #[error("key resolver internal error: {0}")]
    Internal(String),
}

/// HashMap-backed key resolver.
pub struct StaticKeyResolver {
    keys: HashMap<Vec<u8>, Vec<u8>>,
    resolver_id: String,
}

impl StaticKeyResolver {
    const DEFAULT_ID: &'static str = "urn:integrity:key-resolver:static@1";

    /// Builds an empty resolver.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(HashMap::new())
    }

    /// Builds a resolver from `kid` to public-key bytes.
    #[must_use]
    pub fn new(keys: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            keys,
            resolver_id: Self::DEFAULT_ID.to_string(),
        }
    }

    /// Inserts a key binding.
    pub fn insert(&mut self, kid: Vec<u8>, public_key: Vec<u8>) -> Option<Vec<u8>> {
        self.keys.insert(kid, public_key)
    }
}

impl Default for StaticKeyResolver {
    fn default() -> Self {
        Self::empty()
    }
}

impl KeyResolver for StaticKeyResolver {
    fn resolve(&self, key_ref: &KeyRef) -> Result<Vec<u8>, KeyResolverError> {
        match key_ref {
            KeyRef::Kid(kid) => self
                .keys
                .get(kid)
                .cloned()
                .ok_or_else(|| KeyResolverError::KeyNotFound { kid: kid.clone() }),
            KeyRef::RawPublicKey(_) => Err(KeyResolverError::UnsupportedKeyRef(
                "RawPublicKey bypasses resolution; adapters must short-circuit".to_string(),
            )),
        }
    }

    fn resolver_id(&self) -> &str {
        &self.resolver_id
    }
}

/// Method registry used by signature adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodRegistry {
    /// Registry version.
    pub version: SemVer,
    /// Registered method entries.
    pub entries: Vec<MethodRegistryEntry>,
}

/// One method registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodRegistryEntry {
    /// Method URI.
    pub id: Uri,
    /// Signature suite name.
    pub suite: String,
    /// Wire format.
    pub wire: String,
    /// COSE algorithm label, when applicable.
    pub alg: Option<i32>,
    /// Entry status.
    pub status: String,
    /// Optional deprecation notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecation_notice: Option<String>,
}

/// Compatibility alias for signature-method registry consumers.
pub type SignatureMethodRegistry = MethodRegistry;

/// Compatibility alias for signature-method registry entries.
pub type RegistryEntry = MethodRegistryEntry;

impl MethodRegistry {
    /// Resolves a method URI to a registry entry.
    #[must_use]
    pub fn resolve(&self, method: &str) -> Option<&MethodRegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.id.as_str() == method)
    }

    /// Returns the registry version.
    #[must_use]
    pub fn current_version(&self) -> &str {
        self.version.as_str()
    }
}

/// Request passed to a signature verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    /// Domain payload bytes that were signed.
    pub signed_bytes: Vec<u8>,
    /// Signature envelope bytes.
    pub signature_bytes: Vec<u8>,
    /// Signature method URI expected by the consumer.
    pub method_uri: Uri,
    /// Key reference selected by the caller.
    pub key_ref: KeyRef,
}

/// Adapter-internal error surface for verifier implementations.
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Method is not supported by the configured registry or adapter.
    #[error("unsupported method: {method}")]
    MethodUnsupported {
        /// Unsupported method URI.
        method: Uri,
    },
    /// Signature verification reached the primitive and failed.
    #[error("verification failed: {reason}")]
    VerificationFailed {
        /// Failure reason.
        reason: String,
    },
    /// COSE or other envelope bytes were malformed.
    #[error("invalid COSE: {reason}")]
    InvalidCoseEncoding {
        /// Encoding failure reason.
        reason: String,
    },
    /// Internal verifier failure.
    #[error("internal error: {reason}")]
    Internal {
        /// Internal failure reason.
        reason: String,
    },
}

/// Verifies a signature against a method registry.
pub trait Verifier {
    /// Verifies the request and returns a reached receipt.
    ///
    /// # Errors
    /// Returns [`VerifierError`] when the adapter cannot reach a verdict.
    fn verify(
        &self,
        request: &VerifyRequest,
        registry: &MethodRegistry,
    ) -> Result<VerificationReceipt, VerifierError>;
}

/// Receipt-signing failure.
#[derive(Debug, Error)]
pub enum ReceiptSignerError {
    /// The signing primitive rejected the payload.
    #[error("receipt signing failed: {reason}")]
    SigningFailed {
        /// Failure reason.
        reason: String,
    },
    /// Signing key material was unavailable.
    #[error("signing key unavailable: {reason}")]
    KeyUnavailable {
        /// Failure reason.
        reason: String,
    },
    /// Adapter-internal failure.
    #[error("internal error: {reason}")]
    Internal {
        /// Failure reason.
        reason: String,
    },
}

/// Signs canonical receipt-payload bytes.
pub trait ReceiptSigner: Send + Sync + 'static {
    /// Signs canonical receipt-payload bytes.
    ///
    /// # Errors
    /// Returns [`ReceiptSignerError`] when signing cannot produce bytes.
    fn sign_receipt(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, ReceiptSignerError>;

    /// Returns a stable signer identifier.
    fn signer_id(&self) -> &str;
}

/// Shared receipt-signer handle.
pub type ReceiptSignerHandle = Arc<dyn ReceiptSigner>;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_receipt() -> VerificationReceipt {
        VerificationReceipt {
            result: VerificationResult::Verified,
            method: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
            method_registry_version: "1.0.0".into(),
            adapter: AdapterInfo {
                id: "urn:formspec:adapter:webcrypto@1".into(),
                version: "1.0.0".into(),
            },
            key: KeyInfo {
                r#ref: "did:key:z6MkhaXgB...".into(),
                version: Some("1".to_string()),
                snapshot: None,
            },
            verified_at: "2026-05-08T15:45:00Z".to_string(),
            context: Some(VerificationContext {
                revocation: Some(RevocationContext {
                    kind: "ocsp".to_string(),
                    response_hash: "aGVsbG8=".to_string(),
                }),
                timestamping: Some(TimestampingContext {
                    authority: "https://timestamp.example.gov".into(),
                    receipt_hash: "d29ybGQ=".to_string(),
                }),
                witness: Some(WitnessContext {
                    anchor: TrellisAnchorRef {
                        event_hash: "Zm9vYmFy".to_string(),
                        ledger_scope: "urn:trellis:scope:default".to_string(),
                    },
                }),
            }),
            receipt_bytes: Some("0oRWoQExiQEFQnNpZ25lZA==".to_string()),
        }
    }

    #[test]
    fn verification_receipt_json_roundtrips() {
        let json = serde_json::to_string(&sample_receipt()).expect("serialize");
        let roundtripped: VerificationReceipt = serde_json::from_str(&json).expect("deserialize");
        let json2 = serde_json::to_string(&roundtripped).expect("re-serialize");
        assert_eq!(json, json2);
    }

    #[test]
    fn verify_request_serializes_method_uri_not_signature_method() {
        let request = VerifyRequest {
            signed_bytes: vec![1, 2, 3],
            signature_bytes: vec![4, 5, 6],
            method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
            key_ref: KeyRef::Kid(b"kid-1".to_vec()),
        };

        let json = serde_json::to_value(&request).expect("serialize");
        assert_eq!(
            json.get("methodUri").and_then(serde_json::Value::as_str),
            Some("urn:formspec:sig-method:ed25519-cose-sign1@1")
        );
        assert!(
            json.get("signatureMethod").is_none(),
            "ADR 0109 removed the retired JSON signatureMethod mirror"
        );
    }

    #[test]
    fn verification_result_display_is_stable() {
        assert_eq!(VerificationResult::Verified.to_string(), "verified");
        assert_eq!(VerificationResult::Failed.to_string(), "failed");
        assert_eq!(VerificationResult::Unsupported.to_string(), "unsupported");
    }

    #[test]
    fn verification_receipt_helpers_match_variants() {
        let mut receipt = sample_receipt();
        assert!(receipt.is_verified());
        receipt.result = VerificationResult::Failed;
        assert!(receipt.is_failed());
        assert!(!receipt.is_verified());
        receipt.result = VerificationResult::Unsupported;
        assert!(receipt.is_unsupported());
        assert!(!receipt.is_failed());
    }

    #[test]
    fn method_registry_resolves_known_method() {
        let registry = MethodRegistry {
            version: "1.0.0".into(),
            entries: vec![MethodRegistryEntry {
                id: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                suite: "ed25519".to_string(),
                wire: "cose-sign1".to_string(),
                alg: Some(-8),
                status: "active".to_string(),
                deprecation_notice: None,
            }],
        };
        let resolved = registry.resolve("urn:formspec:sig-method:ed25519-cose-sign1@1");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().suite, "ed25519");
        assert_eq!(registry.current_version(), "1.0.0");
    }

    #[test]
    fn method_registry_rejects_unknown_method() {
        let registry = MethodRegistry {
            version: "1.0.0".into(),
            entries: vec![MethodRegistryEntry {
                id: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                suite: "ed25519".to_string(),
                wire: "cose-sign1".to_string(),
                alg: Some(-8),
                status: "active".to_string(),
                deprecation_notice: None,
            }],
        };
        assert!(registry.resolve("urn:nonexistent").is_none());
    }

    #[test]
    fn errors_implement_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&VerifierError::Internal {
            reason: "adapter crashed".to_string(),
        });
        assert_error(&ReceiptSignerError::KeyUnavailable {
            reason: "no key bound".to_string(),
        });
        assert_error(&KeyResolverError::KeyNotFound { kid: b"k".to_vec() });
    }

    #[test]
    fn static_key_resolver_empty_returns_key_not_found_for_kid() {
        let resolver = StaticKeyResolver::empty();
        let result = resolver.resolve(&KeyRef::Kid(b"absent".to_vec()));
        match result {
            Err(KeyResolverError::KeyNotFound { kid }) => assert_eq!(kid, b"absent"),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn static_key_resolver_returns_registered_bytes_for_known_kid() {
        let mut resolver = StaticKeyResolver::empty();
        resolver.insert(b"kid-A".to_vec(), vec![1, 2, 3, 4]);
        let bytes = resolver
            .resolve(&KeyRef::Kid(b"kid-A".to_vec()))
            .expect("resolve");
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn static_key_resolver_rejects_raw_public_key_variant() {
        let resolver = StaticKeyResolver::empty();
        let result = resolver.resolve(&KeyRef::RawPublicKey(vec![0u8; 32]));
        assert!(
            matches!(result, Err(KeyResolverError::UnsupportedKeyRef(_))),
            "RawPublicKey must short-circuit before reaching a resolver"
        );
    }

    #[test]
    fn receipt_signer_handle_is_send_sync_clone() {
        fn assert_send_sync_clone<T: Send + Sync + Clone>(_: &T) {}

        struct NoopSigner;
        impl ReceiptSigner for NoopSigner {
            fn sign_receipt(&self, _: &[u8]) -> Result<Vec<u8>, ReceiptSignerError> {
                Ok(vec![])
            }
            fn signer_id(&self) -> &str {
                "urn:integrity:receipt-signer:noop@1"
            }
        }

        let handle: ReceiptSignerHandle = Arc::new(NoopSigner);
        assert_send_sync_clone(&handle);
        assert_eq!(handle.signer_id(), "urn:integrity:receipt-signer:noop@1");
        assert_eq!(handle.sign_receipt(b"payload").unwrap(), Vec::<u8>::new());
    }

    proptest! {
        #[test]
        fn unknown_method_exact_values_do_not_resolve(
            suffix in "[a-z0-9][a-z0-9._@-]{0,48}"
        ) {
            let known = "urn:formspec:sig-method:ed25519-cose-sign1@1";
            let candidate = format!("urn:formspec:sig-method:unknown-{suffix}");
            prop_assume!(candidate != known);
            let registry = MethodRegistry {
                version: "1.0.0".into(),
                entries: vec![MethodRegistryEntry {
                    id: known.into(),
                    suite: "Ed25519".into(),
                    wire: "COSE_Sign1 with alg = -8".into(),
                    alg: Some(-8),
                    status: "registered".into(),
                    deprecation_notice: None,
                }],
            };

            prop_assert!(
                registry.resolve(&candidate).is_none(),
                "unregistered value in a method prefix must not resolve"
            );
        }
    }
}

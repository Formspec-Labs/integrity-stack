#![forbid(unsafe_code)]

use integrity_signature::{
    AdapterInfo, ClockHandle, KeyInfo, KeyRef, KeyResolverError, KeyResolverHandle, ReceiptSigner,
    ReceiptSignerError, ReceiptSignerHandle, SignatureMethodRegistry, StaticKeyResolver,
    SystemClock, VerificationReceipt, VerificationResult, Verifier, VerifierError, VerifyRequest,
    utc_to_rfc3339_seconds,
};
pub use integrity_signature::{
    RECEIPT_SIGNED_PAYLOAD_DOMAIN, canonical_receipt_payload_bytes,
    canonical_receipt_payload_bytes_with_domain,
};
/// The `ring` whose `Ed25519KeyPair` this crate's signer API accepts.
///
/// Callers that build key pairs name `ring` through this re-export instead of
/// pinning their own, so the two versions cannot drift apart.
pub use ring;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::KeyPair;
use std::sync::Arc;

pub const DEFAULT_ADAPTER_ID: &str = "urn:integrity-stack:adapter:ring@1";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const DEFAULT_SIGNATURE_METHOD_URI_PREFIX: &str = "urn:integrity-stack:sig-method:";
pub const DEFAULT_RECEIPT_METHOD_URI: &str =
    "urn:integrity-stack:receipt-method:ed25519-cose-sign1@1";
pub const DEFAULT_RECEIPT_METHOD_URI_PREFIX: &str = "urn:integrity-stack:receipt-method:";
pub const DEFAULT_IN_PROCESS_RECEIPT_SIGNER_ID: &str =
    "urn:integrity-stack:receipt-signer:ring-in-process@1";

#[derive(Debug, Clone)]
pub struct RingVerifierConfig {
    pub adapter_id: String,
    pub adapter_version: String,
    pub method_uri_prefix: String,
    pub receipt_payload_domain: String,
}

impl RingVerifierConfig {
    #[must_use]
    pub fn new(method_uri_prefix: impl Into<String>) -> Self {
        Self {
            adapter_id: DEFAULT_ADAPTER_ID.to_string(),
            adapter_version: ADAPTER_VERSION.to_string(),
            method_uri_prefix: method_uri_prefix.into(),
            receipt_payload_domain: RECEIPT_SIGNED_PAYLOAD_DOMAIN.to_string(),
        }
    }

    #[must_use]
    pub fn with_adapter_id(mut self, adapter_id: impl Into<String>) -> Self {
        self.adapter_id = adapter_id.into();
        self
    }

    #[must_use]
    pub fn with_adapter_version(mut self, adapter_version: impl Into<String>) -> Self {
        self.adapter_version = adapter_version.into();
        self
    }

    #[must_use]
    pub fn with_receipt_payload_domain(mut self, domain: impl Into<String>) -> Self {
        self.receipt_payload_domain = domain.into();
        self
    }
}

pub struct RingVerifier {
    adapter_info: AdapterInfo,
    method_uri_prefix: String,
    receipt_payload_domain: String,
    clock: ClockHandle,
    key_resolver: KeyResolverHandle,
    receipt_signer: Option<ReceiptSignerHandle>,
}

/// Renders a [`KeyRef`] for the receipt's `key.ref` field — a human-readable
/// identifier the audit consumer can correlate against logs. Kid bytes are
/// base64-encoded so they survive JSON serialization; raw public keys (which
/// can be tens to thousands of bytes long) get a stable summary marker
/// instead of being inlined into the receipt's identifier slot.
fn key_ref_display(key_ref: &KeyRef) -> String {
    use base64::Engine;
    match key_ref {
        KeyRef::Kid(bytes) => base64::engine::general_purpose::STANDARD.encode(bytes),
        KeyRef::RawPublicKey(bytes) => {
            format!(
                "raw:{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )
        }
    }
}

/// Per-algorithm public-key length validation. Rejects malformed/wrong-size
/// inputs before they reach ring's verify routines so the adapter never
/// asks a primitive to interpret bytes of the wrong shape. Closes the
/// per-algorithm-length-validation gap from fs-0gzb.
fn validate_key_length_for_alg(alg: i64, key_bytes: &[u8]) -> Result<(), String> {
    match alg {
        // Ed25519: 32 bytes raw.
        -8 => {
            if key_bytes.len() != 32 {
                return Err(format!(
                    "ed25519 key must be 32 bytes; got {}",
                    key_bytes.len()
                ));
            }
        }
        // ECDSA-P256 (ES256): the ring adapter's wire format is the
        // SEC1 uncompressed point — 65 bytes leading with 0x04. Some
        // future fixtures may pass the raw 64-byte (X || Y) form; the
        // ring `UnparsedPublicKey` rejects that, so we keep parity by
        // also rejecting it here with a more specific message.
        -7 => {
            if key_bytes.len() != 65 || key_bytes[0] != 0x04 {
                return Err(format!(
                    "ecdsa-p256 key must be SEC1 uncompressed (65 bytes, 0x04-prefixed); got {} bytes",
                    key_bytes.len()
                ));
            }
        }
        // RSA-PSS-SHA256: PKCS#1 RSAPublicKey (SEQUENCE { n, e }). Variable
        // length but bounded — modulus 2048..8192 bits plus framing. Reject
        // implausibly small inputs early; the deeper structural check
        // happens inside ring's parser. Anything < 100 bytes cannot encode
        // even a 2048-bit RSA public key with framing.
        -37 => {
            if key_bytes.len() < 100 {
                return Err(format!(
                    "rsa-pss key too short to encode RSAPublicKey; got {} bytes",
                    key_bytes.len()
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

impl RingVerifier {
    /// Builds a verification-only `RingVerifier`. Receipts produced by this
    /// constructor have `receipt_bytes = None` — they record a verdict but
    /// carry no audit-binding signature. Use
    /// [`Self::new_with_receipt_signer`] for receipts that downstream
    /// systems treat as evidence.
    ///
    /// The key resolver defaults to an empty [`StaticKeyResolver`] — any
    /// [`KeyRef::Kid`] request returns [`KeyResolverError::KeyNotFound`].
    /// Use [`Self::new_with_key_resolver`] when verifying via kids resolved
    /// from an external key bag.
    pub fn new() -> Self {
        Self::new_with_config(RingVerifierConfig::new(DEFAULT_SIGNATURE_METHOD_URI_PREFIX))
    }

    #[must_use]
    pub fn new_for_method_prefix(method_uri_prefix: impl Into<String>) -> Self {
        Self::new_with_config(RingVerifierConfig::new(method_uri_prefix))
    }

    #[must_use]
    pub fn new_with_config(config: RingVerifierConfig) -> Self {
        Self::new_with_clock_and_config(Arc::new(SystemClock), config)
    }

    pub fn new_with_clock(clock: ClockHandle) -> Self {
        Self::new_with_clock_and_config(
            clock,
            RingVerifierConfig::new(DEFAULT_SIGNATURE_METHOD_URI_PREFIX),
        )
    }

    pub fn new_with_clock_and_config(clock: ClockHandle, config: RingVerifierConfig) -> Self {
        Self::new_with_clock_config_and_key_resolver(
            clock,
            config,
            Arc::new(StaticKeyResolver::empty()),
        )
    }

    /// Builds a `RingVerifier` wired to the supplied [`KeyResolver`].
    ///
    /// `KeyRef::Kid` requests route through the resolver; `KeyRef::RawPublicKey`
    /// bypasses it. After the resolver returns key bytes, the verifier
    /// asserts `cose.kid` (from the COSE_Sign1 protected header) matches the
    /// `Kid` bytes from the request — closes the kid-swap vector from
    /// fs-skj0.
    pub fn new_with_key_resolver(resolver: KeyResolverHandle) -> Self {
        Self::new_with_config_and_key_resolver(
            RingVerifierConfig::new(DEFAULT_SIGNATURE_METHOD_URI_PREFIX),
            resolver,
        )
    }

    pub fn new_with_config_and_key_resolver(
        config: RingVerifierConfig,
        resolver: KeyResolverHandle,
    ) -> Self {
        Self::new_with_clock_config_and_key_resolver(Arc::new(SystemClock), config, resolver)
    }

    /// Builds a verifier with the supplied clock, configuration, and key resolver.
    ///
    /// Receipts use `clock` for their verification time. Key identifier requests
    /// use `resolver`; raw public keys bypass it. Method and receipt policies
    /// come from `config`, and receipts remain unsigned.
    #[must_use]
    pub fn new_with_clock_config_and_key_resolver(
        clock: ClockHandle,
        config: RingVerifierConfig,
        resolver: KeyResolverHandle,
    ) -> Self {
        Self {
            adapter_info: AdapterInfo {
                id: config.adapter_id.into(),
                version: config.adapter_version.into(),
            },
            method_uri_prefix: config.method_uri_prefix,
            receipt_payload_domain: config.receipt_payload_domain,
            clock,
            key_resolver: resolver,
            receipt_signer: None,
        }
    }

    /// Builds a `RingVerifier` that signs every reached-verdict receipt
    /// via the supplied [`ReceiptSigner`]. The returned
    /// [`VerificationReceipt::receipt_bytes`] is the base64-encoded
    /// COSE_Sign1 envelope binding the signer's key to the canonical
    /// receipt payload (see [`canonical_receipt_payload_bytes`]).
    ///
    /// Signer failures bubble up as
    /// [`VerifierError::Internal`] — `verify` does NOT degrade to an
    /// unsigned receipt when signing fails, because that would silently
    /// produce an unauditable receipt while the caller believes they
    /// configured signing. fs-migs.
    pub fn new_with_receipt_signer(signer: ReceiptSignerHandle) -> Self {
        Self::new_with_clock_and_receipt_signer(Arc::new(SystemClock), signer)
    }

    pub fn new_with_config_and_receipt_signer(
        config: RingVerifierConfig,
        signer: ReceiptSignerHandle,
    ) -> Self {
        Self::new_with_clock_config_and_receipt_signer(Arc::new(SystemClock), config, signer)
    }

    pub fn new_with_clock_and_receipt_signer(
        clock: ClockHandle,
        signer: ReceiptSignerHandle,
    ) -> Self {
        Self::new_with_clock_config_and_receipt_signer(
            clock,
            RingVerifierConfig::new(DEFAULT_SIGNATURE_METHOD_URI_PREFIX),
            signer,
        )
    }

    pub fn new_with_clock_config_and_receipt_signer(
        clock: ClockHandle,
        config: RingVerifierConfig,
        signer: ReceiptSignerHandle,
    ) -> Self {
        Self {
            adapter_info: AdapterInfo {
                id: config.adapter_id.into(),
                version: config.adapter_version.into(),
            },
            method_uri_prefix: config.method_uri_prefix,
            receipt_payload_domain: config.receipt_payload_domain,
            clock,
            key_resolver: Arc::new(StaticKeyResolver::empty()),
            receipt_signer: Some(signer),
        }
    }

    /// Signs `receipt` in place when a [`ReceiptSigner`] is configured.
    ///
    /// On signer success, `receipt.receipt_bytes` is set to the
    /// base64-encoded COSE_Sign1 envelope. On signer failure the verifier
    /// returns `VerifierError::Internal` rather than emitting an unsigned
    /// receipt — see [`Self::new_with_receipt_signer`] for rationale.
    fn attach_signed_receipt_bytes(
        &self,
        receipt: &mut VerificationReceipt,
    ) -> Result<(), VerifierError> {
        let Some(signer) = self.receipt_signer.as_ref() else {
            return Ok(());
        };
        let canonical =
            canonical_receipt_payload_bytes_with_domain(receipt, &self.receipt_payload_domain)
                .map_err(|reason| VerifierError::Internal {
                    reason: format!("canonical receipt payload: {reason}"),
                })?;
        let envelope =
            signer
                .sign_receipt(&canonical)
                .map_err(|error| VerifierError::Internal {
                    reason: format!("receipt signer rejected payload: {error}"),
                })?;
        receipt.receipt_bytes = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            envelope,
        ));
        Ok(())
    }

    fn build_receipt(
        &self,
        result: VerificationResult,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> VerificationReceipt {
        VerificationReceipt {
            result,
            method: request.method_uri.clone(),
            method_registry_version: registry.version.clone(),
            adapter: self.adapter_info.clone(),
            key: KeyInfo {
                r#ref: key_ref_display(&request.key_ref).into(),
                version: None,
                snapshot: None,
            },
            verified_at: utc_to_rfc3339_seconds(self.clock.now_utc()),
            context: None,
            receipt_bytes: None,
        }
    }

    fn verify_ed25519(
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        key_bytes: &[u8],
    ) -> Result<(), String> {
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, key_bytes);
        public_key
            .verify(signed_bytes, signature_bytes)
            .map_err(|e| format!("ed25519 verification failed: {e}"))
    }

    fn verify_ecdsa_p256(
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        key_bytes: &[u8],
    ) -> Result<(), String> {
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key_bytes);
        public_key
            .verify(signed_bytes, signature_bytes)
            .map_err(|e| format!("ecdsa-p256 verification failed: {e}"))
    }

    fn verify_rsa_pss(
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        key_bytes: &[u8],
    ) -> Result<(), String> {
        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, key_bytes);
        public_key
            .verify(signed_bytes, signature_bytes)
            .map_err(|e| format!("rsa-pss verification failed: {e}"))
    }
}

impl Default for RingVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier for RingVerifier {
    fn verify(
        &self,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> Result<VerificationReceipt, VerifierError> {
        let mut receipt = self.compute_receipt(request, registry)?;
        self.attach_signed_receipt_bytes(&mut receipt)?;
        Ok(receipt)
    }
}

impl RingVerifier {
    fn compute_receipt(
        &self,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> Result<VerificationReceipt, VerifierError> {
        let entry = registry.resolve(&request.method_uri);
        let entry = match entry {
            Some(e) => {
                // Allowlist: only the literal "registered" lifecycle status
                // continues to verification. Anything else — "deprecated",
                // "withdrawn", "revoked", typos ("depricated", "DEPRECATED",
                // "deprecated "), unknown future variants, or forged registry
                // strings — returns an unsupported receipt. This is a
                // security-critical gate; blacklisting a single keyword
                // silently activates any string that isn't the keyword
                // (PR-SWEEP-001 / fs-lwsi will fold this into an enum match).
                if e.status != "registered" {
                    return Ok(self.build_receipt(
                        VerificationResult::Unsupported,
                        request,
                        registry,
                    ));
                }
                e
            }
            None => {
                return Ok(self.build_receipt(VerificationResult::Unsupported, request, registry));
            }
        };

        // Resolve key material from the typed KeyRef. Two branches:
        //   - Kid(bytes): resolve through the configured KeyResolver, preserving
        //     missing-key, unsupported-reference, and internal failure types.
        //     Resolution errors prevent a verdict rather than fabricating Failed.
        //   - RawPublicKey(bytes): caller has already committed to the key;
        //     skip resolution and skip the kid-binding check (no identifier
        //     to bind).
        let key_bytes = match &request.key_ref {
            KeyRef::Kid(_) => self
                .key_resolver
                .resolve(&request.key_ref)
                .map_err(|error| match error {
                    KeyResolverError::KeyNotFound { kid } => VerifierError::KeyResolution {
                        reason: format!("key resolver: kid not found ({} bytes)", kid.len()),
                    },
                    KeyResolverError::UnsupportedKeyRef(reason) => {
                        VerifierError::UnsupportedKeyRef { reason }
                    }
                    KeyResolverError::Internal(reason) => VerifierError::Internal {
                        reason: format!("key resolver: {reason}"),
                    },
                })?,
            KeyRef::RawPublicKey(bytes) => bytes.clone(),
        };

        let (alg, verify) = match entry.alg {
            Some(-8) => (
                -8,
                Self::verify_ed25519 as fn(&[u8], &[u8], &[u8]) -> Result<(), String>,
            ),
            Some(-7) => (
                -7,
                Self::verify_ecdsa_p256 as fn(&[u8], &[u8], &[u8]) -> Result<(), String>,
            ),
            Some(-37) => (
                -37,
                Self::verify_rsa_pss as fn(&[u8], &[u8], &[u8]) -> Result<(), String>,
            ),
            None | Some(_) => {
                return Ok(self.build_receipt(VerificationResult::Unsupported, request, registry));
            }
        };
        // Reject malformed key lengths before calling ring's verification primitive.
        if validate_key_length_for_alg(alg, &key_bytes).is_err() {
            return Ok(self.build_receipt(VerificationResult::Unsupported, request, registry));
        }
        let (cose, method_uri) = integrity_cose::decode_cose_sign1_with_method_uri(
            &request.signature_bytes,
            &self.method_uri_prefix,
        )
        .map_err(|error| VerifierError::InvalidCoseEncoding {
            reason: error.to_string(),
        })?;
        if method_uri != request.method_uri.as_str() || cose.alg() != Some(alg) {
            return Ok(self.build_receipt(VerificationResult::Unsupported, request, registry));
        }
        // RawPublicKey has no identifier to bind; Kid must match the COSE header.
        if let KeyRef::Kid(expected_kid) = &request.key_ref {
            if cose.kid() != Some(expected_kid.as_slice()) {
                return Ok(self.build_receipt(VerificationResult::Unsupported, request, registry));
            }
        }
        let payload = cose
            .resolve_payload(Some(&request.signed_bytes))
            .map_err(|error| VerifierError::InvalidCoseEncoding {
                reason: error.to_string(),
            })?;
        let sig_structure = integrity_cose::sig_structure_bytes(cose.protected_header(), payload);
        let result = match verify(&sig_structure, cose.signature(), &key_bytes) {
            Ok(()) => VerificationResult::Verified,
            Err(_) => VerificationResult::Failed,
        };
        Ok(self.build_receipt(result, request, registry))
    }
}

/// Ed25519 key pair held in process memory, parsed from PKCS#8.
///
/// Signs the detached COSE_Sign1 consumer envelope (`alg`, `kid`, method URI;
/// ADR 0109) that [`RingVerifier`] checks, so callers outside this crate sign
/// without depending on ring. The same custody caveat as
/// [`InProcessReceiptSigner`] applies: tests, conformance fixtures and local
/// reference servers only.
pub struct InProcessEd25519Key {
    key_pair: signature::Ed25519KeyPair,
}

impl InProcessEd25519Key {
    /// Parses an unencrypted Ed25519 PKCS#8 v2 document.
    ///
    /// ring requires the v2 form, which carries the public key, and checks that
    /// it matches the private seed.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptSignerError::KeyUnavailable`] when ring rejects the
    /// bytes as an Ed25519 PKCS#8 v2 document.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, ReceiptSignerError> {
        signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map(|key_pair| Self { key_pair })
            .map_err(|e| ReceiptSignerError::KeyUnavailable {
                reason: format!("ed25519 pkcs8 parse: {e}"),
            })
    }

    /// Returns the raw 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Signs `payload` as a detached COSE_Sign1 under `kid` and `method_uri`.
    ///
    /// The envelope carries no payload; verifiers rebuild the `Sig_structure`
    /// from the bytes they hold. Ed25519 is deterministic, so the same inputs
    /// always yield the same envelope.
    pub fn sign_detached_cose_sign1(
        &self,
        kid: &[u8],
        method_uri: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        let protected = integrity_cose::detached_signature_protected_header(
            integrity_cose::COSE_ALG_EDDSA,
            kid,
            method_uri,
        );
        let signature = self
            .key_pair
            .sign(&integrity_cose::sig_structure_bytes(&protected, payload));
        integrity_cose::encode_cose_sign1(&protected, None, signature.as_ref())
    }
}

impl std::fmt::Debug for InProcessEd25519Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessEd25519Key")
            .field("public_key", &self.public_key_bytes())
            .finish()
    }
}

/// Minimal in-process [`ReceiptSigner`] backed by ring's Ed25519 keypair.
///
/// Holds the private key in process memory. Suitable for tests, local
/// reference servers, and embedded use cases where Trellis-managed signing
/// (integrity-signature-ring KMS signer) is not yet wired. Production
/// systems that need HSM-grade key custody or rotation MUST swap in a
/// signer backed by their key-management service — the
/// [`ReceiptSigner`] port keeps that substitution local to the
/// composition root.
pub struct InProcessReceiptSigner {
    key: InProcessEd25519Key,
    /// Optional COSE `kid` bytes. `None` (absent kid) is wire-distinct from
    /// `Some(vec![])` (present-but-empty kid); previously the field used
    /// `Vec::is_empty()` as the absence sentinel which collapsed those two
    /// cases — a foot-gun for any caller passing `Some(&[])`.
    kid: Option<Vec<u8>>,
    signer_id: String,
    receipt_method_uri: String,
}

impl InProcessReceiptSigner {
    /// Wraps an Ed25519 keypair with an optional COSE `kid` for receipt
    /// signing. When `kid` is `None` the COSE protected header omits the
    /// label — independent verifiers must locate the public key by other
    /// means (e.g. the receipt's `key.ref` field).
    pub fn new(key_pair: signature::Ed25519KeyPair, kid: Option<&[u8]>) -> Self {
        Self::new_with_identity(
            key_pair,
            kid,
            DEFAULT_IN_PROCESS_RECEIPT_SIGNER_ID,
            DEFAULT_RECEIPT_METHOD_URI,
        )
    }

    pub fn new_with_identity(
        key_pair: signature::Ed25519KeyPair,
        kid: Option<&[u8]>,
        signer_id: impl Into<String>,
        receipt_method_uri: impl Into<String>,
    ) -> Self {
        Self::from_key_with_identity(
            InProcessEd25519Key { key_pair },
            kid,
            signer_id,
            receipt_method_uri,
        )
    }

    /// Wraps a parsed in-process key as a receipt signer with an explicit identity.
    ///
    /// Callers holding PKCS#8 key material use this instead of
    /// [`Self::new_with_identity`], so they need no ring dependency of their own.
    pub fn from_key_with_identity(
        key: InProcessEd25519Key,
        kid: Option<&[u8]>,
        signer_id: impl Into<String>,
        receipt_method_uri: impl Into<String>,
    ) -> Self {
        Self {
            key,
            kid: kid.map(<[u8]>::to_vec),
            signer_id: signer_id.into(),
            receipt_method_uri: receipt_method_uri.into(),
        }
    }

    /// Generates a fresh Ed25519 keypair via the system RNG and wraps it
    /// as an in-process signer. Returns the signer alongside the raw
    /// public-key bytes so callers can publish the verification key.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptSignerError::Internal`] if the underlying RNG or
    /// PKCS#8 parser fails — both indicate a system-level fault, not a
    /// caller bug.
    pub fn generate(kid: Option<&[u8]>) -> Result<(Self, Vec<u8>), ReceiptSignerError> {
        Self::generate_with_identity(
            kid,
            DEFAULT_IN_PROCESS_RECEIPT_SIGNER_ID,
            DEFAULT_RECEIPT_METHOD_URI,
        )
    }

    pub fn generate_with_identity(
        kid: Option<&[u8]>,
        signer_id: impl Into<String>,
        receipt_method_uri: impl Into<String>,
    ) -> Result<(Self, Vec<u8>), ReceiptSignerError> {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| {
            ReceiptSignerError::Internal {
                reason: format!("ed25519 keygen: {e}"),
            }
        })?;
        let key = InProcessEd25519Key::from_pkcs8(pkcs8.as_ref())?;
        let public_key_bytes = key.public_key_bytes().to_vec();
        Ok((
            Self::from_key_with_identity(key, kid, signer_id, receipt_method_uri),
            public_key_bytes,
        ))
    }

    /// Returns the raw Ed25519 public-key bytes for the embedded keypair.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key.public_key_bytes()
    }
}

impl ReceiptSigner for InProcessReceiptSigner {
    fn sign_receipt(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, ReceiptSignerError> {
        let kid_slice = self
            .kid
            .as_deref()
            .ok_or_else(|| ReceiptSignerError::KeyUnavailable {
                reason: "receipt-signing requires a kid per ADR 0109 consumer envelope shape"
                    .to_string(),
            })?;
        Ok(self.key.sign_detached_cose_sign1(
            kid_slice,
            &self.receipt_method_uri,
            canonical_payload,
        ))
    }

    fn signer_id(&self) -> &str {
        &self.signer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use integrity_signature::{FixedClock, KeyResolver, RegistryEntry};
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    const TEST_SIG_METHOD_PREFIX: &str = "urn:formspec:sig-method:";

    fn test_config() -> RingVerifierConfig {
        RingVerifierConfig::new(TEST_SIG_METHOD_PREFIX)
    }

    fn test_verifier() -> RingVerifier {
        RingVerifier::new_with_config(test_config())
    }

    fn test_registry() -> SignatureMethodRegistry {
        SignatureMethodRegistry {
            version: "1.0.0".into(),
            entries: vec![
                RegistryEntry {
                    id: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    suite: "Ed25519".to_string(),
                    wire: "COSE_Sign1 with alg = -8 (EdDSA)".to_string(),
                    alg: Some(-8),
                    status: "registered".to_string(),
                    deprecation_notice: None,
                },
                RegistryEntry {
                    id: "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1".into(),
                    suite: "ECDSA-P256".to_string(),
                    wire: "COSE_Sign1 with alg = -7 (ES256)".to_string(),
                    alg: Some(-7),
                    status: "registered".to_string(),
                    deprecation_notice: None,
                },
                RegistryEntry {
                    id: "urn:formspec:sig-method:rsa-pss-sha256-cose-sign1@1".into(),
                    suite: "RSA-PSS-SHA256".to_string(),
                    wire: "COSE_Sign1 with alg = -37 (PS256)".to_string(),
                    alg: Some(-37),
                    status: "registered".to_string(),
                    deprecation_notice: None,
                },
                RegistryEntry {
                    id: "urn:formspec:sig-method:ml-dsa-65-cose-sign1@1".into(),
                    suite: "ML-DSA-65 (FIPS 204)".to_string(),
                    wire: "COSE_Sign1 with alg = TBD".to_string(),
                    alg: None,
                    status: "registered".to_string(),
                    deprecation_notice: None,
                },
            ],
        }
    }

    /// Zero-bytes filler key for tests that exercise paths that reject
    /// *before* key bytes are consumed (registry lifecycle gate, unknown
    /// method, etc.). 32 bytes so it also satisfies Ed25519's key-length
    /// gate on the few tests that proceed further. Use real key bytes
    /// when the test exercises the verification primitive.
    fn placeholder_raw_public_key() -> KeyRef {
        KeyRef::RawPublicKey(vec![0u8; 32])
    }

    #[test]
    fn test_unsupported_for_unknown_method() {
        let verifier = test_verifier();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: vec![1, 2, 3],
                    signature_bytes: vec![4, 5, 6],
                    method_uri: "urn:formspec:sig-method:unknown@1".into(),
                    key_ref: placeholder_raw_public_key(),
                },
                &registry,
            )
            .unwrap();
        assert_eq!(receipt.result.to_string(), "unsupported");
    }

    /// Builds a registry whose single ed25519 entry carries `status`. Lets
    /// each lifecycle-gate test exercise the allowlist without disturbing
    /// the shared `test_registry()` fixture (everything else points at the
    /// stable "registered" entries).
    fn registry_with_ed25519_status(status: &str) -> SignatureMethodRegistry {
        SignatureMethodRegistry {
            version: "1.0.0".into(),
            entries: vec![RegistryEntry {
                id: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                suite: "Ed25519".to_string(),
                wire: "COSE_Sign1 with alg = -8 (EdDSA)".to_string(),
                alg: Some(-8),
                status: status.to_string(),
                deprecation_notice: None,
            }],
        }
    }

    fn ed25519_verify_request() -> VerifyRequest {
        VerifyRequest {
            signed_bytes: vec![1, 2, 3],
            signature_bytes: vec![4, 5, 6],
            method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
            key_ref: placeholder_raw_public_key(),
        }
    }

    /// Existing behavior: literal "deprecated" returns unsupported.
    #[test]
    fn registry_status_deprecated_returns_unsupported() {
        let verifier = test_verifier();
        let registry = registry_with_ed25519_status("deprecated");
        let receipt = verifier
            .verify(&ed25519_verify_request(), &registry)
            .expect("receipt");
        assert_eq!(receipt.result.to_string(), "unsupported");
    }

    /// Existing behavior: literal "registered" continues to verification.
    /// The vacuous key bytes here make COSE decode fail downstream — but
    /// crucially the lifecycle gate must *not* be the rejection layer.
    /// We assert the receipt is anything other than "unsupported", which
    /// proves the allowlist let us through to the next stage.
    #[test]
    fn registry_status_registered_continues_past_lifecycle_gate() {
        let verifier = test_verifier();
        let registry = registry_with_ed25519_status("registered");
        let outcome = verifier.verify(&ed25519_verify_request(), &registry);
        // Either Err(InvalidCoseEncoding) from the COSE decoder downstream,
        // or Ok(failed) from a downstream signature mismatch — both prove we
        // got past the lifecycle gate. An Ok(unsupported) here would mean
        // the gate rejected a registered status, which is the regression we
        // are guarding against.
        match outcome {
            Ok(receipt) => assert_ne!(
                receipt.result.to_string(),
                "unsupported",
                "registered status must pass the lifecycle gate"
            ),
            Err(VerifierError::InvalidCoseEncoding { .. }) => {
                // Downstream COSE rejection — proves we got past the gate.
            }
            Err(other) => panic!("unexpected error past lifecycle gate: {other}"),
        }
    }

    /// New behavior: a typo previously slipped through the blacklist and
    /// silently activated verification. Allowlist closes that gap.
    #[test]
    fn registry_status_typo_returns_unsupported() {
        let verifier = test_verifier();
        for typo in ["depricated", "DEPRECATED", "deprecated "] {
            let registry = registry_with_ed25519_status(typo);
            let receipt = verifier
                .verify(&ed25519_verify_request(), &registry)
                .expect("receipt");
            assert_eq!(
                receipt.result.to_string(),
                "unsupported",
                "status {typo:?} must not activate verification"
            );
        }
    }

    /// New behavior: future lifecycle states added upstream without adapter
    /// coordination must default to unsupported, not silent activation.
    #[test]
    fn registry_status_unknown_lifecycle_returns_unsupported() {
        let verifier = test_verifier();
        for unknown in ["withdrawn", "revoked", "unknown", "active"] {
            let registry = registry_with_ed25519_status(unknown);
            let receipt = verifier
                .verify(&ed25519_verify_request(), &registry)
                .expect("receipt");
            assert_eq!(
                receipt.result.to_string(),
                "unsupported",
                "status {unknown:?} must not activate verification"
            );
        }
    }

    /// New behavior: empty status is not "registered", must return
    /// unsupported. Under the old blacklist this also silently activated.
    #[test]
    fn registry_status_empty_returns_unsupported() {
        let verifier = test_verifier();
        let registry = registry_with_ed25519_status("");
        let receipt = verifier
            .verify(&ed25519_verify_request(), &registry)
            .expect("receipt");
        assert_eq!(receipt.result.to_string(), "unsupported");
    }

    #[test]
    fn ring_adapter_uses_injected_clock_for_receipt_timestamp() {
        let verifier = RingVerifier::new_with_clock_and_config(
            Arc::new(FixedClock::at_rfc3339("2026-05-13T12:00:00Z").expect("fixed clock")),
            test_config(),
        );
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: vec![1, 2, 3],
                    signature_bytes: vec![4, 5, 6],
                    method_uri: "urn:formspec:sig-method:unknown@1".into(),
                    key_ref: placeholder_raw_public_key(),
                },
                &registry,
            )
            .expect("receipt");

        assert_eq!(receipt.verified_at, "2026-05-13T12:00:00Z");
    }

    #[test]
    fn test_unsupported_for_pqc_null_alg() {
        let verifier = test_verifier();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: vec![1, 2, 3],
                    signature_bytes: vec![4, 5, 6],
                    method_uri: "urn:formspec:sig-method:ml-dsa-65-cose-sign1@1".into(),
                    key_ref: placeholder_raw_public_key(),
                },
                &registry,
            )
            .unwrap();
        assert_eq!(receipt.result.to_string(), "unsupported");
    }

    #[test]
    fn test_adapter_info_in_receipt() {
        // The 65-byte SEC1-shaped placeholder satisfies the ecdsa-p256
        // key-length gate so this test still exercises the COSE-decode /
        // signature-verify path (the prior 8-byte placeholder pre-failed at
        // key-length, which would still hit adapter_info on the unsupported
        // receipt but masks any future regression of the key-length gate).
        let verifier = test_verifier();
        let registry = test_registry();
        let protected = integrity_cose::detached_signature_protected_header(
            -7,
            b"test-kid",
            "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1",
        );
        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, &[0u8; 64]);
        let mut placeholder_p256 = vec![0u8; 65];
        placeholder_p256[0] = 0x04;
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: vec![1, 2, 3],
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(placeholder_p256),
                },
                &registry,
            )
            .unwrap();
        assert_eq!(receipt.adapter.id, "urn:integrity-stack:adapter:ring@1");
        assert_eq!(receipt.adapter.version, "0.1.0");
        assert!(receipt.verified_at.len() > 0);
    }

    #[test]
    fn test_ed25519_invalid_signature_fails() {
        let verifier = test_verifier();
        let registry = test_registry();
        let key_bytes = vec![0u8; 32];
        let protected = integrity_cose::detached_signature_protected_header(
            -8,
            b"test-kid",
            "urn:formspec:sig-method:ed25519-cose-sign1@1",
        );
        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, &[0u8; 64]);
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: b"test message".to_vec(),
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(key_bytes),
                },
                &registry,
            )
            .unwrap();
        assert_eq!(receipt.result.to_string(), "failed");
    }

    #[test]
    fn ring_adapter_rejects_cose_sign1_without_method_uri() {
        let verifier = test_verifier();
        let registry = test_registry();
        // Legacy MAP_1 with alg-only — no method_uri (-65540). Post-ADR-0109
        // verifier rejects envelopes that omit the method URI label.
        let legacy_protected = [0xa1, 0x01, 0x27];
        let signature_bytes =
            integrity_cose::encode_cose_sign1(&legacy_protected, None, &[0u8; 64]);

        let error = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: b"test message".to_vec(),
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(vec![0u8; 32]),
                },
                &registry,
            )
            .expect_err("missing method_uri should reject");

        match error {
            VerifierError::InvalidCoseEncoding { reason } => {
                assert!(
                    reason.contains("method_uri"),
                    "expected method_uri rejection, got: {reason}"
                );
            }
            other => panic!("expected InvalidCoseEncoding error, got: {other}"),
        }
    }

    #[test]
    fn ring_adapter_rejects_within_subspace_method_uri_inequality_before_crypto() {
        let verifier = test_verifier();
        let registry = test_registry();
        let protected = integrity_cose::detached_signature_protected_header(
            -8,
            b"test-kid",
            "urn:formspec:sig-method:ed25519-cose-sign1@99",
        );
        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, &[0u8; 64]);

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: b"test message".to_vec(),
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(vec![0u8; 32]),
                },
                &registry,
            )
            .expect("method_uri mismatch should reach an unsupported verdict");

        assert!(
            receipt.is_unsupported(),
            "method_uri mismatch must reject before invalid signature bytes produce Failed"
        );
    }

    #[test]
    fn registered_method_with_wrong_cose_alg_returns_unsupported() {
        let verifier = test_verifier();
        let registry = test_registry();
        let protected = integrity_cose::detached_signature_protected_header(
            -7,
            b"test-kid",
            "urn:formspec:sig-method:ed25519-cose-sign1@1",
        );
        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, &[0u8; 64]);

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: b"test message".to_vec(),
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(vec![0u8; 32]),
                },
                &registry,
            )
            .expect("alg mismatch should reach an unsupported verdict");

        assert!(
            receipt.is_unsupported(),
            "COSE alg mismatch must reject before invalid signature bytes produce Failed"
        );
    }

    #[test]
    fn test_ed25519_cose_sign1_valid_signature_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let signed_bytes = b"formspec signed payload".to_vec();
        let protected = integrity_cose::detached_signature_protected_header(
            -8,
            b"test-kid",
            "urn:formspec:sig-method:ed25519-cose-sign1@1",
        );
        let sig_structure = integrity_cose::sig_structure_bytes(&protected, &signed_bytes);
        let primitive_signature = key_pair.sign(&sig_structure);
        let signature_bytes =
            integrity_cose::encode_cose_sign1(&protected, None, primitive_signature.as_ref());

        let verifier = test_verifier();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(key_pair.public_key().as_ref().to_vec()),
                },
                &registry,
            )
            .expect("verify");

        assert!(receipt.is_verified(), "ed25519 round-trip must verify");
    }

    // The earlier `test_did_key_ref_returns_clear_error` and
    // `test_urn_key_ref_returns_clear_error` tests exercised the legacy
    // stringly-typed `KidOrThumbprint` path that sniffed `did:` / `urn:`
    // prefixes. That path is gone — `KeyRef` is typed and the resolver-port
    // takes over identifier resolution. Coverage for resolver failures lives
    // in `kid_lookup_failure_returns_key_resolution_error` below.

    // ---------- Golden-vector round-trips (fs-wxoz) ----------
    //
    // Real cross-adapter import vectors. Each test:
    //   1. Generates / loads a real key, signs `signed_bytes` via ring's
    //      *signing* API, wraps the signature in COSE_Sign1.
    //   2. Routes through `RingVerifier::verify` and asserts the receipt is
    //      "verified" — proves ring's *dispatch* path (key parse + verify
    //      constants + COSE decode) is sound end-to-end.
    //   3. Flips one byte of the inner signature bytes and re-verifies,
    //      asserting the receipt is "failed" — proves the negative path
    //      rejects tampered signatures rather than silently passing.
    //   4. Emits the vector to `tests/fixtures/golden-vectors/<alg>.json`
    //      when `INTEGRITY_REGENERATE_GOLDEN_VECTORS=1`. The committed file
    //      is then re-loaded and re-verified in a separate fixture-import
    //      test, mirroring the byte-for-byte path webcrypto and Trellis
    //      adapters will take when consuming these vectors.

    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("golden-vectors")
    }

    fn to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    fn to_b64(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }

    fn from_b64(s: &str) -> Vec<u8> {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
            .expect("base64 decode")
    }

    /// Reads a committed golden-vector JSON or fails loudly.
    ///
    /// Committed fixtures live in `tests/fixtures/golden-vectors/` and are
    /// checked into the repo. The import tests below read them; if a fixture
    /// is missing, that is always a real regression (deleted file, broken
    /// checkout, wrong path). Skipping silently — as the prior `eprintln +
    /// return` did — masks the regression as a green test run. Always panic.
    ///
    /// Workflow for authoring a new vector type:
    ///   1. Add the round-trip test (it generates + signs + verifies in-process).
    ///   2. Run `INTEGRITY_REGENERATE_GOLDEN_VECTORS=1 cargo nextest run \
    ///      -p formspec-signature-adapter-ring` to write the fixture.
    ///   3. Commit the fixture.
    ///   4. Add the import test (it reads the now-committed fixture).
    /// Steps 1–3 happen before step 4, so the import test only ever runs
    /// against a present fixture in normal operation.
    fn read_committed_vector_or_panic(path: &std::path::Path, name: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|_| {
            panic!(
                "{name} committed golden vector missing at {}; \
                 this fixture is committed to the repo and must be present. \
                 To regenerate, set INTEGRITY_REGENERATE_GOLDEN_VECTORS=1 and \
                 rerun the round-trip test first to produce the file before \
                 committing it.",
                path.display()
            );
        })
    }

    #[test]
    fn read_committed_vector_or_panic_returns_file_contents_when_present() {
        let temp_path =
            std::env::temp_dir().join(format!("fs-wxoz-helper-{}.json", std::process::id()));
        std::fs::write(&temp_path, r#"{"test":"content"}"#).expect("write temp");
        let contents = read_committed_vector_or_panic(&temp_path, "test.json");
        std::fs::remove_file(&temp_path).ok();
        assert_eq!(contents, r#"{"test":"content"}"#);
    }

    #[test]
    fn read_committed_vector_or_panic_panics_with_actionable_message_when_missing() {
        let missing = std::env::temp_dir().join(format!(
            "fs-wxoz-helper-missing-{}.json",
            std::process::id()
        ));
        // Best-effort cleanup in case a prior run left state on disk.
        std::fs::remove_file(&missing).ok();

        let result =
            std::panic::catch_unwind(|| read_committed_vector_or_panic(&missing, "missing.json"));

        assert!(result.is_err(), "must panic when fixture absent");
        let err = result.unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&'static str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("missing.json"),
            "panic message must name the fixture; got: {msg}"
        );
        assert!(
            msg.contains("committed golden vector missing"),
            "panic message must explain the missing-vector contract; got: {msg}"
        );
        assert!(
            msg.contains("INTEGRITY_REGENERATE_GOLDEN_VECTORS"),
            "panic message must point to the regenerate env var; got: {msg}"
        );
    }

    /// JSON fixture shape. Hand-rolled (no serde) so the crate keeps zero
    /// extra dev-deps and importers can match the exact key ordering
    /// byte-for-byte if they care to.
    fn write_vector(path: &std::path::Path, vector: &GoldenVector<'_>) {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"method_uri\": \"{}\",\n", vector.method_uri));
        s.push_str(&format!("  \"registry_alg\": {},\n", vector.registry_alg));
        s.push_str("  \"adapter\": {\n");
        s.push_str("    \"id\": \"urn:integrity-stack:adapter:ring@1\",\n");
        s.push_str("    \"version\": \"0.1.0\"\n");
        s.push_str("  },\n");
        s.push_str(&format!(
            "  \"public_key_format\": \"{}\",\n",
            vector.public_key_format
        ));
        s.push_str(&hex_b64_field("public_key", vector.public_key, false));
        s.push_str(&hex_b64_field("signed_bytes", vector.signed_bytes, false));
        s.push_str(&hex_b64_field(
            "protected_header",
            vector.protected_header,
            false,
        ));
        s.push_str(&hex_b64_field("sig_structure", vector.sig_structure, false));
        s.push_str(&hex_b64_field("raw_signature", vector.raw_signature, false));
        s.push_str(&hex_b64_field(
            "signature_bytes_cose_sign1",
            vector.signature_bytes_cose_sign1,
            true,
        ));
        s.push_str("}\n");
        std::fs::write(path, s).expect("write vector");
    }

    fn hex_b64_field(name: &str, bytes: &[u8], last: bool) -> String {
        let comma = if last { "" } else { "," };
        format!(
            "  \"{name}\": {{\n    \"hex\": \"{}\",\n    \"base64\": \"{}\"\n  }}{comma}\n",
            to_hex(bytes),
            to_b64(bytes),
        )
    }

    struct GoldenVector<'a> {
        method_uri: &'a str,
        registry_alg: i64,
        public_key_format: &'a str,
        public_key: &'a [u8],
        signed_bytes: &'a [u8],
        protected_header: &'a [u8],
        sig_structure: &'a [u8],
        raw_signature: &'a [u8],
        signature_bytes_cose_sign1: &'a [u8],
    }

    fn read_b64_field(json: &str, field: &str) -> Vec<u8> {
        // Minimal hand-rolled grep — the fixture format above is fixed enough
        // that we don't need a full JSON parser to round-trip a few base64
        // strings. The inner `"base64": "<value>"` is unique per field after
        // its enclosing `"<field>":` opener.
        let anchor = format!("\"{field}\": {{");
        let start = json
            .find(&anchor)
            .unwrap_or_else(|| panic!("missing field {field}"));
        let after = &json[start..];
        let b64_anchor = "\"base64\": \"";
        let b64_start = after
            .find(b64_anchor)
            .unwrap_or_else(|| panic!("missing base64 for {field}"));
        let payload_start = start + b64_start + b64_anchor.len();
        let rest = &json[payload_start..];
        let payload_end = rest.find('"').expect("unterminated base64 string");
        from_b64(&json[payload_start..payload_start + payload_end])
    }

    fn maybe_regenerate() -> bool {
        std::env::var("INTEGRITY_REGENERATE_GOLDEN_VECTORS")
            .ok()
            .as_deref()
            == Some("1")
    }

    fn flip_inner_signature(cose_bytes: &[u8], raw_sig: &[u8]) -> Vec<u8> {
        // The COSE_Sign1 envelope embeds the raw signature byte-for-byte as
        // the final bstr; flipping one byte there changes the inner sig
        // without disturbing the protected header or other framing.
        let needle_start = cose_bytes
            .windows(raw_sig.len())
            .position(|w| w == raw_sig)
            .expect("raw signature must appear inside COSE_Sign1 envelope");
        let mut tampered = cose_bytes.to_vec();
        tampered[needle_start] ^= 0x01;
        tampered
    }

    #[test]
    fn test_ecdsa_p256_cose_sign1_valid_signature_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("generate ecdsa pkcs8");
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("parse ecdsa pkcs8");

        let signed_bytes = b"formspec ecdsa-p256 golden vector payload".to_vec();
        let protected = integrity_cose::detached_signature_protected_header(
            -7,
            b"test-kid",
            "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1",
        );
        let sig_structure = integrity_cose::sig_structure_bytes(&protected, &signed_bytes);
        let raw_signature = key_pair.sign(&rng, &sig_structure).expect("ecdsa sign");
        let signature_bytes =
            integrity_cose::encode_cose_sign1(&protected, None, raw_signature.as_ref());
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let verifier = test_verifier();
        let registry = test_registry();

        // Positive path.
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: signed_bytes.clone(),
                    signature_bytes: signature_bytes.clone(),
                    method_uri: "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key_bytes.clone()),
                },
                &registry,
            )
            .expect("verify ecdsa");
        assert!(
            receipt.is_verified(),
            "ecdsa-p256 positive round-trip must verify"
        );

        // Negative path — flip one byte of the inner signature.
        let tampered = flip_inner_signature(&signature_bytes, raw_signature.as_ref());
        assert_ne!(tampered, signature_bytes, "tamper must mutate envelope");
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: signed_bytes.clone(),
                    signature_bytes: tampered,
                    method_uri: "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key_bytes.clone()),
                },
                &registry,
            )
            .expect("verify tampered ecdsa");
        assert_eq!(
            receipt.result.to_string(),
            "failed",
            "ecdsa-p256 tampered signature must reject"
        );

        if maybe_regenerate() {
            std::fs::create_dir_all(fixture_dir()).expect("mkdir");
            write_vector(
                &fixture_dir().join("ecdsa-p256-sha256.json"),
                &GoldenVector {
                    method_uri: "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1",
                    registry_alg: -7,
                    public_key_format: "SEC1 uncompressed P-256 (65 bytes, 0x04 prefix)",
                    public_key: &public_key_bytes,
                    signed_bytes: &signed_bytes,
                    protected_header: &protected,
                    sig_structure: &sig_structure,
                    raw_signature: raw_signature.as_ref(),
                    signature_bytes_cose_sign1: &signature_bytes,
                },
            );
        }
    }

    #[test]
    fn test_rsa_pss_sha256_cose_sign1_valid_signature_verifies() {
        // Ring cannot generate RSA keys. Load a pre-committed PKCS#8 v1
        // test key (2048-bit, generated once via `openssl genpkey`).
        let pkcs8_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("rsa-test-key.pkcs8");
        let pkcs8 = std::fs::read(&pkcs8_path).expect("rsa test key pkcs8");
        let key_pair = signature::RsaKeyPair::from_pkcs8(&pkcs8).expect("parse rsa pkcs8");

        let rng = SystemRandom::new();
        let signed_bytes = b"formspec rsa-pss-sha256 golden vector payload".to_vec();
        let protected = integrity_cose::detached_signature_protected_header(
            -37,
            b"test-kid",
            "urn:formspec:sig-method:rsa-pss-sha256-cose-sign1@1",
        );
        let sig_structure = integrity_cose::sig_structure_bytes(&protected, &signed_bytes);

        let mut raw_signature = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &signature::RSA_PSS_SHA256,
                &rng,
                &sig_structure,
                &mut raw_signature,
            )
            .expect("rsa-pss sign");

        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, &raw_signature);

        use ring::signature::KeyPair as _;
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let verifier = test_verifier();
        let registry = test_registry();

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: signed_bytes.clone(),
                    signature_bytes: signature_bytes.clone(),
                    method_uri: "urn:formspec:sig-method:rsa-pss-sha256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key_bytes.clone()),
                },
                &registry,
            )
            .expect("verify rsa-pss");
        assert!(
            receipt.is_verified(),
            "rsa-pss-sha256 positive round-trip must verify"
        );

        let tampered = flip_inner_signature(&signature_bytes, &raw_signature);
        assert_ne!(tampered, signature_bytes);
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: signed_bytes.clone(),
                    signature_bytes: tampered,
                    method_uri: "urn:formspec:sig-method:rsa-pss-sha256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key_bytes.clone()),
                },
                &registry,
            )
            .expect("verify tampered rsa-pss");
        assert_eq!(
            receipt.result.to_string(),
            "failed",
            "rsa-pss-sha256 tampered signature must reject"
        );

        if maybe_regenerate() {
            std::fs::create_dir_all(fixture_dir()).expect("mkdir");
            write_vector(
                &fixture_dir().join("rsa-pss-sha256.json"),
                &GoldenVector {
                    method_uri: "urn:formspec:sig-method:rsa-pss-sha256-cose-sign1@1",
                    registry_alg: -37,
                    public_key_format: "DER-encoded RSAPublicKey (PKCS#1 SEQUENCE { n, e })",
                    public_key: &public_key_bytes,
                    signed_bytes: &signed_bytes,
                    protected_header: &protected,
                    sig_structure: &sig_structure,
                    raw_signature: &raw_signature,
                    signature_bytes_cose_sign1: &signature_bytes,
                },
            );
        }
    }

    #[test]
    fn test_ecdsa_p256_committed_golden_vector_imports_and_verifies() {
        // Mirrors the byte-for-byte path another adapter (webcrypto,
        // trellis-admission-formspec) will take when importing this vector:
        // read JSON → decode public_key + signed_bytes + COSE_Sign1 → verify.
        // Regenerate mode is the only path that may bypass the fixture-present
        // assertion (the round-trip test produces the file before this one
        // re-reads it; parallel nextest can't guarantee ordering).
        let path = fixture_dir().join("ecdsa-p256-sha256.json");
        let json = read_committed_vector_or_panic(&path, "ecdsa-p256-sha256.json");
        let public_key = read_b64_field(&json, "public_key");
        let signed_bytes = read_b64_field(&json, "signed_bytes");
        let signature_bytes = read_b64_field(&json, "signature_bytes_cose_sign1");

        let verifier = test_verifier();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ecdsa-p256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key),
                },
                &registry,
            )
            .expect("verify imported ecdsa vector");
        assert!(receipt.is_verified());
    }

    #[test]
    fn test_rsa_pss_sha256_committed_golden_vector_imports_and_verifies() {
        let path = fixture_dir().join("rsa-pss-sha256.json");
        let json = read_committed_vector_or_panic(&path, "rsa-pss-sha256.json");
        let public_key = read_b64_field(&json, "public_key");
        let signed_bytes = read_b64_field(&json, "signed_bytes");
        let signature_bytes = read_b64_field(&json, "signature_bytes_cose_sign1");

        let verifier = test_verifier();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:rsa-pss-sha256-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key),
                },
                &registry,
            )
            .expect("verify imported rsa-pss vector");
        assert!(receipt.is_verified());
    }

    // ---------- Receipt signing (fs-migs) ----------

    /// Builds an ed25519 round-trip VerifyRequest whose verdict is
    /// Verified — used to drive receipt-signing tests through the same
    /// path a real consumer would take.
    fn verified_ed25519_request() -> (VerifyRequest, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let signed_bytes = b"formspec receipt-signing happy path".to_vec();
        // Build a response-signing envelope (sig-method prefix). The helper
        // builds a VerifyRequest whose method_uri is sig-method:ed25519
        // (line below); the verifier rejects mismatched prefixes per ADR 0109.
        let protected = integrity_cose::detached_signature_protected_header(
            -8,
            b"test-kid",
            "urn:formspec:sig-method:ed25519-cose-sign1@1",
        );
        let sig_structure = integrity_cose::sig_structure_bytes(&protected, &signed_bytes);
        let raw_sig = key_pair.sign(&sig_structure);
        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, raw_sig.as_ref());
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let request = VerifyRequest {
            signed_bytes,
            signature_bytes,
            method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
            key_ref: KeyRef::RawPublicKey(public_key_bytes.clone()),
        };
        (request, public_key_bytes)
    }

    /// Without a configured ReceiptSigner the legacy behavior is preserved:
    /// receipt_bytes stays None. fs-migs.
    #[test]
    fn verifier_without_receipt_signer_leaves_receipt_bytes_none() {
        let verifier = test_verifier();
        let (request, _) = verified_ed25519_request();
        let receipt = verifier.verify(&request, &test_registry()).expect("verify");
        assert!(receipt.is_verified());
        assert!(
            receipt.receipt_bytes.is_none(),
            "verification-only verifier must not fabricate receipt bytes"
        );
    }

    /// With a configured ReceiptSigner, a reached-verdict receipt carries
    /// a non-None receipt_bytes whose COSE_Sign1 envelope verifies under
    /// the signer's published public key. fs-migs.
    #[test]
    fn verifier_with_receipt_signer_attaches_verifiable_receipt_bytes() {
        let (signer, signer_pub_key) =
            InProcessReceiptSigner::generate(Some(b"receipt-kid")).expect("generate signer");
        assert_eq!(signer.signer_id(), DEFAULT_IN_PROCESS_RECEIPT_SIGNER_ID);
        let verifier =
            RingVerifier::new_with_config_and_receipt_signer(test_config(), Arc::new(signer));
        let (request, _) = verified_ed25519_request();
        let receipt = verifier.verify(&request, &test_registry()).expect("verify");
        assert!(receipt.is_verified());
        let envelope_b64 = receipt
            .receipt_bytes
            .as_ref()
            .expect("receipt_bytes must be populated when signer is wired");
        let envelope =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, envelope_b64)
                .expect("base64 decode envelope");

        let (cose, _) = integrity_cose::decode_cose_sign1_with_method_uri(
            &envelope,
            DEFAULT_RECEIPT_METHOD_URI_PREFIX,
        )
        .expect("cose decode");
        assert_eq!(cose.alg(), Some(-8), "ed25519 EdDSA alg expected");
        let canonical = canonical_receipt_payload_bytes(&VerificationReceipt {
            // Reconstruct the receipt-without-signature view the signer saw.
            // We strip receipt_bytes via canonical_receipt_payload_bytes,
            // so cloning the receipt as-is is fine — only the JSON-stripping
            // path matters.
            ..receipt.clone()
        })
        .expect("canonical payload");
        let payload = cose
            .resolve_payload(Some(&canonical))
            .expect("payload resolves");
        let sig_structure = integrity_cose::sig_structure_bytes(cose.protected_header(), payload);
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &signer_pub_key);
        public_key
            .verify(&sig_structure, cose.signature())
            .expect("receipt signature must verify under signer's public key");
    }

    /// Receipt signing is deterministic for Ed25519: the same (canonical
    /// payload, key) pair MUST produce identical envelope bytes across
    /// invocations. Different payloads MUST produce different envelopes.
    /// fs-migs.
    #[test]
    fn in_process_signer_is_deterministic_for_ed25519() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("pkcs8");
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        let signer = InProcessReceiptSigner::new(key_pair, Some(b"kid"));

        let payload_a = b"canonical-receipt-payload-a";
        let payload_b = b"canonical-receipt-payload-b";
        let env_a1 = signer.sign_receipt(payload_a).expect("sign a1");
        let env_a2 = signer.sign_receipt(payload_a).expect("sign a2");
        let env_b = signer.sign_receipt(payload_b).expect("sign b");

        assert_eq!(env_a1, env_a2, "Ed25519 signing must be deterministic");
        assert_ne!(
            env_a1, env_b,
            "distinct payloads must produce distinct envelopes"
        );
    }

    /// Tampering the receipt payload must break receipt-signature
    /// verification — proves the signed bytes commit to receipt content,
    /// not arbitrary noise. fs-migs.
    #[test]
    fn tampered_canonical_payload_breaks_receipt_signature() {
        let (signer, public_key_bytes) =
            InProcessReceiptSigner::generate(Some(b"receipt-kid")).expect("generate signer");
        let payload = b"original canonical receipt payload";
        let envelope = signer.sign_receipt(payload).expect("sign");
        let (cose, _) = integrity_cose::decode_cose_sign1_with_method_uri(
            &envelope,
            DEFAULT_RECEIPT_METHOD_URI_PREFIX,
        )
        .expect("decode");
        let tampered_payload = b"tampered canonical receipt payload";
        let sig_structure =
            integrity_cose::sig_structure_bytes(cose.protected_header(), tampered_payload);
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);
        public_key
            .verify(&sig_structure, cose.signature())
            .expect_err("tampered payload must fail signature verification");
    }

    /// Canonical receipt-payload bytes use the integrity-canonical domain
    /// frame and strip `receiptBytes` before JCS encoding. Hash stability
    /// across runs is implicit (integrity-canonical is byte-stable); the
    /// explicit assertions here are: receiptBytes is omitted, the bytes
    /// start with the domain tag, and adding receipt_bytes to the input
    /// does not change output. fs-migs.
    #[test]
    fn canonical_receipt_payload_strips_receipt_bytes_and_uses_domain_frame() {
        let mut receipt = VerificationReceipt {
            result: VerificationResult::Verified,
            method: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
            method_registry_version: "1.0.0".into(),
            adapter: AdapterInfo {
                id: DEFAULT_ADAPTER_ID.into(),
                version: ADAPTER_VERSION.into(),
            },
            key: KeyInfo {
                r#ref: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                version: None,
                snapshot: None,
            },
            verified_at: "2026-05-16T00:00:00Z".to_string(),
            context: None,
            receipt_bytes: None,
        };
        let without = canonical_receipt_payload_bytes(&receipt).expect("without");
        receipt.receipt_bytes = Some("ignored-bytes".to_string());
        let with = canonical_receipt_payload_bytes(&receipt).expect("with");
        assert_eq!(
            without, with,
            "receiptBytes must not contribute to the signed preimage"
        );
        assert!(
            with.starts_with(RECEIPT_SIGNED_PAYLOAD_DOMAIN.as_bytes()),
            "preimage must lead with the receipt-signing domain tag"
        );
        assert_eq!(
            with[RECEIPT_SIGNED_PAYLOAD_DOMAIN.len()],
            0u8,
            "domain tag must be NUL-separated from canonical JSON"
        );
    }

    // ---------- ReceiptSigner verdict-coverage + failing-signer (fs-abjt) ----------

    /// Test-only signer that always returns `Err(SigningFailed)`. Used to
    /// prove the fs-no9r "no silent unsigned fallback on signer failure"
    /// contract: a failing signer MUST surface as `VerifierError::Internal`,
    /// not as a successful receipt with `receipt_bytes = None`.
    struct FailingReceiptSigner;

    impl ReceiptSigner for FailingReceiptSigner {
        fn sign_receipt(&self, _payload: &[u8]) -> Result<Vec<u8>, ReceiptSignerError> {
            Err(ReceiptSignerError::SigningFailed {
                reason: "test signer always fails".to_string(),
            })
        }

        fn signer_id(&self) -> &str {
            "urn:formspec:receipt-signer:test-failing@1"
        }
    }

    /// A reached Failed verdict (signature cryptographically rejected) MUST
    /// still receive receipt_bytes when a signer is wired. The verdict-binding
    /// evidence in `receipt_bytes` is audit-load-bearing for negative outcomes
    /// too — auditors prove the verifier *processed* the bad signature, not
    /// just that they decided to call it bad. fs-abjt.
    #[test]
    fn verifier_with_signer_populates_receipt_bytes_on_failed_verdict() {
        let (signer, _signer_pub_key) =
            InProcessReceiptSigner::generate(Some(b"receipt-kid")).expect("generate signer");
        let verifier =
            RingVerifier::new_with_config_and_receipt_signer(test_config(), Arc::new(signer));
        // Construct a Failed verdict by tampering with a verified envelope.
        let (mut request, _) = verified_ed25519_request();
        // Flip the last byte of the signature_bytes to break the COSE inner
        // signature. The COSE envelope still decodes; ring rejects the verify.
        let last = request.signature_bytes.len() - 1;
        request.signature_bytes[last] ^= 0xff;

        let receipt = verifier
            .verify(&request, &test_registry())
            .expect("verify must reach a verdict");
        assert!(
            receipt.is_failed(),
            "tampered signature must produce Failed (got {:?})",
            receipt.result,
        );
        assert!(
            receipt.receipt_bytes.is_some(),
            "Failed receipts must still carry receipt_bytes when signer is wired"
        );
    }

    /// A reached Unsupported verdict MUST also receive receipt_bytes when a
    /// signer is wired. Same audit-coverage argument as the Failed case —
    /// receipt_bytes records that the verifier reached the verdict; the
    /// caller cannot conflate "verifier crashed" with "verifier reached
    /// Unsupported". fs-abjt.
    #[test]
    fn verifier_with_signer_populates_receipt_bytes_on_unsupported_verdict() {
        let (signer, _signer_pub_key) =
            InProcessReceiptSigner::generate(Some(b"receipt-kid")).expect("generate signer");
        let verifier =
            RingVerifier::new_with_config_and_receipt_signer(test_config(), Arc::new(signer));
        // Construct an Unsupported verdict by routing through an unknown
        // signature method (registry resolve returns None → unsupported).
        let (mut request, _) = verified_ed25519_request();
        request.method_uri = "urn:formspec:sig-method:nonexistent@99".into();

        let receipt = verifier
            .verify(&request, &test_registry())
            .expect("verify must reach a verdict");
        assert!(
            receipt.is_unsupported(),
            "unknown method must produce Unsupported (got {:?})",
            receipt.result,
        );
        assert!(
            receipt.receipt_bytes.is_some(),
            "Unsupported receipts must still carry receipt_bytes when signer is wired"
        );
    }

    /// When the signer fails, the verifier MUST return
    /// `Err(VerifierError::Internal)` — NEVER an `Ok(receipt)` with
    /// `receipt_bytes = None`. The fs-no9r contract distinguishes
    /// "verifier reached a verdict" (Ok) from "verifier could not
    /// complete" (Err); silently degrading a signer failure to an
    /// unsigned receipt collapses that distinction. fs-abjt.
    #[test]
    fn verifier_with_failing_signer_returns_verifier_error_internal() {
        let verifier = RingVerifier::new_with_config_and_receipt_signer(
            test_config(),
            Arc::new(FailingReceiptSigner),
        );
        let (request, _) = verified_ed25519_request();
        let err = verifier
            .verify(&request, &test_registry())
            .expect_err("failing signer must surface as VerifierError, not Ok(unsigned)");
        match err {
            VerifierError::Internal { reason } => {
                assert!(
                    reason.contains("signer"),
                    "Internal reason must name the signer (got: {reason})"
                );
            }
            other => panic!("expected VerifierError::Internal, got {other:?}"),
        }
    }

    // ---------- KeyResolver port + kid binding (fs-0gzb) ----------

    use std::collections::HashMap;

    /// Builds a signed Ed25519 COSE_Sign1 envelope along with the keypair's
    /// public key bytes and a known `kid`. Shared between the kid-binding
    /// tests below — each scenario varies only how the `kid` flows into the
    /// `VerifyRequest`.
    fn ed25519_envelope_with_kid(kid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("pkcs8");
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        let signed_bytes = b"formspec kid-binding payload".to_vec();
        let protected = integrity_cose::detached_signature_protected_header(
            -8,
            kid,
            "urn:formspec:sig-method:ed25519-cose-sign1@1",
        );
        let sig_structure = integrity_cose::sig_structure_bytes(&protected, &signed_bytes);
        let raw_sig = key_pair.sign(&sig_structure);
        let signature_bytes = integrity_cose::encode_cose_sign1(&protected, None, raw_sig.as_ref());
        (
            signed_bytes,
            signature_bytes,
            key_pair.public_key().as_ref().to_vec(),
        )
    }

    /// Ed25519 happy path via `KeyRef::Kid` routed through a `StaticKeyResolver`.
    /// Proves the resolver-injection path verifies a real signature end to
    /// end and that the kid binding `cose.kid == request.keyRef.Kid` holds.
    #[test]
    fn ed25519_kid_path_via_static_resolver_verifies() {
        let kid = b"audit-kid-A".to_vec();
        let (signed_bytes, signature_bytes, public_key) = ed25519_envelope_with_kid(&kid);

        let mut resolver = StaticKeyResolver::empty();
        resolver.insert(kid.clone(), public_key);
        let verifier =
            RingVerifier::new_with_config_and_key_resolver(test_config(), Arc::new(resolver));
        let registry = test_registry();

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::Kid(kid),
                },
                &registry,
            )
            .expect("verify");
        assert!(receipt.is_verified(), "kid-resolved ed25519 must verify");
    }

    #[test]
    fn injected_clock_and_key_resolver_preserve_recorded_receipt_time() {
        const RECORDED_TIME: &str = "2001-02-03T04:05:06Z";
        let kid = b"historical-key".to_vec();
        let (signed_bytes, signature_bytes, public_key) = ed25519_envelope_with_kid(&kid);
        let mut resolver = StaticKeyResolver::empty();
        resolver.insert(kid.clone(), public_key);
        let verifier = RingVerifier::new_with_clock_config_and_key_resolver(
            Arc::new(FixedClock::at_rfc3339(RECORDED_TIME).expect("recorded clock")),
            test_config(),
            Arc::new(resolver),
        );
        let mut request = VerifyRequest {
            signed_bytes,
            signature_bytes,
            method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
            key_ref: KeyRef::Kid(kid),
        };
        let verified = verifier.verify(&request, &test_registry()).expect("verify");
        assert!(verified.is_verified());
        assert_eq!(verified.verified_at, RECORDED_TIME);
        assert_eq!(
            verified.adapter.id.as_str(),
            test_config().adapter_id.as_str()
        );
        assert_eq!(
            verified.adapter.version.as_str(),
            test_config().adapter_version.as_str()
        );
        assert!(verified.receipt_bytes.is_none());

        request.signed_bytes.push(0);
        let failed = verifier
            .verify(&request, &test_registry())
            .expect("verdict");
        let mut expected = verified;
        expected.result = VerificationResult::Failed;
        assert_eq!(failed, expected, "failed receipt preserves all metadata");

        for alg in [Some(42), None] {
            let mut registry = test_registry();
            registry.entries[0].alg = alg;
            let unsupported = verifier
                .verify(&request, &registry)
                .expect("unsupported verdict");
            expected.result = VerificationResult::Unsupported;
            assert_eq!(
                unsupported, expected,
                "unsupported receipt preserves all metadata"
            );
        }
    }

    /// fs-skj0 — kid mismatch attack vector. COSE envelope carries
    /// `kid = audit-kid-A`; request asks for `kid = audit-kid-B`; resolver
    /// returns the public key bound to `B`. The verifier MUST reject before
    /// reaching the primitive, with verdict `unsupported`.
    #[test]
    fn kid_mismatch_between_cose_envelope_and_request_returns_unsupported() {
        let envelope_kid = b"audit-kid-A".to_vec();
        let request_kid = b"audit-kid-B".to_vec();
        let (signed_bytes, signature_bytes, _envelope_public_key) =
            ed25519_envelope_with_kid(&envelope_kid);

        // Resolver knows about request_kid but binds it to a *different*
        // (irrelevant) key — proves the rejection is at the kid binding,
        // not at the primitive.
        let mut resolver = StaticKeyResolver::empty();
        resolver.insert(request_kid.clone(), vec![0u8; 32]);
        let verifier =
            RingVerifier::new_with_config_and_key_resolver(test_config(), Arc::new(resolver));
        let registry = test_registry();

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::Kid(request_kid),
                },
                &registry,
            )
            .expect("verify");
        assert!(
            receipt.is_unsupported(),
            "kid mismatch must produce unsupported verdict, got: {}",
            receipt.result
        );
    }

    /// Missing keys remain distinguishable from primitive or internal failures.
    #[test]
    fn kid_lookup_failure_returns_key_resolution_error() {
        let envelope_kid = b"some-kid".to_vec();
        let (signed_bytes, signature_bytes, _) = ed25519_envelope_with_kid(&envelope_kid);

        // Empty resolver — any Kid resolves to KeyNotFound.
        let verifier = RingVerifier::new_with_config_and_key_resolver(
            test_config(),
            Arc::new(StaticKeyResolver::empty()),
        );
        let registry = test_registry();

        let error = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::Kid(envelope_kid),
                },
                &registry,
            )
            .expect_err("KeyNotFound must surface as Err, not Ok(failed)");
        match error {
            VerifierError::KeyResolution { reason } => {
                assert!(
                    reason.contains("kid not found"),
                    "expected kid-not-found phrasing, got: {reason}"
                );
            }
            other => panic!("expected VerifierError::KeyResolution, got: {other}"),
        }
    }

    #[derive(Debug)]
    struct RejectingKeyResolver {
        unsupported: bool,
    }

    impl KeyResolver for RejectingKeyResolver {
        fn resolve(&self, _: &KeyRef) -> Result<Vec<u8>, KeyResolverError> {
            if self.unsupported {
                Err(KeyResolverError::UnsupportedKeyRef(
                    "remote keys disabled".into(),
                ))
            } else {
                Err(KeyResolverError::Internal("provider unavailable".into()))
            }
        }

        fn resolver_id(&self) -> &str {
            "urn:test:rejecting-resolver"
        }
    }

    #[test]
    fn resolver_failure_types_survive_supported_and_unsupported_algorithms() {
        for alg in [Some(-8), Some(42), None] {
            for unsupported in [true, false] {
                let verifier = RingVerifier::new_with_config_and_key_resolver(
                    test_config(),
                    Arc::new(RejectingKeyResolver { unsupported }),
                );
                let mut registry = test_registry();
                registry.entries[0].alg = alg;
                let error = verifier
                    .verify(
                        &VerifyRequest {
                            signed_bytes: vec![],
                            signature_bytes: vec![],
                            method_uri: registry.entries[0].id.clone(),
                            key_ref: KeyRef::Kid(b"lookup-key".to_vec()),
                        },
                        &registry,
                    )
                    .expect_err("resolver failure must prevent a receipt");
                match (unsupported, error) {
                    (true, VerifierError::UnsupportedKeyRef { reason }) => {
                        assert!(reason.contains("remote keys disabled"));
                    }
                    (false, VerifierError::Internal { reason }) => {
                        assert!(reason.contains("provider unavailable"));
                    }
                    (_, other) => panic!("unexpected resolver error: {other}"),
                }
            }
        }
    }

    /// Per-algorithm key-length validation. Ed25519 keys must be 32 bytes;
    /// a 31-byte key short-circuits to `unsupported` before reaching ring's
    /// primitive (which would otherwise return a generic error that the
    /// adapter collapsed to `failed` — the wrong caller signal).
    #[test]
    fn ed25519_wrong_length_key_returns_unsupported() {
        let registry = test_registry();
        let verifier = test_verifier();
        // Build a valid-looking COSE envelope so the wedge is the key length.
        let (signed_bytes, signature_bytes, _) = ed25519_envelope_with_kid(b"any-kid");

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(vec![0u8; 31]),
                },
                &registry,
            )
            .expect("verify");
        assert!(
            receipt.is_unsupported(),
            "31-byte ed25519 key must route to unsupported, got: {}",
            receipt.result
        );
    }

    /// Default (no explicit resolver) constructor wires an empty
    /// `StaticKeyResolver`. `KeyRef::Kid` immediately surfaces a
    /// `VerifierError::KeyResolution` — the verifier cannot reach a verdict
    /// because there is no key to verify against. Pairs with the
    /// new_with_key_resolver constructor as the canonical migration: callers
    /// that previously passed raw key bytes via `KidOrThumbprint(base64(...))`
    /// switch to `KeyRef::RawPublicKey(bytes)` directly; callers that want to
    /// look keys up by kid wire a real resolver into the constructor.
    #[test]
    fn default_verifier_rejects_kid_without_resolver() {
        let registry = test_registry();
        let verifier = test_verifier();
        let (signed_bytes, signature_bytes, _) = ed25519_envelope_with_kid(b"k");

        let error = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::Kid(b"k".to_vec()),
                },
                &registry,
            )
            .expect_err("default verifier has no resolver — Kid must fail");
        assert!(matches!(error, VerifierError::KeyResolution { .. }));
    }

    /// `key.ref` field on the receipt is human-readable: `Kid(bytes)` is
    /// base64; `RawPublicKey(bytes)` carries a `raw:` prefix so a consumer
    /// can tell the variant at a glance without misreading raw key bytes as
    /// a kid identifier.
    #[test]
    fn receipt_key_ref_field_distinguishes_kid_from_raw_public_key() {
        let registry = test_registry();
        let verifier = test_verifier();
        let (signed_bytes, signature_bytes, public_key) = ed25519_envelope_with_kid(b"kid-X");

        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    method_uri: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: KeyRef::RawPublicKey(public_key),
                },
                &registry,
            )
            .expect("verify");
        assert!(receipt.is_verified());
        assert!(
            receipt.key.r#ref.as_str().starts_with("raw:"),
            "raw public-key path must mark the receipt key ref with `raw:` prefix"
        );
    }

    /// Static resolver round-trips `HashMap` ownership through the
    /// constructor — proves the type plays nicely with the `Send + Sync +
    /// 'static` bounds the port imposes.
    #[test]
    fn static_key_resolver_round_trip_via_constructor() {
        let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        map.insert(b"k".to_vec(), vec![1, 2, 3]);
        let resolver = StaticKeyResolver::new(map);
        let bytes = resolver.resolve(&KeyRef::Kid(b"k".to_vec())).expect("hit");
        assert_eq!(bytes, vec![1, 2, 3]);
        assert!(matches!(
            resolver.resolve(&KeyRef::Kid(b"absent".to_vec())),
            Err(KeyResolverError::KeyNotFound { .. })
        ));
    }

    // ---------- In-process Ed25519 key from PKCS#8 (fs-dlou) ----------

    /// Returns a ring-generated PKCS#8 v2 document and its raw public key.
    fn ed25519_pkcs8_and_public_key() -> (Vec<u8>, Vec<u8>) {
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("pkcs8");
        let public_key = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .expect("parse")
            .public_key()
            .as_ref()
            .to_vec();
        (pkcs8.as_ref().to_vec(), public_key)
    }

    /// A PKCS#8 key signs the detached COSE_Sign1 that ring and integrity-cose
    /// compose by hand, byte for byte, and the verifier accepts it.
    #[test]
    fn in_process_ed25519_key_signs_detached_cose_sign1_from_pkcs8() {
        const METHOD: &str = "urn:formspec:sig-method:ed25519-cose-sign1@1";
        let (pkcs8, public_key) = ed25519_pkcs8_and_public_key();
        let key = InProcessEd25519Key::from_pkcs8(&pkcs8).expect("parse pkcs8");
        assert_eq!(key.public_key_bytes(), public_key.as_slice());

        let payload = b"detached document payload";
        let envelope = key.sign_detached_cose_sign1(b"document-kid", METHOD, payload);

        let pair = signature::Ed25519KeyPair::from_pkcs8(&pkcs8).expect("parse");
        let protected =
            integrity_cose::detached_signature_protected_header(-8, b"document-kid", METHOD);
        let by_hand = integrity_cose::encode_cose_sign1(
            &protected,
            None,
            pair.sign(&integrity_cose::sig_structure_bytes(&protected, payload))
                .as_ref(),
        );
        assert_eq!(envelope, by_hand);

        let receipt = test_verifier()
            .verify(
                &VerifyRequest {
                    signed_bytes: payload.to_vec(),
                    signature_bytes: envelope,
                    method_uri: METHOD.into(),
                    key_ref: KeyRef::RawPublicKey(public_key),
                },
                &test_registry(),
            )
            .expect("verify");
        assert!(receipt.is_verified());
    }

    /// A receipt signer built from a parsed key keeps its identity and signs
    /// receipts that verify under that key's public half.
    #[test]
    fn receipt_signer_from_in_process_key_signs_under_its_identity() {
        let (pkcs8, public_key) = ed25519_pkcs8_and_public_key();
        let key = InProcessEd25519Key::from_pkcs8(&pkcs8).expect("parse pkcs8");
        let signer = InProcessReceiptSigner::from_key_with_identity(
            key,
            Some(b"receipt-kid"),
            "urn:test:receipt-signer",
            DEFAULT_RECEIPT_METHOD_URI,
        );
        assert_eq!(signer.public_key_bytes(), public_key.as_slice());
        assert_eq!(signer.signer_id(), "urn:test:receipt-signer");

        let payload = b"canonical receipt payload";
        let envelope = signer.sign_receipt(payload).expect("sign");
        let (cose, _) = integrity_cose::decode_cose_sign1_with_method_uri(
            &envelope,
            DEFAULT_RECEIPT_METHOD_URI_PREFIX,
        )
        .expect("decode");
        assert_eq!(cose.kid(), Some(b"receipt-kid".as_slice()));
        signature::UnparsedPublicKey::new(&signature::ED25519, &public_key)
            .verify(
                &integrity_cose::sig_structure_bytes(cose.protected_header(), payload),
                cose.signature(),
            )
            .expect("receipt verifies under the parsed key");
    }

    /// Bytes that are not an Ed25519 PKCS#8 v2 document are refused, not panicked on.
    #[test]
    fn in_process_ed25519_key_refuses_non_pkcs8_bytes() {
        let (_, public_key) = ed25519_pkcs8_and_public_key();
        for bytes in [&b""[..], b"not a pkcs8 document", &public_key] {
            assert!(matches!(
                InProcessEd25519Key::from_pkcs8(bytes),
                Err(ReceiptSignerError::KeyUnavailable { .. })
            ));
        }
    }

    /// Debug output carries the public key and nothing else.
    #[test]
    fn in_process_ed25519_key_debug_shows_only_the_public_key() {
        let (pkcs8, public_key) = ed25519_pkcs8_and_public_key();
        let key = InProcessEd25519Key::from_pkcs8(&pkcs8).expect("parse pkcs8");
        assert_eq!(
            format!("{key:?}"),
            format!("InProcessEd25519Key {{ public_key: {public_key:?} }}")
        );
    }
}

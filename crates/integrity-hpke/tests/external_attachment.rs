// Rust guideline compliant 2026-02-21
//! Exercises the explicitly selected external attachment profile, not legacy records.

use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256};
use integrity_hpke::external_attachment::{
    AttachmentContext, ProtectionLimits, Recipient, derive_external_attachment_nonce,
    open_external_attachment, protect_external_attachment,
};
use integrity_seam::{OsSecureRandom, SecureRandom};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

const ORIGINAL: &[u8] = b"neutral attachment\0original bytes\n";

fn context() -> AttachmentContext<'static> {
    AttachmentContext {
        idempotency_key: b"accepted-occurrence-1",
        original_sha256: Sha256::digest(ORIGINAL).into(),
        original_byte_length: ORIGINAL.len() as u64,
    }
}

fn limits() -> ProtectionLimits {
    ProtectionLimits {
        original_bytes: 1024,
        recipients: 4,
        recipient_id_bytes: 64,
    }
}

fn public(seed: &[u8; 32]) -> [u8; 32] {
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(seed).unwrap();
    <X25519HkdfSha256 as Kem>::sk_to_pk(&sk)
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap()
}

#[test]
fn every_real_recipient_opens_exact_original_and_tampering_refuses() {
    let seeds = [[0x21; 32], [0x31; 32]];
    let recipients = [
        Recipient {
            id: b"owner",
            public_key: public(&seeds[0]),
        },
        Recipient {
            id: b"reader",
            public_key: public(&seeds[1]),
        },
    ];
    let protected =
        protect_external_attachment(&OsSecureRandom, context(), ORIGINAL, &recipients, limits())
            .unwrap();
    assert_eq!(
        protected.nonce,
        derive_external_attachment_nonce(context()).unwrap()
    );
    assert_eq!(protected.ciphertext.len(), ORIGINAL.len() + 16);
    assert_eq!(protected.key_bag.len(), 2);
    assert_ne!(
        protected.key_bag[0].ephemeral_pubkey,
        protected.key_bag[1].ephemeral_pubkey
    );
    for (entry, seed) in protected.key_bag.iter().zip(&seeds) {
        assert_eq!(entry.suite, 1);
        assert_eq!(entry.wrapped_dek.len(), 48);
        assert_eq!(
            open_external_attachment(context(), &protected.ciphertext, entry, seed, limits())
                .unwrap(),
            ORIGINAL
        );
        let mut changed = protected.ciphertext.clone();
        changed[0] ^= 1;
        assert!(open_external_attachment(context(), &changed, entry, seed, limits()).is_err());
        assert!(
            open_external_attachment(
                context(),
                &protected.ciphertext,
                entry,
                &[0x7f; 32],
                limits()
            )
            .is_err()
        );
        let mut changed_wrap = entry.clone();
        changed_wrap.wrapped_dek[0] ^= 1;
        assert!(
            open_external_attachment(
                context(),
                &protected.ciphertext,
                &changed_wrap,
                seed,
                limits()
            )
            .is_err()
        );
        changed_wrap = entry.clone();
        changed_wrap.suite = 2;
        assert!(
            open_external_attachment(
                context(),
                &protected.ciphertext,
                &changed_wrap,
                seed,
                limits()
            )
            .is_err()
        );
    }
}

#[test]
fn signed_metadata_and_idempotency_changes_refuse() {
    let seed = [0x21; 32];
    let recipients = [Recipient {
        id: b"owner",
        public_key: public(&seed),
    }];
    let protected =
        protect_external_attachment(&OsSecureRandom, context(), ORIGINAL, &recipients, limits())
            .unwrap();
    let entry = &protected.key_bag[0];
    let mut changed = context();
    changed.original_byte_length += 1;
    assert!(
        open_external_attachment(changed, &protected.ciphertext, entry, &seed, limits()).is_err()
    );
    assert!(
        protect_external_attachment(&OsSecureRandom, changed, ORIGINAL, &recipients, limits())
            .is_err()
    );
    changed = context();
    changed.original_sha256[0] ^= 1;
    assert!(
        open_external_attachment(changed, &protected.ciphertext, entry, &seed, limits()).is_err()
    );
    assert!(
        protect_external_attachment(&OsSecureRandom, changed, ORIGINAL, &recipients, limits())
            .is_err()
    );
    changed = context();
    changed.idempotency_key = b"different-operation";
    assert!(
        open_external_attachment(changed, &protected.ciphertext, entry, &seed, limits()).is_err()
    );
}

struct CountRandom {
    calls: AtomicUsize,
    fail_at: usize,
}
impl SecureRandom for CountRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at {
            return Err("injected entropy failure".into());
        }
        dest.fill(0x40 + call as u8);
        Ok(())
    }
}

#[test]
fn entropy_failure_in_dek_or_later_wrap_never_returns_output() {
    let recipients = [
        Recipient {
            id: b"owner",
            public_key: public(&[0x21; 32]),
        },
        Recipient {
            id: b"reader",
            public_key: public(&[0x31; 32]),
        },
    ];
    for fail_at in [1, 2, 3] {
        let rng = CountRandom {
            calls: AtomicUsize::new(0),
            fail_at,
        };
        assert!(
            protect_external_attachment(&rng, context(), ORIGINAL, &recipients, limits()).is_err()
        );
    }
}

#[test]
fn invalid_bounds_and_recipient_sets_refuse_before_entropy() {
    let rng = CountRandom {
        calls: AtomicUsize::new(0),
        fail_at: usize::MAX,
    };
    let good = Recipient {
        id: b"owner",
        public_key: public(&[0x21; 32]),
    };
    assert!(protect_external_attachment(&rng, context(), ORIGINAL, &[], limits()).is_err());
    assert!(
        protect_external_attachment(&rng, context(), ORIGINAL, &[good, good], limits()).is_err()
    );
    let empty = Recipient { id: b"", ..good };
    assert!(protect_external_attachment(&rng, context(), ORIGINAL, &[empty], limits()).is_err());
    let mut bounded = limits();
    bounded.original_bytes = ORIGINAL.len() - 1;
    assert!(protect_external_attachment(&rng, context(), ORIGINAL, &[good], bounded).is_err());
    let mut invalid = context();
    invalid.idempotency_key = b"";
    assert!(protect_external_attachment(&rng, invalid, ORIGINAL, &[good], limits()).is_err());
    assert_eq!(rng.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn retain_output_for_replay_new_protection_is_not_a_retry() {
    let seed = [0x21; 32];
    let recipients = [Recipient {
        id: b"owner",
        public_key: public(&seed),
    }];
    let first =
        protect_external_attachment(&OsSecureRandom, context(), ORIGINAL, &recipients, limits())
            .unwrap();
    let second =
        protect_external_attachment(&OsSecureRandom, context(), ORIGINAL, &recipients, limits())
            .unwrap();
    assert_eq!(first.nonce, second.nonce);
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_ne!(
        first.key_bag[0].ephemeral_pubkey,
        second.key_bag[0].ephemeral_pubkey
    );
    assert_eq!(
        open_external_attachment(
            context(),
            &first.ciphertext,
            &first.key_bag[0],
            &seed,
            limits()
        )
        .unwrap(),
        ORIGINAL
    );
}

#[test]
fn independent_payload_byte_vector_and_authenticated_wrong_original_refuse() {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
    let seed = [0x21; 32];
    let recipients = [Recipient {
        id: b"owner",
        public_key: public(&seed),
    }];
    let rng = CountRandom {
        calls: AtomicUsize::new(0),
        fail_at: usize::MAX,
    };
    let protected =
        protect_external_attachment(&rng, context(), ORIGINAL, &recipients, limits()).unwrap();
    assert_eq!(
        protected.nonce,
        *include_bytes!("external-attachment-vector/nonce.bin")
    );
    assert_eq!(
        protected.ciphertext.as_slice(),
        include_bytes!("external-attachment-vector/ciphertext.bin")
    );
    assert_eq!(
        open_external_attachment(
            context(),
            &protected.ciphertext,
            &protected.key_bag[0],
            &seed,
            limits()
        )
        .unwrap(),
        ORIGINAL
    );
    // A valid AEAD tag alone cannot substitute a different original body.
    let cipher = ChaCha20Poly1305::new_from_slice(&[0x41; 32]).unwrap();
    let mut substituted = ORIGINAL.to_vec();
    substituted[0] ^= 1;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&protected.nonce), b"", &mut substituted)
        .unwrap();
    substituted.extend_from_slice(&tag);
    assert!(
        open_external_attachment(
            context(),
            &substituted,
            &protected.key_bag[0],
            &seed,
            limits()
        )
        .is_err()
    );
}

#[test]
fn public_nonce_helper_matches_independent_vector_and_refuses_invalid_identity() {
    assert_eq!(
        derive_external_attachment_nonce(context())
            .unwrap()
            .as_slice(),
        include_bytes!("external-attachment-vector/nonce.bin")
    );
    for id in [b"".as_slice(), &[0; 65]] {
        assert!(
            derive_external_attachment_nonce(AttachmentContext {
                idempotency_key: id,
                ..context()
            })
            .is_err()
        );
    }
}

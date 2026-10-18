// Rust guideline compliant 2026-02-21

use integrity_cose::{KeyFileSigner, verify_ed25519_signature};
use integrity_seam::{Purpose, PurposeSigner, SignError};

const SCOPE: [u8; 32] = [7; 32];

#[tokio::test]
async fn a_signature_verifies_under_the_published_key() {
    let signer = KeyFileSigner::from_key_bytes([(Purpose::Attestation, vec![1; 32])]).unwrap();
    let published = signer.keys(Purpose::Attestation).await.unwrap();
    let signed = signer
        .sign(&SCOPE, Purpose::Attestation, b"signing input")
        .await
        .unwrap();

    assert_eq!(signed.kid, published.current.kid);
    assert!(verify_ed25519_signature(
        published.current.public_key,
        b"signing input",
        signed.signature
    ));
    assert!(!verify_ed25519_signature(
        published.current.public_key,
        b"another input",
        signed.signature
    ));
}

#[tokio::test]
async fn a_rotation_publishes_the_previous_key_beside_the_current_one() {
    let old = KeyFileSigner::from_key_bytes([(Purpose::Attestation, vec![1; 32])]).unwrap();
    let old_public = old.keys(Purpose::Attestation).await.unwrap().current;
    let mut rotated_file = vec![2; 32];
    rotated_file.extend_from_slice(&old_public.public_key);
    let rotated = KeyFileSigner::from_key_bytes([(Purpose::Attestation, rotated_file)]).unwrap();

    let keys = rotated.keys(Purpose::Attestation).await.unwrap();
    assert_eq!(keys.previous, Some(old_public.clone()));
    assert_ne!(keys.current.kid, old_public.kid);
    let signed = rotated
        .sign(&SCOPE, Purpose::Attestation, b"x")
        .await
        .unwrap();
    assert_eq!(signed.kid, keys.current.kid, "only the current key signs");
}

#[tokio::test]
async fn a_purpose_without_a_key_does_not_sign() {
    let signer = KeyFileSigner::from_key_bytes(std::iter::empty()).unwrap();
    assert_eq!(
        signer.sign(&SCOPE, Purpose::Attestation, b"x").await,
        Err(SignError::NoKey(Purpose::Attestation))
    );
}

#[tokio::test]
async fn malformed_key_files_are_refused() {
    for bytes in [vec![], vec![1; 31], vec![1; 33], vec![1; 65]] {
        assert!(KeyFileSigner::from_key_bytes([(Purpose::Attestation, bytes)]).is_err());
    }
    // The previous key may not equal the current key.
    let current = KeyFileSigner::from_key_bytes([(Purpose::Attestation, vec![3; 32])]).unwrap();
    let mut file = vec![3; 32];
    file.extend_from_slice(
        &current
            .keys(Purpose::Attestation)
            .await
            .unwrap()
            .current
            .public_key,
    );
    assert!(KeyFileSigner::from_key_bytes([(Purpose::Attestation, file)]).is_err());
    // One purpose cannot be given two keys.
    assert!(
        KeyFileSigner::from_key_bytes([
            (Purpose::Attestation, vec![1; 32]),
            (Purpose::Attestation, vec![2; 32]),
        ])
        .is_err()
    );
}

#[test]
fn the_debug_form_shows_no_key_material() {
    let signer = KeyFileSigner::from_key_bytes([(Purpose::Attestation, vec![0xAB; 32])]).unwrap();
    let shown = format!("{signer:?}");
    assert!(!shown.contains("171") && !shown.to_lowercase().contains("abab"));
}

#[test]
fn no_current_or_previous_key_can_serve_two_purposes() {
    let public = |seed| {
        KeyFileSigner::from_key_bytes([(Purpose::Seal, vec![seed; 32])])
            .unwrap()
            .public_keys(Purpose::Seal)
            .unwrap()
            .current
            .public_key
    };
    for (first_previous, second_previous) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let mut first = vec![if first_previous { 2 } else { 1 }; 32];
        let mut second = vec![if second_previous { 3 } else { 1 }; 32];
        if first_previous {
            first.extend_from_slice(&public(1));
        }
        if second_previous {
            second.extend_from_slice(&public(1));
        }
        assert!(
            KeyFileSigner::from_key_bytes(
                [(Purpose::Attestation, first), (Purpose::Seal, second),]
            )
            .is_err(),
            "current/previous reuse {first_previous}/{second_previous}"
        );
    }
}

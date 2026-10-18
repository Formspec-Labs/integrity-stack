use super::*;

const EXPORT: &[u8] = include_bytes!(
    "../../../../../../trellis/fixtures/vectors/export/001-two-event-chain/expected-export.zip"
);
const SIGNER_KEY: &[u8] =
    include_bytes!("../../../../../../trellis/fixtures/vectors/_keys/issuer-001.cose_key");
const OTHER_KEY: &[u8] =
    include_bytes!("../../../../../../trellis/fixtures/vectors/_keys/issuer-002.cose_key");

fn public_key(cose_key: &[u8]) -> [u8; 32] {
    trellis_cddl::parse_ed25519_cose_key(cose_key)
        .expect("fixture key")
        .public_key
}

fn head_checkpoint_digest(zip: &[u8]) -> [u8; 32] {
    export_head_checkpoint_digest(zip).expect("head")
}

/// One key set pinned for both purposes, as a single-key deployment's two history files are.
fn both(keys: PinnedSigningKeys) -> PinnedTrellisKeys {
    PinnedTrellisKeys::new(keys.clone(), keys)
}

#[test]
fn an_export_signed_by_a_pinned_key_is_accepted_at_its_head_checkpoint() {
    let pinned = both(PinnedSigningKeys::from_public_keys([
        public_key(OTHER_KEY),
        public_key(SIGNER_KEY),
    ]));
    assert_eq!(check_pinned_signers(EXPORT, &pinned, None), Ok(()));
    assert_eq!(
        check_pinned_signers(EXPORT, &pinned, Some(head_checkpoint_digest(EXPORT))),
        Ok(())
    );
}

#[test]
fn an_export_citing_a_key_outside_the_pinned_history_is_refused() {
    let pinned = both(PinnedSigningKeys::from_public_keys([public_key(OTHER_KEY)]));
    assert_eq!(
        check_pinned_signers(EXPORT, &pinned, None),
        Err(PinnedExportRefusal::UnpinnedSigner)
    );
}

#[test]
fn a_key_pinned_for_one_purpose_does_not_vouch_for_the_other() {
    // The fixture signs its events, checkpoints and manifest with one key.
    let signer = PinnedSigningKeys::from_public_keys([public_key(SIGNER_KEY)]);
    let other = PinnedSigningKeys::from_public_keys([public_key(OTHER_KEY)]);
    for pinned in [
        // The signer pinned only as a Manifest key: the events cite no Ledger key.
        PinnedTrellisKeys::new(other.clone(), signer.clone()),
        // The signer pinned only as a Ledger key: the manifest cites no Manifest key.
        PinnedTrellisKeys::new(signer, other),
    ] {
        assert_eq!(
            check_pinned_signers(EXPORT, &pinned, None),
            Err(PinnedExportRefusal::UnpinnedSigner)
        );
    }
}

#[test]
fn an_export_at_another_head_checkpoint_is_refused() {
    let pinned = both(PinnedSigningKeys::from_public_keys([public_key(SIGNER_KEY)]));
    assert_eq!(
        check_pinned_signers(EXPORT, &pinned, Some([7; 32])),
        Err(PinnedExportRefusal::HeadCheckpointDiffers)
    );
}

#[test]
fn a_history_file_pins_the_public_key_of_every_row() {
    let row = |key: &[u8]| serde_json::json!({"public_key": hex(&public_key(key)), "valid_from_unix_secs": 0});
    let json = serde_json::to_vec(&serde_json::json!([row(OTHER_KEY), row(SIGNER_KEY)])).unwrap();
    let pinned = PinnedTrellisKeys::from_history_json(&json, &json).expect("histories");
    assert_eq!(check_pinned_signers(EXPORT, &pinned, None), Ok(()));
    assert!(PinnedTrellisKeys::from_history_json(&json, b"[]").is_err());
    assert!(PinnedSigningKeys::from_history_json(b"[]").is_err());
    assert!(PinnedSigningKeys::from_history_json(br#"[{"public_key":"zz"}]"#).is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

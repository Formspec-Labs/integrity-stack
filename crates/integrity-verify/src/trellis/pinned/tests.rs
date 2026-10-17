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

#[test]
fn an_export_signed_by_a_pinned_key_is_accepted_at_its_head_checkpoint() {
    let pinned =
        PinnedSigningKeys::from_public_keys([public_key(OTHER_KEY), public_key(SIGNER_KEY)]);
    assert_eq!(check_pinned_signers(EXPORT, &pinned, None), Ok(()));
    assert_eq!(
        check_pinned_signers(EXPORT, &pinned, Some(head_checkpoint_digest(EXPORT))),
        Ok(())
    );
}

#[test]
fn an_export_citing_a_key_outside_the_pinned_history_is_refused() {
    let pinned = PinnedSigningKeys::from_public_keys([public_key(OTHER_KEY)]);
    assert_eq!(
        check_pinned_signers(EXPORT, &pinned, None),
        Err(PinnedExportRefusal::UnpinnedSigner)
    );
}

#[test]
fn an_export_at_another_head_checkpoint_is_refused() {
    let pinned = PinnedSigningKeys::from_public_keys([public_key(SIGNER_KEY)]);
    assert_eq!(
        check_pinned_signers(EXPORT, &pinned, Some([7; 32])),
        Err(PinnedExportRefusal::HeadCheckpointDiffers)
    );
}

#[test]
fn a_history_file_pins_the_public_key_of_every_row() {
    let row = |key: &[u8]| serde_json::json!({"public_key": hex(&public_key(key)), "valid_from_unix_secs": 0});
    let json = serde_json::to_vec(&serde_json::json!([row(OTHER_KEY), row(SIGNER_KEY)])).unwrap();
    let pinned = PinnedSigningKeys::from_history_json(&json).expect("history");
    assert_eq!(check_pinned_signers(EXPORT, &pinned, None), Ok(()));
    assert!(PinnedSigningKeys::from_history_json(b"[]").is_err());
    assert!(PinnedSigningKeys::from_history_json(br#"[{"public_key":"zz"}]"#).is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

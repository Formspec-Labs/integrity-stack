// Rust guideline compliant 2026-02-21

//! Issuing through the purpose signer changes who signs, never what is signed.

use integrity_cose::KeyFileSigner;
use integrity_disclosure::{
    Encoding, ErrorCode, IssuanceSalts, IssueParams, IssuerPin, VerifyOptions, issue, issue_signed,
    verify,
};
use integrity_seam::{OsSecureRandom, Purpose, PurposeSigner};
use serde_json::{Map, json};

const SEED: [u8; 32] = [5; 32];
const SCOPE: [u8; 32] = [9; 32];
const TYP: &str = "example+sd-jwt";

fn claims() -> Vec<(String, serde_json::Value)> {
    vec![
        ("name".into(), json!("Ada")),
        ("income".into(), json!(42000)),
    ]
}

fn params(kid: &str) -> IssueParams {
    IssueParams {
        iss: "https://issuer.example/t1".into(),
        kid: kid.into(),
        typ: TYP.into(),
        public_claims: Map::new(),
    }
}

#[test]
fn the_purpose_signer_issues_what_the_seed_would_and_the_pinned_key_verifies_it() {
    let signer = KeyFileSigner::from_key_bytes([(Purpose::Attestation, SEED.to_vec())]).unwrap();
    let current = signer.keys(Purpose::Attestation).unwrap().current;
    let salts = IssuanceSalts::generate(&OsSecureRandom, &["income", "name"]).unwrap();
    let params = params(&current.kid);

    let by_signer = issue_signed(
        &params,
        &claims(),
        &salts,
        &signer,
        &SCOPE,
        Purpose::Attestation,
    )
    .unwrap();
    let by_seed = issue(&params, &claims(), &salts, &SEED).unwrap();
    assert_eq!(by_signer, by_seed);

    let pin = IssuerPin {
        iss: params.iss.clone(),
        kid: current.kid,
        public_key: current.public_key,
    };
    let options = VerifyOptions {
        expected_typ: TYP,
        encoding: Encoding::Pinned,
    };
    let verified = verify(&by_signer.present(&["name"]).unwrap(), &[pin], &options).unwrap();
    assert_eq!(verified.disclosed.len(), 1);
}

#[test]
fn a_header_kid_the_signer_did_not_sign_under_is_refused() {
    let signer = KeyFileSigner::from_key_bytes([(Purpose::Attestation, SEED.to_vec())]).unwrap();
    let salts = IssuanceSalts::generate(&OsSecureRandom, &["income", "name"]).unwrap();
    let error = issue_signed(
        &params("some-other-kid"),
        &claims(),
        &salts,
        &signer,
        &SCOPE,
        Purpose::Attestation,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Signer);
}

// Rust guideline compliant 2026-02-21

//! Signing outside the crate changes who signs, never what is signed.

use integrity_cose::{KeyFileSigner, sign_ed25519};
use integrity_disclosure::{
    Encoding, IssuanceSalts, IssueParams, IssuerPin, VerifyOptions, issue, prepare, verify,
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

#[tokio::test]
async fn a_port_signed_issuance_is_what_the_seed_would_issue_and_the_pinned_key_verifies_it() {
    let signer = KeyFileSigner::from_key_bytes([(Purpose::Attestation, SEED.to_vec())]).unwrap();
    let current = signer.keys(Purpose::Attestation).await.unwrap().current;
    let salts = IssuanceSalts::generate(&OsSecureRandom, &["income", "name"]).unwrap();
    let params = params(&current.kid);

    let prepared = prepare(&params, &claims(), &salts).unwrap();
    let signed = signer
        .sign(&SCOPE, Purpose::Attestation, prepared.signing_input())
        .await
        .unwrap();
    assert_eq!(signed.kid, current.kid);
    assert_eq!(
        signed.signature,
        sign_ed25519(SEED, prepared.signing_input())
    );
    let assembled = prepared.assemble(&signed.signature).unwrap();
    assert_eq!(assembled, issue(&params, &claims(), &salts, &SEED).unwrap());

    let pin = IssuerPin {
        iss: params.iss.clone(),
        kid: current.kid,
        public_key: current.public_key,
    };
    let options = VerifyOptions {
        expected_typ: TYP,
        encoding: Encoding::Pinned,
    };
    let verified = verify(&assembled.present(&["name"]).unwrap(), &[pin], &options).unwrap();
    assert_eq!(verified.disclosed.len(), 1);
}

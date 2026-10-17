// Rust guideline compliant 2026-02-21

//! `check_claims` answers "can these be issued" without salts, and agrees with the builder.

use integrity_disclosure::{
    ErrorCode, IssuanceSalts, MAX_CLAIMS, MAX_PATH_BYTES, build_disclosures, check_claims,
};
use integrity_seam::OsSecureRandom;
use serde_json::json;

fn claims(paths: &[String]) -> Vec<(String, serde_json::Value)> {
    paths.iter().map(|p| (p.clone(), json!(1))).collect()
}

#[test]
fn it_accepts_what_the_builder_accepts_and_refuses_what_it_refuses() {
    let fine = claims(&["data.a".into(), "data.b".into()]);
    check_claims(&fine).unwrap();
    let salts = IssuanceSalts::generate(&OsSecureRandom, &["data.a", "data.b"]).unwrap();
    build_disclosures(&fine, &salts).unwrap();

    let too_long = claims(&["x".repeat(MAX_PATH_BYTES + 1)]);
    let too_many: Vec<_> = (0..=MAX_CLAIMS)
        .map(|i| (format!("k{i}"), json!(i)))
        .collect();
    let duplicate = claims(&["a".into(), "a".into()]);
    for bad in [too_long, too_many, duplicate, Vec::new()] {
        assert_eq!(
            check_claims(&bad).unwrap_err().code(),
            ErrorCode::InvalidClaims
        );
    }
}

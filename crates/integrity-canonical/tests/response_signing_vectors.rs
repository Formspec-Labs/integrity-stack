// Rust guideline compliant 2026-02-21
//! Shared whole-Response signing vectors, independently generated with Python JCS and exact Decimal numbers.

use integrity_canonical::{
    DigestAlgorithm, canonical_response_signed_payload_bytes_from_json, compute_digest,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/response-signing/vectors.json"
    ))
    .expect("shared fixture must be valid JSON")
}

#[test]
fn signing_bytes_and_sha256_match_independent_shared_vectors() {
    let vectors = fixture();
    for vector in vectors["valid"].as_array().expect("valid vector array") {
        for input in vector["inputJson"].as_array().expect("input variant array") {
            let input = input.as_str().expect("JSON text");
            let bytes = canonical_response_signed_payload_bytes_from_json(input.as_bytes())
                .expect("signing bytes");
            assert_eq!(hex::encode(&bytes), vector["bytesHex"].as_str().unwrap());
            assert_eq!(
                compute_digest(&bytes, DigestAlgorithm::Sha256),
                vector["sha256"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn invalid_wire_values_never_produce_signing_bytes() {
    let vectors = fixture();
    for vector in vectors["invalid"].as_array().expect("invalid vector array") {
        let input = vector["inputJson"].as_str().expect("JSON text");
        assert!(
            canonical_response_signed_payload_bytes_from_json(input.as_bytes()).is_err(),
            "invalid vector {} must not produce bytes",
            vector["name"]
        );
    }
}

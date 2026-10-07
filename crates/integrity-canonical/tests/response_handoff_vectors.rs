// Rust guideline compliant 2026-02-21
//! Shared full-Response handoff vectors, independently generated with Python JCS.

use integrity_canonical::{DigestAlgorithm, canonical_response_handoff_bytes, compute_digest};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/response-handoff/vectors.json"
    ))
    .expect("shared fixture must be valid JSON")
}

#[test]
fn handoff_bytes_and_sha256_match_independent_shared_vectors() {
    let vectors = fixture();
    for vector in vectors["valid"].as_array().expect("valid vector array") {
        for input in vector["inputJson"].as_array().expect("input variant array") {
            let response: Value = serde_json::from_str(input.as_str().expect("JSON text"))
                .expect("valid Response object");
            let bytes = canonical_response_handoff_bytes(&response).expect("handoff bytes");
            assert_eq!(hex::encode(&bytes), vector["bytesHex"].as_str().unwrap());
            assert_eq!(
                compute_digest(&bytes, DigestAlgorithm::Sha256),
                vector["sha256"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn invalid_wire_values_never_produce_handoff_bytes() {
    let vectors = fixture();
    for vector in vectors["invalid"].as_array().expect("invalid vector array") {
        let input = vector["inputJson"].as_str().expect("JSON text");
        if let Ok(response) = serde_json::from_str::<Value>(input) {
            assert!(
                canonical_response_handoff_bytes(&response).is_err(),
                "invalid vector {} must not produce bytes",
                vector["name"]
            );
        }
    }
}

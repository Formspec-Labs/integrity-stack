use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use integrity_cose::default_async_sign;
use integrity_seam::{SealRequest, default_seal_input};

#[tokio::test]
async fn round_trip_via_cose_sign1() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let req = SealRequest {
        domain: "wos.case_event/v1".into(),
        payload: serde_json::json!({"x":1}),
        kid_input: sk.verifying_key().to_bytes(),
    };

    let input = default_seal_input(&req).unwrap();
    assert_eq!(
        input.kid,
        hex::encode(integrity_cose::derive_kid(
            integrity_cose::SUITE_ID_PHASE_1,
            sk.verifying_key().to_bytes()
        ))
    );

    let envelope = default_async_sign(&input, &sk).await.unwrap();
    let bytes = STANDARD.decode(&envelope.cose_sign1_b64).unwrap();
    let decoded = integrity_cose::decode_cose_sign1(&bytes).unwrap();
    let kid = hex::decode(&envelope.kid).unwrap();

    assert!(
        integrity_cose::verify_ed25519_sign1(sk.verifying_key().to_bytes(), &bytes, None).unwrap()
    );
    assert_eq!(decoded.kid(), Some(kid.as_slice()));
}

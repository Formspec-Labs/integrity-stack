use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use integrity_cose::default_async_sign;
use integrity_seam::{KidInput, SealRequest, default_seal_input};

#[tokio::test]
async fn round_trip_via_cose_sign1() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let req = SealRequest {
        domain: "wos.case_event/v1".into(),
        payload: serde_json::json!({"x":1}),
        kid_input: KidInput::Phase1Ed25519(sk.verifying_key().to_bytes()),
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

struct RecordingSigner {
    inner: integrity_cose::KeyFileSigner,
    calls: std::sync::Mutex<Vec<([u8; 32], integrity_seam::Purpose, Vec<u8>)>>,
    mode: u8,
}
#[async_trait::async_trait]
impl integrity_seam::PurposeSigner for RecordingSigner {
    async fn sign(
        &self,
        scope: &[u8; 32],
        purpose: integrity_seam::Purpose,
        input: &[u8],
    ) -> Result<integrity_seam::Signed, integrity_seam::SignError> {
        self.calls
            .lock()
            .unwrap()
            .push((*scope, purpose, input.to_vec()));
        if self.mode == 1 {
            return Err(integrity_seam::SignError::Backend("test failure".into()));
        }
        let mut result = self.inner.sign(scope, purpose, input).await?;
        if self.mode == 2 {
            result.kid = "wrong-key".into();
        }
        Ok(result)
    }
    async fn keys(
        &self,
        purpose: integrity_seam::Purpose,
    ) -> Result<integrity_seam::PurposeKeys, integrity_seam::SignError> {
        self.inner.keys(purpose).await
    }
}

#[tokio::test]
async fn purpose_seal_preserves_bytes_scope_and_failure_refusals() {
    let sk = SigningKey::from_bytes(&[7; 32]);
    let input = default_seal_input(&SealRequest {
        domain: "formspec.signature/v1".into(),
        payload: serde_json::json!({"answer": 42}),
        kid_input: KidInput::Phase1Ed25519(sk.verifying_key().to_bytes()),
    })
    .unwrap();
    let scope = [0x73; 32];
    for mode in 0..3 {
        let signer = RecordingSigner {
            inner: integrity_cose::KeyFileSigner::from_key_bytes([(
                integrity_seam::Purpose::Seal,
                vec![7; 32],
            )])
            .unwrap(),
            calls: std::sync::Mutex::new(Vec::new()),
            mode,
        };
        let result = integrity_cose::purpose_async_sign(&input, &signer, &scope).await;
        if mode == 0 {
            let actual = result.unwrap();
            let expected = default_async_sign(&input, &sk).await.unwrap();
            assert_eq!(actual.cose_sign1_b64, expected.cose_sign1_b64);
            assert_eq!(actual.canonical_event_hash, expected.canonical_event_hash);
        } else {
            assert!(result.is_err());
        }
        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, scope);
        assert_eq!(calls[0].1, integrity_seam::Purpose::Seal);
        let protected = integrity_cose::protected_header_bytes(integrity_cose::derive_kid(
            1,
            sk.verifying_key().to_bytes(),
        ));
        assert_eq!(
            calls[0].2,
            integrity_cose::sig_structure_bytes(&protected, &input.domain_separated_bytes)
        );
    }
}

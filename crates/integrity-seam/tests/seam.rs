use integrity_seam::{KidInput, SealRequest, default_seal_input};
use proptest::prelude::*;

#[test]
fn build_seal_input_is_deterministic() {
    let req = SealRequest {
        domain: "wos.case_event/v1".into(),
        payload: serde_json::json!({"case_id":"C-1","phase":"submit"}),
        kid_input: KidInput::Phase1Ed25519([7u8; 32]),
    };

    let a = default_seal_input(&req).unwrap();
    let b = default_seal_input(&req).unwrap();

    assert_eq!(a.canonical_event_hash, b.canonical_event_hash);
    assert_eq!(a.domain_separated_bytes, b.domain_separated_bytes);
    assert_eq!(a.kid, b.kid);
}

proptest! {
    #[test]
    fn key_order_invariant(keys in proptest::collection::vec("[a-z]{1,5}", 1..10)) {
        let unique = keys.iter().collect::<std::collections::BTreeSet<_>>();
        prop_assume!(unique.len() == keys.len());

        let mut o1 = serde_json::Map::new();
        let mut o2 = serde_json::Map::new();
        for (i, key) in keys.iter().enumerate() {
            o1.insert(key.clone(), serde_json::Value::from(i as u64));
        }
        for (i, key) in keys.iter().rev().enumerate() {
            o2.insert(key.clone(), serde_json::Value::from((keys.len() - 1 - i) as u64));
        }
        prop_assume!(o1.len() == o2.len());

        let a = default_seal_input(&SealRequest {
            domain: "d".into(),
            payload: serde_json::Value::Object(o1),
            kid_input: KidInput::Phase1Ed25519([0u8; 32]),
        }).unwrap();
        let b = default_seal_input(&SealRequest {
            domain: "d".into(),
            payload: serde_json::Value::Object(o2),
            kid_input: KidInput::Phase1Ed25519([0u8; 32]),
        }).unwrap();

        prop_assert_eq!(a.canonical_event_hash, b.canonical_event_hash);
    }
}

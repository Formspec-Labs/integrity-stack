use integrity_seam::{OsSecureRandom, SecureRandom};

#[test]
fn os_secure_random_fills_unique_bytes() {
    let rng = OsSecureRandom;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];

    rng.fill_bytes(&mut a).unwrap();
    rng.fill_bytes(&mut b).unwrap();

    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn object_safe() {
    let rng: Box<dyn SecureRandom> = Box::new(OsSecureRandom);
    let mut buf = [0u8; 16];

    rng.fill_bytes(&mut buf).unwrap();
}

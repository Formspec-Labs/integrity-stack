#![no_main]

use integrity_cose::{SUITE_ID_PHASE_1, decode_protected_header};
use libfuzzer_sys::fuzz_target;

const MAX_PROTECTED_HEADER_FUZZ_LEN: usize = 128;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = decode_substrate_protected_header(data) else {
        return;
    };

    assert!(header.kid.is_some());
    assert!(header.suite_id.is_some());
    assert!(matches!(
        header.artifact_type.as_deref(),
        Some("event" | "checkpoint" | "manifest")
    ));
    assert!(header.method_uri.is_none());
});

fn decode_substrate_protected_header(
    data: &[u8],
) -> Result<integrity_cose::ProtectedHeader, ()> {
    if data.len() > MAX_PROTECTED_HEADER_FUZZ_LEN {
        return Err(());
    }
    if data.first() != Some(&0xa4) {
        return Err(());
    }
    let header = decode_protected_header(data).map_err(|_| ())?;
    if header.alg != -8
        || header.kid.is_none()
        || header.suite_id != Some(SUITE_ID_PHASE_1)
        || header.method_uri.is_some()
    {
        return Err(());
    }
    match header.artifact_type.as_deref() {
        Some("event" | "checkpoint" | "manifest") => Ok(header),
        _ => Err(()),
    }
}

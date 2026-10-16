// Rust guideline compliant 2026-02-21

//! Properties of SD-JWT issue, present and verify. Test names state the property proved.
//!
//! The cross-language vectors in `tests/fixtures/selective-disclosure/vectors.json` are generated
//! here (`INTEGRITY_DISCLOSURE_REGEN=1`) and compared on every run; the TypeScript package checks
//! the same file.

#![allow(
    clippy::cloned_ref_to_slice_refs,
    reason = "vector builders read better with owned one-element slices"
)]

use std::collections::HashSet;
use std::error::Error;
use std::sync::atomic::{AtomicU8, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use integrity_canonical::canonical_json_bytes;
use integrity_cose::sign_ed25519;
use integrity_disclosure::{
    Encoding, ErrorCode, IssuanceSalts, IssueParams, Issued, IssuerPin, MAX_DISCLOSURES,
    MAX_PRESENTATION_BYTES, REFUSED_CLAIM_NAMES, SALT_BYTES, VerifyOptions, build_disclosures,
    disclosure_digest, issue, issue_with_random, padded_digest_count, present, verify,
};
use integrity_seam::{OsSecureRandom, SecureRandom};
use serde_json::{Map, Value, json};

const TYP: &str = "formspec-response+sd-jwt";
const ISS: &str = "https://formspec.example/t/acme/w/main/e/prod";
const KID: &str = "att-2026-10";

// RFC 8032 section 7.1 test vectors 1 and 2: the current and the rotated issuer keys.
const SEED_1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PK_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SEED_2: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const PK_2: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

fn hex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn jcs(value: &Value) -> String {
    String::from_utf8(canonical_json_bytes(value).unwrap()).unwrap()
}

/// Counter-driven entropy: distinct, reproducible salts for vectors.
struct CountingRandom(AtomicU8);

impl SecureRandom for CountingRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        for byte in dest {
            *byte = self.0.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

fn params(kid: &str) -> IssueParams {
    let mut public_claims = Map::new();
    public_claims.insert(
        "definition".into(),
        json!({"url": "https://forms.example/intake", "version": "1.2.0", "hash": "sha256:abc"}),
    );
    public_claims.insert("accepted_at".into(), json!("2026-10-16T12:00:00Z"));
    IssueParams {
        iss: ISS.into(),
        kid: kid.into(),
        typ: TYP.into(),
        public_claims,
    }
}

fn pin(kid: &str, key_hex: &str) -> IssuerPin {
    IssuerPin {
        iss: ISS.into(),
        kid: kid.into(),
        public_key: hex32(key_hex),
    }
}

fn pinned() -> VerifyOptions<'static> {
    VerifyOptions {
        expected_typ: TYP,
        encoding: Encoding::Pinned,
    }
}

fn lenient() -> VerifyOptions<'static> {
    VerifyOptions {
        expected_typ: TYP,
        encoding: Encoding::Rfc9901,
    }
}

fn claims_a() -> Vec<(String, Value)> {
    // Deliberately unsorted. Includes the numbers where JCS differs from naive printing, names that
    // are hazards in JavaScript objects, and two paths whose UTF-8 and UTF-16 orders disagree.
    let text = r#"[
      ["applicant.name", "Zoë Müller"],
      ["household[1].income", 42000.5],
      ["household[0].income", 100],
      ["applicant.ssn_last4", "1234"],
      ["attachment.id", {"size": 1024, "mediaType": "application/pdf", "hash": "sha256:ab"}],
      ["n.big", 1e21],
      ["n.tiny", 4.5e-7],
      ["n.negzero", -0.0],
      ["n.unit", 1.0],
      ["flag", true],
      ["nothing", null],
      ["list", [1, "a", {"b": []}]],
      ["toJSON", "proto"],
      ["prototype", "ctor"],
      ["￿", "bmp-high"],
      ["😀", "astral"]
    ]"#;
    let items: Vec<(String, Value)> = serde_json::from_str(text).unwrap();
    items
}

fn claims_b() -> Vec<(String, Value)> {
    vec![
        ("applicant.name".into(), json!("Other Person")),
        ("applicant.ssn_last4".into(), json!("9999")),
        ("flag".into(), json!(false)),
    ]
}

fn issue_a(kid: &str, seed: &str) -> (Issued, IssuanceSalts) {
    let rng = CountingRandom(AtomicU8::new(1));
    issue_with_random(&params(kid), &claims_a(), &rng, &hex32(seed)).unwrap()
}

fn all_paths(claims: &[(String, Value)]) -> Vec<&str> {
    claims.iter().map(|(p, _)| p.as_str()).collect()
}

/// Splits `jwt~d1~...~` into the JWT and its disclosures.
fn split(presentation: &str) -> (String, Vec<String>) {
    let mut parts: Vec<&str> = presentation.split('~').collect();
    assert_eq!(parts.pop(), Some(""));
    let jwt = parts.remove(0).to_owned();
    (jwt, parts.into_iter().map(str::to_owned).collect())
}

fn join(jwt: &str, disclosures: &[String]) -> String {
    let mut out = format!("{jwt}~");
    for disclosure in disclosures {
        out.push_str(disclosure);
        out.push('~');
    }
    out
}

/// Signs arbitrary header and payload text with a seed: for crafting hostile credentials.
fn sign_raw(seed: &str, header: &str, payload: &str) -> String {
    let input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
    let signature = sign_ed25519(hex32(seed), input.as_bytes());
    format!("{input}.{}", b64(&signature))
}

fn header_text(kid: &str) -> String {
    format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"{TYP}"}}"#)
}

/// A salt string of 16 distinct bytes seeded by `n`.
fn salt(n: u8) -> String {
    b64(&[n; SALT_BYTES])
}

fn disc(salt: &str, path: &str, value: &Value) -> String {
    b64(jcs(&json!([salt, path, value])).as_bytes())
}

/// A signed credential over `_sd` digests of exactly `disclosures` (plus `extra_payload`).
fn crafted(seed: &str, disclosures: &[String], extra_payload: &str) -> String {
    let digests: Vec<String> = disclosures.iter().map(|d| disclosure_digest(d)).collect();
    crafted_with_digests(seed, &digests, extra_payload)
}

fn crafted_with_digests(seed: &str, digests: &[String], extra_payload: &str) -> String {
    let mut sorted = digests.to_vec();
    sorted.sort();
    let sd = serde_json::to_string(&sorted).unwrap();
    let payload = format!(r#"{{"_sd":{sd},"_sd_alg":"sha-256","iss":"{ISS}"{extra_payload}}}"#);
    // The payload is already key-sorted when extra members sort after "iss".
    sign_raw(seed, &header_text(KID), &payload)
}

fn code(result: Result<impl std::fmt::Debug, integrity_disclosure::DisclosureError>) -> ErrorCode {
    result.unwrap_err().code()
}

fn pins_current() -> Vec<IssuerPin> {
    vec![pin(KID, PK_1)]
}

// ---------------------------------------------------------------- issue, present, verify

#[test]
fn an_issued_presentation_verifies_offline_against_the_pinned_key() {
    let (issued, _) = issue_a(KID, SEED_1);
    let paths = ["applicant.name", "household[0].income"];
    let verified = verify(&issued.present(&paths).unwrap(), &pins_current(), &pinned()).unwrap();
    assert_eq!(verified.iss, ISS);
    assert_eq!(verified.kid, KID);
    assert_eq!(
        verified.public_claims["accepted_at"],
        json!("2026-10-16T12:00:00Z")
    );
    let disclosed: Vec<(&str, &str)> = verified
        .disclosed
        .iter()
        .map(|c| (c.path.as_str(), c.value_jcs.as_str()))
        .collect();
    assert_eq!(
        disclosed,
        [
            ("applicant.name", "\"Zoë Müller\""),
            ("household[0].income", "100")
        ]
    );
}

#[test]
fn a_presentation_holds_only_allowlisted_values_and_no_aggregate_hash() {
    let (issued, _) = issue_a(KID, SEED_1);
    let presentation = issued.present(&["applicant.name"]).unwrap();
    // Decode every segment; no withheld value, path or salt may appear in any of them.
    let (jwt, disclosures) = split(&presentation);
    let mut text = String::new();
    for segment in jwt
        .split('.')
        .take(2)
        .chain(disclosures.iter().map(String::as_str))
    {
        text.push_str(&String::from_utf8(URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap());
        text.push('\n');
    }
    for withheld in [
        "1234",
        "42000.5",
        "household",
        "ssn_last4",
        "proto",
        "astral",
    ] {
        assert!(!text.contains(withheld), "{withheld} leaked");
    }
    assert!(!text.contains("responseHash") && !text.contains("response_hash"));
    assert_eq!(disclosures.len(), 1);
}

#[test]
fn presenting_nothing_discloses_nothing_and_still_verifies() {
    let (issued, _) = issue_a(KID, SEED_1);
    let presentation = issued.present(&[]).unwrap();
    assert_eq!(presentation, format!("{}~", issued.jwt));
    assert!(
        verify(&presentation, &pins_current(), &pinned())
            .unwrap()
            .disclosed
            .is_empty()
    );
}

#[test]
fn the_digest_list_is_padded_to_a_power_of_two_with_decoys() {
    for claims in 1..=9usize {
        let list: Vec<(String, Value)> = (0..claims).map(|i| (format!("f{i}"), json!(i))).collect();
        let rng = CountingRandom(AtomicU8::new(0));
        let (issued, salts) = issue_with_random(&params(KID), &list, &rng, &hex32(SEED_1)).unwrap();
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(issued.jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let sd = payload["_sd"].as_array().unwrap();
        assert_eq!(sd.len(), claims.next_power_of_two(), "{claims} claims");
        assert_eq!(sd.len(), padded_digest_count(claims));
        assert_eq!(salts.decoys.len(), sd.len() - claims);
        let digests: Vec<&str> = sd.iter().map(|d| d.as_str().unwrap()).collect();
        assert!(digests.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
    }
}

#[test]
fn every_salt_is_128_bits_and_all_salts_are_distinct() {
    let rng = OsSecureRandom;
    let paths: Vec<String> = (0..64).map(|i| format!("f{i}")).collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let salts = IssuanceSalts::generate(&rng, &refs).unwrap();
    let all: Vec<&String> = salts.claims.values().chain(&salts.decoys).collect();
    assert_eq!(all.len(), 64);
    for salt in &all {
        assert_eq!(URL_SAFE_NO_PAD.decode(salt).unwrap().len(), SALT_BYTES);
    }
    assert_eq!(all.iter().collect::<HashSet<_>>().len(), all.len());
    assert_eq!(SALT_BYTES * 8, 128);
}

#[test]
fn reissue_from_stored_salts_is_byte_identical() {
    let (first, salts) = issue_a(KID, SEED_1);
    let stored = serde_json::to_string(&salts).unwrap();
    let restored: IssuanceSalts = serde_json::from_str(&stored).unwrap();
    let second = issue(&params(KID), &claims_a(), &restored, &hex32(SEED_1)).unwrap();
    assert_eq!(first, second);
}

#[test]
fn rebuilt_disclosures_reproduce_the_committed_digests() {
    let (issued, salts) = issue_a(KID, SEED_1);
    let rebuilt = build_disclosures(&claims_a(), &salts).unwrap();
    assert_eq!(rebuilt, issued.disclosures);
    let (jwt, _) = split(&present(&issued.jwt, &rebuilt, &[]).unwrap());
    assert_eq!(jwt, issued.jwt);
}

#[test]
fn claim_input_order_does_not_change_the_issued_bytes() {
    let (_, salts) = issue_a(KID, SEED_1);
    let mut reversed = claims_a();
    reversed.reverse();
    let forward = issue(&params(KID), &claims_a(), &salts, &hex32(SEED_1)).unwrap();
    let backward = issue(&params(KID), &reversed, &salts, &hex32(SEED_1)).unwrap();
    assert_eq!(forward, backward);
}

#[test]
fn disclosures_are_ordered_by_utf8_bytes_of_the_path() {
    let (issued, _) = issue_a(KID, SEED_1);
    let order: Vec<&str> = issued.disclosures.iter().map(|d| d.path.as_str()).collect();
    let mut sorted = order.clone();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(order, sorted);
    let high = order.iter().position(|p| *p == "\u{ffff}").unwrap();
    let astral = order.iter().position(|p| *p == "\u{1F600}").unwrap();
    assert!(high < astral, "U+FFFF sorts before U+1F600 in UTF-8");
}

#[test]
fn presentation_order_follows_the_issuer_not_the_request() {
    let (issued, _) = issue_a(KID, SEED_1);
    let a = issued.present(&["flag", "applicant.name"]).unwrap();
    let b = issued.present(&["applicant.name", "flag"]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn an_unknown_or_repeated_allowlist_path_is_refused() {
    let (issued, _) = issue_a(KID, SEED_1);
    assert_eq!(code(issued.present(&["nope"])), ErrorCode::UnknownPath);
    assert_eq!(
        code(issued.present(&["flag", "flag"])),
        ErrorCode::DuplicatePath
    );
}

#[test]
fn presenting_refuses_disclosures_that_do_not_belong_to_the_issuer_jwt() {
    let (issued, _) = issue_a(KID, SEED_1);
    let foreign = {
        let rng = CountingRandom(AtomicU8::new(200));
        issue_with_random(&params(KID), &claims_b(), &rng, &hex32(SEED_1))
            .unwrap()
            .0
    };
    assert_eq!(
        code(present(&issued.jwt, &foreign.disclosures, &["flag"])),
        ErrorCode::UnknownDigest
    );
}

// ---------------------------------------------------------------- adversarial verification

#[test]
fn a_tampered_value_is_rejected_as_an_unknown_digest() {
    let (issued, salts) = issue_a(KID, SEED_1);
    let mut forged = claims_a();
    forged[3].1 = json!("9999");
    let fake = build_disclosures(&forged, &salts).unwrap();
    let target = fake
        .iter()
        .find(|d| d.path == "applicant.ssn_last4")
        .unwrap();
    let presentation = join(&issued.jwt, std::slice::from_ref(&target.encoded));
    assert_eq!(
        code(verify(&presentation, &pins_current(), &pinned())),
        ErrorCode::UnknownDigest
    );
}

#[test]
fn a_swapped_salt_is_rejected_as_an_unknown_digest() {
    let (issued, _) = issue_a(KID, SEED_1);
    let real = issued
        .disclosures
        .iter()
        .find(|d| d.path == "flag")
        .unwrap();
    let forged = disc(&salt(77), "flag", &json!(true));
    assert_ne!(forged, real.encoded);
    assert_eq!(
        code(verify(
            &join(&issued.jwt, &[forged]),
            &pins_current(),
            &pinned()
        )),
        ErrorCode::UnknownDigest
    );
}

#[test]
fn a_disclosure_from_another_credential_is_rejected() {
    let (issued, _) = issue_a(KID, SEED_1);
    let rng = CountingRandom(AtomicU8::new(100));
    let (other, _) = issue_with_random(&params(KID), &claims_b(), &rng, &hex32(SEED_1)).unwrap();
    let foreign = other.disclosures[0].encoded.clone();
    assert_eq!(
        code(verify(
            &join(&issued.jwt, &[foreign]),
            &pins_current(),
            &pinned()
        )),
        ErrorCode::UnknownDigest
    );
}

#[test]
fn a_wrong_iss_is_rejected_even_when_the_key_and_kid_match() {
    let (issued, _) = issue_a(KID, SEED_1);
    let other_tenant = IssuerPin {
        iss: "https://formspec.example/t/other/w/main/e/prod".into(),
        ..pin(KID, PK_1)
    };
    assert_eq!(
        code(verify(
            &issued.present(&[]).unwrap(),
            &[other_tenant],
            &pinned()
        )),
        ErrorCode::WrongIssuer
    );
}

#[test]
fn key_rotation_keeps_the_old_kid_valid_under_the_old_pinned_key() {
    let old = issue_a("att-2026-10", SEED_1).0.present(&["flag"]).unwrap();
    let new = issue_a("att-2027-01", SEED_2).0.present(&["flag"]).unwrap();
    let pins = [pin("att-2026-10", PK_1), pin("att-2027-01", PK_2)];
    assert!(verify(&old, &pins, &pinned()).is_ok());
    assert!(verify(&new, &pins, &pinned()).is_ok());
    // A relying party that has only seen the old key rejects the new kid, fail closed.
    assert_eq!(
        code(verify(&new, &pins[..1], &pinned())),
        ErrorCode::UnknownKey
    );
    // The new key's signature under the old kid is a forgery against the old pin.
    let forged = issue_a("att-2026-10", SEED_2).0.present(&["flag"]).unwrap();
    assert_eq!(
        code(verify(&forged, &pins[..1], &pinned())),
        ErrorCode::BadSignature
    );
}

#[test]
fn two_pins_with_the_same_kid_are_ambiguous_and_refused() {
    let (issued, _) = issue_a(KID, SEED_1);
    let pins = [pin(KID, PK_1), pin(KID, PK_2)];
    assert_eq!(
        code(verify(&issued.present(&[]).unwrap(), &pins, &pinned())),
        ErrorCode::AmbiguousPins
    );
}

#[test]
fn editing_the_signed_payload_breaks_the_signature() {
    let (issued, _) = issue_a(KID, SEED_1);
    let mut parts: Vec<String> = issued.jwt.split('.').map(str::to_owned).collect();
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
    parts[1] = b64(payload.replace("2026-10-16", "2026-10-17").as_bytes());
    let forged = format!("{}~", parts.join("."));
    assert_eq!(
        code(verify(&forged, &pins_current(), &pinned())),
        ErrorCode::BadSignature
    );
}

#[test]
fn a_repeated_disclosure_is_rejected() {
    let (issued, _) = issue_a(KID, SEED_1);
    let flag = issued
        .disclosures
        .iter()
        .find(|d| d.path == "flag")
        .unwrap()
        .encoded
        .clone();
    let doubled = join(&issued.jwt, &[flag.clone(), flag]);
    assert_eq!(
        code(verify(&doubled, &pins_current(), &pinned())),
        ErrorCode::DuplicateDisclosure
    );
}

#[test]
fn duplicate_digests_in_the_signed_sd_list_are_rejected() {
    let d = disc(&salt(1), "a", &json!(1));
    let digest = disclosure_digest(&d);
    let jwt = crafted_with_digests(SEED_1, &[digest.clone(), digest], "");
    assert_eq!(
        code(verify(&join(&jwt, &[d]), &pins_current(), &pinned())),
        ErrorCode::DuplicateDigest
    );
}

#[test]
fn two_disclosures_naming_the_same_path_are_rejected() {
    let first = disc(&salt(1), "a", &json!(1));
    let second = disc(&salt(2), "a", &json!(2));
    let jwt = crafted(SEED_1, &[first.clone(), second.clone()], "");
    assert_eq!(
        code(verify(
            &join(&jwt, &[first, second]),
            &pins_current(),
            &pinned()
        )),
        ErrorCode::DuplicatePath
    );
}

#[test]
fn a_path_may_not_shadow_a_payload_claim() {
    for name in ["iss", "accepted_at", "_sd", "_sd_alg", "..."] {
        let d = disc(&salt(1), name, &json!("x"));
        let jwt = crafted(
            SEED_1,
            std::slice::from_ref(&d),
            r#","accepted_at":"2026-10-16T12:00:00Z""#,
        );
        // "accepted_at" sorts before "iss" so the payload above is not JCS; read it leniently.
        assert_eq!(
            code(verify(&join(&jwt, &[d]), &pins_current(), &lenient())),
            ErrorCode::ReservedClaimName,
            "{name}"
        );
    }
}

#[test]
fn issuing_refuses_a_path_that_shadows_a_public_claim() {
    let list = vec![("accepted_at".to_owned(), json!("x"))];
    let rng = CountingRandom(AtomicU8::new(0));
    assert_eq!(
        code(issue_with_random(&params(KID), &list, &rng, &hex32(SEED_1))),
        ErrorCode::ReservedClaimName
    );
}

#[test]
fn nested_structure_keys_in_claims_and_payload_are_refused() {
    let rng = CountingRandom(AtomicU8::new(0));
    for hostile in [json!({"_sd": ["x"]}), json!([{"...": "x"}])] {
        let list = vec![("a".to_owned(), hostile.clone())];
        assert_eq!(
            code(issue_with_random(&params(KID), &list, &rng, &hex32(SEED_1))),
            ErrorCode::InvalidClaims
        );
        let d = disc(&salt(1), "a", &hostile);
        let jwt = crafted(SEED_1, std::slice::from_ref(&d), "");
        assert_eq!(
            code(verify(&join(&jwt, &[d]), &pins_current(), &pinned())),
            ErrorCode::UnsupportedStructure
        );
    }
    let jwt = crafted(SEED_1, &[], r#","zz":{"_sd":[]}"#);
    assert_eq!(
        code(verify(&format!("{jwt}~"), &pins_current(), &pinned())),
        ErrorCode::UnsupportedStructure
    );
}

#[test]
fn key_binding_and_a_missing_trailing_tilde_are_refused() {
    let (issued, _) = issue_a(KID, SEED_1);
    let bare = issued.jwt.clone();
    assert_eq!(
        code(verify(&bare, &pins_current(), &pinned())),
        ErrorCode::MalformedCompact
    );
    let with_kb = format!("{}~{}", issued.present(&[]).unwrap(), issued.jwt);
    assert_eq!(
        code(verify(&with_kb, &pins_current(), &pinned())),
        ErrorCode::MalformedCompact
    );
    // A cnf claim promises key binding this profile cannot check, so it is refused, not ignored.
    let payload = format!(r#"{{"_sd":[],"_sd_alg":"sha-256","cnf":{{"kid":"x"}},"iss":"{ISS}"}}"#);
    let cnf = sign_raw(SEED_1, &header_text(KID), &payload);
    assert_eq!(
        code(verify(&format!("{cnf}~"), &pins_current(), &pinned())),
        ErrorCode::UnsupportedStructure
    );
}

#[test]
fn header_and_algorithm_substitutions_are_refused() {
    let payload = format!(r#"{{"_sd":[],"_sd_alg":"sha-256","iss":"{ISS}"}}"#);
    let cases = [
        r#"{"alg":"none","kid":"att-2026-10","typ":"formspec-response+sd-jwt"}"#,
        r#"{"alg":"ES256","kid":"att-2026-10","typ":"formspec-response+sd-jwt"}"#,
        r#"{"alg":"EdDSA","kid":"att-2026-10","typ":"JWT"}"#,
        r#"{"alg":"EdDSA","kid":"att-2026-10","typ":"formspec-response+sd-jwt","jwk":{}}"#,
        r#"{"alg":"EdDSA","typ":"formspec-response+sd-jwt"}"#,
    ];
    for header in cases {
        let input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
        let sig = sign_ed25519(hex32(SEED_1), input.as_bytes());
        let jwt = format!("{input}.{}", b64(&sig));
        assert_eq!(
            code(verify(&format!("{jwt}~"), &pins_current(), &lenient())),
            ErrorCode::UnsupportedHeader,
            "{header}"
        );
    }
}

#[test]
fn an_sd_alg_other_than_sha_256_is_refused() {
    let payload = format!(r#"{{"_sd":[],"_sd_alg":"sha-512","iss":"{ISS}"}}"#);
    let jwt = sign_raw(SEED_1, &header_text(KID), &payload);
    assert_eq!(
        code(verify(&format!("{jwt}~"), &pins_current(), &pinned())),
        ErrorCode::UnsupportedSdAlg
    );
}

#[test]
fn an_array_element_disclosure_is_refused_as_unsupported() {
    let two = b64(jcs(&json!([salt(1), "x"])).as_bytes());
    let jwt = crafted(SEED_1, std::slice::from_ref(&two), "");
    assert_eq!(
        code(verify(&join(&jwt, &[two]), &pins_current(), &pinned())),
        ErrorCode::UnsupportedStructure
    );
}

#[test]
fn pinned_mode_demands_jcs_and_128_bit_salts_but_rfc_9901_mode_does_not() {
    let spaced = b64(format!(r#"["{}", "a", 1]"#, salt(1)).as_bytes());
    let jwt = crafted(SEED_1, std::slice::from_ref(&spaced), "");
    let presentation = join(&jwt, std::slice::from_ref(&spaced));
    assert_eq!(
        code(verify(&presentation, &pins_current(), &pinned())),
        ErrorCode::NonCanonicalDisclosure
    );
    assert!(verify(&presentation, &pins_current(), &lenient()).is_ok());

    let short = disc(&b64(&[9u8; 8]), "a", &json!(1));
    let jwt = crafted(SEED_1, std::slice::from_ref(&short), "");
    let presentation = join(&jwt, std::slice::from_ref(&short));
    assert_eq!(
        code(verify(&presentation, &pins_current(), &pinned())),
        ErrorCode::WeakSalt
    );
    assert!(verify(&presentation, &pins_current(), &lenient()).is_ok());

    let loose_payload = format!(r#"{{ "_sd": [], "iss": "{ISS}" }}"#);
    let jwt = sign_raw(SEED_1, &header_text(KID), &loose_payload);
    assert_eq!(
        code(verify(&format!("{jwt}~"), &pins_current(), &pinned())),
        ErrorCode::MalformedJson
    );
    assert!(verify(&format!("{jwt}~"), &pins_current(), &lenient()).is_ok());
}

#[test]
fn input_beyond_the_size_bounds_is_refused_before_any_decoding() {
    let huge = "A".repeat(MAX_PRESENTATION_BYTES + 1);
    assert_eq!(
        code(verify(&huge, &pins_current(), &pinned())),
        ErrorCode::InputTooLarge
    );
    let (issued, _) = issue_a(KID, SEED_1);
    let many = format!("{}{}", issued.jwt, "~A".repeat(MAX_DISCLOSURES + 1) + "~");
    assert_eq!(
        code(verify(&many, &pins_current(), &pinned())),
        ErrorCode::InputTooLarge
    );
}

#[test]
fn an_oversized_sd_list_is_refused_and_work_stays_bounded() {
    let digests: Vec<String> = (0..9000)
        .map(|i| disclosure_digest(&i.to_string()))
        .collect();
    let jwt = crafted_with_digests(SEED_1, &digests, "");
    assert_eq!(
        code(verify(&format!("{jwt}~"), &pins_current(), &pinned())),
        ErrorCode::InputTooLarge
    );
}

#[test]
fn deeply_nested_json_is_refused_without_recursing() {
    let nested = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
    let payload = format!(r#"{{"_sd":[],"iss":"{ISS}","zz":{nested}}}"#);
    let jwt = sign_raw(SEED_1, &header_text(KID), &payload);
    assert_eq!(
        code(verify(&format!("{jwt}~"), &pins_current(), &lenient())),
        ErrorCode::MalformedJson
    );
    let deep = (0..40).fold(json!(1), |inner, _| json!([inner]));
    let list = vec![("a".to_owned(), deep)];
    let rng = CountingRandom(AtomicU8::new(0));
    assert_eq!(
        code(issue_with_random(&params(KID), &list, &rng, &hex32(SEED_1))),
        ErrorCode::InvalidClaims
    );
}

#[test]
fn malformed_input_of_every_shape_fails_closed_without_panicking() {
    let (issued, _) = issue_a(KID, SEED_1);
    let good = issued.present(&["flag"]).unwrap();
    let mut inputs: Vec<String> = vec![
        String::new(),
        "~".into(),
        "~~".into(),
        "a.b~".into(),
        "a.b.c~".into(),
        "a.b.c.d~".into(),
        "..~".into(),
        "é~".into(),
        format!("{good} "),
        good.replace('~', "~~"),
    ];
    // Every proper prefix and a flip of every byte position in the JWT must fail or verify; none may panic.
    for cut in 0..good.len() {
        inputs.push(good[..cut].to_owned());
    }
    for (i, original) in good.bytes().enumerate().step_by(7) {
        let mut bytes = good.clone().into_bytes();
        bytes[i] = if original == b'A' { b'B' } else { b'A' };
        inputs.push(String::from_utf8(bytes).unwrap());
    }
    for input in inputs {
        if let Ok(verified) = verify(&input, &pins_current(), &pinned()) {
            assert!(verified.disclosed.len() <= 1);
        }
    }
}

#[test]
fn lone_surrogate_escapes_and_out_of_range_numbers_are_refused() {
    for value_text in [r#""\ud800""#, "1e999"] {
        let d = b64(format!(r#"["{}","a",{value_text}]"#, salt(1)).as_bytes());
        let jwt = crafted(SEED_1, std::slice::from_ref(&d), "");
        assert_eq!(
            code(verify(&join(&jwt, &[d]), &pins_current(), &lenient())),
            ErrorCode::MalformedJson,
            "{value_text}"
        );
    }
}

#[test]
fn issuing_refuses_empty_oversized_duplicate_and_reserved_inputs() {
    let rng = CountingRandom(AtomicU8::new(0));
    let seed = hex32(SEED_1);
    let attempt =
        |list: Vec<(String, Value)>| code(issue_with_random(&params(KID), &list, &rng, &seed));
    assert_eq!(attempt(vec![]), ErrorCode::InvalidClaims);
    assert_eq!(
        attempt(vec![("a".into(), json!(1)), ("a".into(), json!(2))]),
        ErrorCode::InvalidClaims
    );
    assert_eq!(
        attempt(vec![("".into(), json!(1))]),
        ErrorCode::InvalidClaims
    );
    assert_eq!(
        attempt(vec![("_sd".into(), json!(1))]),
        ErrorCode::InvalidClaims
    );
    assert_eq!(
        attempt(vec![("p".repeat(1025), json!(1))]),
        ErrorCode::InvalidClaims
    );
    let too_many = (0..=integrity_disclosure::MAX_CLAIMS)
        .map(|i| (format!("f{i}"), json!(i)))
        .collect();
    assert_eq!(attempt(too_many), ErrorCode::InvalidClaims);
}

#[test]
fn stored_salts_that_do_not_match_the_claims_are_refused() {
    let seed = hex32(SEED_1);
    let rng = CountingRandom(AtomicU8::new(100));
    let (_, mut salts) = issue_with_random(&params(KID), &claims_b(), &rng, &seed).unwrap();
    assert_eq!(salts.decoys.len(), 1, "three claims pad to four digests");
    salts.decoys.pop();
    assert_eq!(
        code(issue(&params(KID), &claims_b(), &salts, &seed)),
        ErrorCode::InvalidSalts
    );
    let (_, mut salts) = issue_a(KID, SEED_1);
    salts.claims.insert("flag".into(), b64(&[1u8; 8]));
    assert_eq!(
        code(issue(&params(KID), &claims_a(), &salts, &seed)),
        ErrorCode::InvalidSalts
    );
    let (_, mut salts) = issue_a(KID, SEED_1);
    let copy = salts.claims["flag"].clone();
    salts.claims.insert("nothing".into(), copy);
    // Equal salts under different paths still give distinct digests; this must verify.
    assert!(issue(&params(KID), &claims_a(), &salts, &seed).is_ok());
}

// ---------------------------------------------------------------- RFC 9901 examples

#[test]
fn rfc_9901_section_4_2_disclosure_and_digest_examples_hold() {
    let disclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    let bytes = URL_SAFE_NO_PAD.decode(disclosure).unwrap();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]"#
    );
    assert_eq!(
        disclosure_digest(disclosure),
        "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
    );
}

#[test]
fn rfc_9901_appendix_a_1_top_level_disclosures_hash_to_the_listed_digests() {
    let cases = [
        (
            concat!(
                "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICI2YzVjMGE0OS1iNTg",
                "5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiXQ"
            ),
            "X6ZAYOII2vPN40V7xExZwVwz7yRmLNcVwt5DL8RLv4g",
        ),
        (
            concat!(
                "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiXHU1OTJ",
                "hXHU5MGNlIl0"
            ),
            "ommFAicVT8LGHCB0uywx7fYuo3MHYKO15cz-RZEYM5Q",
        ),
        (
            concat!(
                "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIlx1NWM",
                "3MVx1NzUzMCJd"
            ),
            "C9inp6YoRaEXR427zYJP7Qrk1WH_8bdwOA_YUrUnGQU",
        ),
        (
            concat!(
                "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgIlwidW51c3VhbCB",
                "lbWFpbCBhZGRyZXNzXCJAZXhhbXBsZS5qcCJd"
            ),
            "Kuet1yAa0HIQvYnOVd59hcViO9Ug6J2kSfqYRBeowvE",
        ),
        (
            concat!(
                "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlciIsICIrODE",
                "tODAtMTIzNC01Njc4Il0"
            ),
            "s0BKYsLWxQQeU8tVlltM7MKsIRTrEIa1PkJmqxBBf5U",
        ),
        (
            concat!(
                "WyJ5eXRWYmRBUEdjZ2wyckk0QzlHU29nIiwgImJpcnRoZGF0ZSIsICIxOTQwLTA",
                "xLTAxIl0"
            ),
            "MMldOFFzB2d0umlmpTIaGerhWdU_PpYfLvKhh_f_9aY",
        ),
    ];
    for (disclosure, digest) in cases {
        assert_eq!(disclosure_digest(disclosure), digest);
    }
}

#[test]
fn rfc_9901_disclosures_verify_in_rfc_mode_once_signed_under_a_pinned_key() {
    // The RFC's own signatures are ES256, which this profile refuses by design; re-sign the RFC's
    // top-level disclosures under Ed25519 and check they are read as the RFC specifies.
    let disclosures = [
        concat!(
            "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiXHU1OTJ",
            "hXHU5MGNlIl0"
        )
        .to_owned(),
        concat!(
            "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgIlwidW51c3VhbCB",
            "lbWFpbCBhZGRyZXNzXCJAZXhhbXBsZS5qcCJd"
        )
        .to_owned(),
    ];
    let jwt = crafted(SEED_1, &disclosures, "");
    let verified = verify(&join(&jwt, &disclosures), &pins_current(), &lenient()).unwrap();
    let read: Vec<(&str, &str)> = verified
        .disclosed
        .iter()
        .map(|c| (c.path.as_str(), c.value_jcs.as_str()))
        .collect();
    assert_eq!(
        read,
        [
            ("given_name", "\"\u{592a}\u{90ce}\""),
            ("email", "\"\\\"unusual email address\\\"@example.jp\"")
        ]
    );
}

// ---------------------------------------------------------------- refused names, present, malleability

/// The group order of Ed25519, little endian.
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Replaces the signature's S with S + L: the same signature in a non-canonical encoding.
fn malleate_signature(jwt: &str) -> String {
    let (head, signature) = jwt.rsplit_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
    let mut carry = 0u16;
    for (byte, order) in bytes[32..].iter_mut().zip(GROUP_ORDER_LE) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 256 bits");
    format!("{head}.{}", b64(&bytes))
}

#[test]
fn a_non_canonical_signature_s_plus_l_is_rejected() {
    let (issued, _) = issue_a(KID, SEED_1);
    let forged = malleate_signature(&issued.jwt);
    assert_ne!(forged, issued.jwt);
    assert_eq!(
        code(verify(&format!("{forged}~"), &pins_current(), &pinned())),
        ErrorCode::BadSignature
    );
}

#[test]
fn every_refused_claim_name_is_refused_at_issue_and_by_the_verifier() {
    assert!(REFUSED_CLAIM_NAMES.len() > 20);
    for required in [
        "exp",
        "nbf",
        "sub",
        "iat",
        "aud",
        "jti",
        "iss",
        "cnf",
        "vct",
        "status",
        "toString",
        "valueOf",
        "hasOwnProperty",
        "__proto__",
        "constructor",
        "_sd",
        "_sd_alg",
        "...",
    ] {
        assert!(
            REFUSED_CLAIM_NAMES.contains(&required),
            "{required} missing"
        );
    }
    let rng = CountingRandom(AtomicU8::new(0));
    for name in REFUSED_CLAIM_NAMES {
        let list = vec![((*name).to_owned(), json!("x"))];
        assert_eq!(
            code(issue_with_random(&params(KID), &list, &rng, &hex32(SEED_1))),
            ErrorCode::InvalidClaims,
            "{name} at issue"
        );
        let d = disc(&salt(1), name, &json!("x"));
        let jwt = crafted(SEED_1, std::slice::from_ref(&d), "");
        for options in [pinned(), lenient()] {
            assert_eq!(
                code(verify(&join(&jwt, &[d.clone()]), &pins_current(), &options)),
                ErrorCode::ReservedClaimName,
                "{name} at verify"
            );
        }
    }
}

#[test]
fn present_derives_path_and_digest_from_the_encoded_disclosure() {
    let (issued, _) = issue_a(KID, SEED_1);
    let ssn = issued
        .disclosures
        .iter()
        .find(|d| d.path == "applicant.ssn_last4")
        .unwrap()
        .clone();
    // A struct that labels the SSN disclosure with an allowed path must not leak it.
    let mut relabelled = issued.disclosures.clone();
    let slot = relabelled.iter().position(|d| d.path == "flag").unwrap();
    relabelled[slot].encoded = ssn.encoded.clone();
    assert_eq!(
        code(present(&issued.jwt, &relabelled, &["flag"])),
        ErrorCode::MalformedDisclosure
    );
    // Same for a struct whose digest field is forged to match the issuer JWT.
    let mut wrong_digest = issued.disclosures.clone();
    wrong_digest[slot].digest = ssn.digest.clone();
    assert_eq!(
        code(present(&issued.jwt, &wrong_digest, &["flag"])),
        ErrorCode::MalformedDisclosure
    );
    // Even when only another path is requested, a corrupt struct is refused outright.
    assert_eq!(
        code(present(&issued.jwt, &relabelled, &["applicant.name"])),
        ErrorCode::MalformedDisclosure
    );
}

#[test]
fn a_flood_of_tilde_segments_is_refused_by_count_before_any_per_segment_work() {
    let flood = format!(
        "{}{}",
        "a.b.c",
        "~".repeat(10_000_000)
            .get(..MAX_PRESENTATION_BYTES - 10)
            .unwrap()
    );
    assert_eq!(
        code(verify(&flood, &pins_current(), &pinned())),
        ErrorCode::InputTooLarge
    );
}

// ---------------------------------------------------------------- cross-language vectors

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pin_json(pin: &IssuerPin) -> Value {
    json!({"iss": pin.iss, "kid": pin.kid, "publicKeyHex": hex(&pin.public_key)})
}

fn verified_json(
    result: Result<integrity_disclosure::Verified, integrity_disclosure::DisclosureError>,
) -> Value {
    match result {
        Ok(v) => json!({"ok": {
            "iss": v.iss,
            "kid": v.kid,
            "publicClaims": v.public_claims,
            "disclosed": v.disclosed.iter().map(|c| json!({"path": c.path, "valueJcs": c.value_jcs})).collect::<Vec<_>>(),
        }}),
        Err(e) => json!({"code": e.code().as_str()}),
    }
}

fn verify_case(name: &str, presentation: String, pins: &[IssuerPin], encoding: Encoding) -> Value {
    let options = VerifyOptions {
        expected_typ: TYP,
        encoding,
    };
    json!({
        "name": name,
        "presentation": presentation,
        "typ": TYP,
        "encoding": if encoding == Encoding::Pinned { "pinned" } else { "rfc9901" },
        "pins": pins.iter().map(pin_json).collect::<Vec<_>>(),
        "expect": verified_json(verify(&presentation, pins, &options)),
    })
}

fn build_vectors() -> Value {
    let (a, salts_a) = issue_a(KID, SEED_1);
    let claims = claims_a();
    let other = {
        let rng = CountingRandom(AtomicU8::new(100));
        issue_with_random(&params(KID), &claims_b(), &rng, &hex32(SEED_1)).unwrap()
    };
    let mut issuances = Vec::new();
    {
        let mut add = |name: &str,
                       claims: &[(String, Value)],
                       issued: &Issued,
                       salts: &IssuanceSalts,
                       selections: Vec<Vec<&str>>| {
            let presentations: Vec<Value> = selections
                .iter()
                .map(|paths| json!({"paths": paths, "compact": issued.present(paths).unwrap()}))
                .collect();
            issuances.push(json!({
                "name": name,
                "claims": claims.iter().map(|(p, v)| json!({"path": p, "value": v})).collect::<Vec<_>>(),
                "salts": salts,
                "jwt": issued.jwt,
                "disclosures": issued.disclosures.iter().map(|d| json!({"path": d.path, "encoded": d.encoded, "digest": d.digest})).collect::<Vec<_>>(),
                "presentations": presentations,
            }));
        };
        add(
            "sixteen claims, no decoys",
            &claims,
            &a,
            &salts_a,
            vec![
                vec![],
                vec!["applicant.name"],
                vec!["household[0].income", "household[1].income"],
                vec!["toJSON", "\u{ffff}", "\u{1F600}", "prototype"],
                all_paths(&claims),
            ],
        );
        add(
            "three claims, one decoy",
            &claims_b(),
            &other.0,
            &other.1,
            vec![
                vec![],
                vec!["flag"],
                vec!["applicant.name", "applicant.ssn_last4", "flag"],
            ],
        );
    }

    let mut rejects = Vec::new();
    let pins = pins_current();
    let flag = a
        .disclosures
        .iter()
        .find(|d| d.path == "flag")
        .unwrap()
        .encoded
        .clone();
    let name = a
        .disclosures
        .iter()
        .find(|d| d.path == "applicant.name")
        .unwrap()
        .encoded
        .clone();

    rejects.push(verify_case(
        "accepts a full presentation",
        a.present(&all_paths(&claims)).unwrap(),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "tampered value",
        join(
            &a.jwt,
            &[disc(&salts_a.claims["flag"], "flag", &json!(false))],
        ),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "swapped salt",
        join(&a.jwt, &[disc(&salt(77), "flag", &json!(true))]),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "disclosure from another credential",
        join(&a.jwt, &[other.0.disclosures[0].encoded.clone()]),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "wrong iss",
        a.present(&["flag"]).unwrap(),
        &[IssuerPin {
            iss: "https://formspec.example/t/other".into(),
            ..pin(KID, PK_1)
        }],
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "wrong key under the right kid",
        a.present(&["flag"]).unwrap(),
        &[pin(KID, PK_2)],
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "kid not pinned",
        a.present(&["flag"]).unwrap(),
        &[pin("other-kid", PK_1)],
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "ambiguous pins",
        a.present(&["flag"]).unwrap(),
        &[pin(KID, PK_1), pin(KID, PK_2)],
        Encoding::Pinned,
    ));
    let rotated_old = issue_a("att-2026-10", SEED_1).0.present(&["flag"]).unwrap();
    let rotated_new = issue_a("att-2027-01", SEED_2).0.present(&["flag"]).unwrap();
    let both = [pin("att-2026-10", PK_1), pin("att-2027-01", PK_2)];
    rejects.push(verify_case(
        "rotation: old kid under old key",
        rotated_old.clone(),
        &both,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "rotation: new kid under new key",
        rotated_new.clone(),
        &both,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "rotation: new kid, only old key pinned",
        rotated_new,
        &both[..1],
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "repeated disclosure",
        join(&a.jwt, &[flag.clone(), flag.clone()]),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "missing trailing tilde",
        a.jwt.clone(),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "key binding suffix",
        format!("{}{}", join(&a.jwt, &[name.clone()]), a.jwt),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "non-ascii",
        format!("{}é~", a.jwt),
        &pins,
        Encoding::Pinned,
    ));

    let d1 = disc(&salt(1), "a", &json!(1));
    let dup = disclosure_digest(&d1);
    rejects.push(verify_case(
        "duplicate digest in _sd",
        join(
            &crafted_with_digests(SEED_1, &[dup.clone(), dup], ""),
            &[d1.clone()],
        ),
        &pins,
        Encoding::Pinned,
    ));
    let d2 = disc(&salt(2), "a", &json!(2));
    rejects.push(verify_case(
        "duplicate path",
        join(
            &crafted(SEED_1, &[d1.clone(), d2.clone()], ""),
            &[d1.clone(), d2],
        ),
        &pins,
        Encoding::Pinned,
    ));
    let shadow = disc(&salt(1), "iss", &json!("x"));
    rejects.push(verify_case(
        "path shadows iss",
        join(&crafted(SEED_1, &[shadow.clone()], ""), &[shadow]),
        &pins,
        Encoding::Pinned,
    ));
    let nested = disc(&salt(1), "a", &json!({"_sd": ["x"]}));
    rejects.push(verify_case(
        "nested _sd in value",
        join(&crafted(SEED_1, &[nested.clone()], ""), &[nested]),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "nested _sd in payload",
        format!("{}~", crafted(SEED_1, &[], r#","zz":{"_sd":[]}"#)),
        &pins,
        Encoding::Pinned,
    ));
    let cnf = sign_raw(
        SEED_1,
        &header_text(KID),
        &format!(r#"{{"_sd":[],"_sd_alg":"sha-256","cnf":{{"kid":"x"}},"iss":"{ISS}"}}"#),
    );
    rejects.push(verify_case(
        "cnf in payload",
        format!("{cnf}~"),
        &pins,
        Encoding::Pinned,
    ));
    let array_element = b64(jcs(&json!([salt(1), "x"])).as_bytes());
    rejects.push(verify_case(
        "array element disclosure",
        join(
            &crafted(SEED_1, &[array_element.clone()], ""),
            &[array_element],
        ),
        &pins,
        Encoding::Pinned,
    ));
    let spaced = b64(format!(r#"["{}", "a", 1]"#, salt(1)).as_bytes());
    let spaced_jwt = crafted(SEED_1, &[spaced.clone()], "");
    rejects.push(verify_case(
        "non-canonical disclosure, pinned",
        join(&spaced_jwt, &[spaced.clone()]),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "non-canonical disclosure, rfc9901",
        join(&spaced_jwt, &[spaced]),
        &pins,
        Encoding::Rfc9901,
    ));
    let short = disc(&b64(&[9u8; 8]), "a", &json!(1));
    let short_jwt = crafted(SEED_1, &[short.clone()], "");
    rejects.push(verify_case(
        "short salt, pinned",
        join(&short_jwt, &[short.clone()]),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "short salt, rfc9901",
        join(&short_jwt, &[short]),
        &pins,
        Encoding::Rfc9901,
    ));
    let loose = sign_raw(
        SEED_1,
        &header_text(KID),
        &format!(r#"{{ "_sd": [], "iss": "{ISS}" }}"#),
    );
    rejects.push(verify_case(
        "non-canonical payload, pinned",
        format!("{loose}~"),
        &pins,
        Encoding::Pinned,
    ));
    rejects.push(verify_case(
        "non-canonical payload, rfc9901",
        format!("{loose}~"),
        &pins,
        Encoding::Rfc9901,
    ));
    let sha512 = sign_raw(
        SEED_1,
        &header_text(KID),
        &format!(r#"{{"_sd":[],"_sd_alg":"sha-512","iss":"{ISS}"}}"#),
    );
    rejects.push(verify_case(
        "sd_alg sha-512",
        format!("{sha512}~"),
        &pins,
        Encoding::Pinned,
    ));
    let wrong_typ = sign_raw(
        SEED_1,
        r#"{"alg":"EdDSA","kid":"att-2026-10","typ":"JWT"}"#,
        &format!(r#"{{"_sd":[],"_sd_alg":"sha-256","iss":"{ISS}"}}"#),
    );
    rejects.push(verify_case(
        "wrong typ",
        format!("{wrong_typ}~"),
        &pins,
        Encoding::Pinned,
    ));
    let surrogate = b64(format!(r#"["{}","a","\ud800"]"#, salt(1)).as_bytes());
    rejects.push(verify_case(
        "lone surrogate in value",
        join(&crafted(SEED_1, &[surrogate.clone()], ""), &[surrogate]),
        &pins,
        Encoding::Rfc9901,
    ));
    let deep = sign_raw(
        SEED_1,
        &header_text(KID),
        &format!(
            r#"{{"_sd":[],"iss":"{ISS}","zz":{}1{}}}"#,
            "[".repeat(40),
            "]".repeat(40)
        ),
    );
    rejects.push(verify_case(
        "payload nests beyond the bound",
        format!("{deep}~"),
        &pins,
        Encoding::Rfc9901,
    ));
    let malleable = malleate_signature(&a.jwt);
    rejects.push(verify_case(
        "non-canonical signature S plus L",
        format!("{malleable}~"),
        &pins,
        Encoding::Pinned,
    ));
    let mut tampered = a.present(&["flag"]).unwrap().into_bytes();
    let position = a.jwt.rfind('.').unwrap() + 3;
    tampered[position] = if tampered[position] == b'A' {
        b'B'
    } else {
        b'A'
    };
    rejects.push(verify_case(
        "signature byte flipped",
        String::from_utf8(tampered).unwrap(),
        &pins,
        Encoding::Pinned,
    ));

    json!({
        "profile": "integrity-disclosure SD-JWT vectors: Rust-generated, checked by Rust and TypeScript",
        "typ": TYP,
        "refusedClaimNames": REFUSED_CLAIM_NAMES,
        "issuer": {"iss": ISS, "kid": KID, "seedHex": SEED_1, "publicKeyHex": PK_1},
        "publicClaims": params(KID).public_claims,
        "issue": issuances,
        "verify": rejects,
    })
}

#[test]
fn the_shared_vector_file_matches_what_this_implementation_produces() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/selective-disclosure/vectors.json"
    );
    let built = build_vectors();
    if std::env::var_os("INTEGRITY_DISCLOSURE_REGEN").is_some() {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        stored, built,
        "regenerate with INTEGRITY_DISCLOSURE_REGEN=1 only on a deliberate wire change"
    );
}

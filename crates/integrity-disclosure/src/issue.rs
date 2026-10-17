// Rust guideline compliant 2026-02-21

//! Issuing an SD-JWT and presenting a subset of its disclosures.

use std::collections::{BTreeMap, HashSet};

use integrity_cose::sign_ed25519;
use integrity_seam::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{DisclosureError, ErrorCode, Result};
use crate::verify::jwt_sd_digests;
use crate::wire::{
    MAX_CLAIMS, MAX_ISS_BYTES, MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES, SALT_BYTES,
    SD_ALG, Scan, b64_decode, b64_encode, disclosure_digest, disclosure_path, encode_disclosure,
    is_reserved_name, jcs, scan_value,
};

/// JWS `alg` for Ed25519 (RFC 8037).
pub(crate) const ALG_EDDSA: &str = "EdDSA";

/// Returns how many `_sd` entries an SD-JWT with `claims` claims carries.
///
/// This is the decoy-digest and padding policy: `_sd` is padded with decoy digests to the next
/// power of two, so a presentation reveals the claim count only to within a factor of two. A
/// decoy is the SHA-256 digest of a fresh 128-bit salt string, as RFC 9901 §4.2.5 recommends.
#[must_use]
pub fn padded_digest_count(claims: usize) -> usize {
    claims.next_power_of_two()
}

/// Salts for one issuance: one per claim path plus the decoys.
///
/// Persist this beside the issuer JWT. The same salts, claims and key re-issue byte-identical
/// output, because the encoding is canonical and Ed25519 signatures are deterministic. Delete it
/// to make every disclosure unrecoverable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceSalts {
    /// Salt string (base64url of 128 random bits) by claim path.
    pub claims: BTreeMap<String, String>,
    /// Salt strings behind the decoy digests.
    pub decoys: Vec<String>,
}

impl IssuanceSalts {
    /// Draws a fresh salt for each path and for each decoy the padding policy needs.
    ///
    /// # Errors
    ///
    /// Fails when `paths` is empty, longer than `MAX_CLAIMS`, holds a duplicate, or the entropy
    /// source fails.
    pub fn generate(rng: &dyn SecureRandom, paths: &[&str]) -> Result<Self> {
        if paths.is_empty() || paths.len() > MAX_CLAIMS {
            return Err(DisclosureError::new(
                ErrorCode::InvalidClaims,
                "claim count must be between 1 and MAX_CLAIMS",
            ));
        }
        let mut claims = BTreeMap::new();
        for path in paths {
            if claims
                .insert((*path).to_owned(), fresh_salt(rng)?)
                .is_some()
            {
                return Err(DisclosureError::new(
                    ErrorCode::InvalidClaims,
                    "duplicate claim path",
                ));
            }
        }
        let decoys = (paths.len()..padded_digest_count(paths.len()))
            .map(|_| fresh_salt(rng))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { claims, decoys })
    }
}

fn fresh_salt(rng: &dyn SecureRandom) -> Result<String> {
    let mut bytes = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut bytes)
        .map_err(|_| DisclosureError::new(ErrorCode::Entropy, "entropy source failed"))?;
    Ok(b64_encode(&bytes))
}

fn check_salt(salt: &str) -> Result<()> {
    match b64_decode(salt) {
        Ok(bytes) if bytes.len() == SALT_BYTES => Ok(()),
        _ => Err(DisclosureError::new(
            ErrorCode::InvalidSalts,
            "salt is not 128 bits of base64url",
        )),
    }
}

/// Issuer inputs besides the claims, salts and key.
#[derive(Debug, Clone, PartialEq)]
pub struct IssueParams {
    /// Issuer identifier. Derive it from tenant context, never from author input.
    pub iss: String,
    /// Key identifier the relying party pins beside `iss`.
    pub kid: String,
    /// JWT `typ` header, for example `formspec-response+sd-jwt`.
    pub typ: String,
    /// Claims shown to everyone, such as `definition` and `accepted_at`.
    ///
    /// Must not use `iss`, `cnf`, `_sd`, `_sd_alg` or `...`, nor nest `_sd` or `...` keys.
    pub public_claims: Map<String, Value>,
}

/// One disclosure, ready to present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedDisclosure {
    /// Claim path.
    pub path: String,
    /// `base64url(JCS([salt, path, value]))`.
    pub encoded: String,
    /// Base64url SHA-256 digest of `encoded`, as listed in `_sd`.
    pub digest: String,
}

/// An issued SD-JWT: the signed issuer JWT and every disclosure, sorted by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// Compact issuer JWT `header.payload.signature`.
    pub jwt: String,
    /// Every claim's disclosure.
    pub disclosures: Vec<IssuedDisclosure>,
}

impl Issued {
    /// Presents the issuer JWT with only the disclosures at `paths`.
    ///
    /// # Errors
    ///
    /// See [`present`].
    pub fn present(&self, paths: &[&str]) -> Result<String> {
        present(&self.jwt, &self.disclosures, paths)
    }
}

/// Builds every claim's disclosure from claims and stored salts, sorted by path.
///
/// Call this at request time to rebuild disclosures without the signing key.
///
/// # Errors
///
/// Fails when the claims are empty, too many, duplicated, have a malformed path or a value that
/// cannot be carried, or the salts do not match the claims exactly.
pub fn build_disclosures(
    claims: &[(String, Value)],
    salts: &IssuanceSalts,
) -> Result<Vec<IssuedDisclosure>> {
    let invalid = |message: &str| DisclosureError::new(ErrorCode::InvalidClaims, message);
    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        return Err(invalid("claim count must be between 1 and MAX_CLAIMS"));
    }
    let mut sorted: Vec<&(String, Value)> = claims.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in sorted.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(invalid("duplicate claim path"));
        }
    }
    for (path, value) in &sorted {
        if path.is_empty() || path.len() > MAX_PATH_BYTES || is_reserved_name(path) {
            return Err(invalid("claim path is empty, too long or a refused name"));
        }
        if scan_value(value, 0) != Scan::Clean {
            return Err(invalid("claim value nests too deeply or uses _sd or ..."));
        }
    }
    if salts.claims.len() != sorted.len()
        || salts.decoys.len() != padded_digest_count(sorted.len()) - sorted.len()
    {
        return Err(DisclosureError::new(
            ErrorCode::InvalidSalts,
            "salts do not match the claims and padding policy",
        ));
    }
    sorted
        .into_iter()
        .map(|(path, value)| {
            let salt = salts.claims.get(path).ok_or_else(|| {
                DisclosureError::new(ErrorCode::InvalidSalts, "no salt for a claim path")
            })?;
            check_salt(salt)?;
            let encoded = encode_disclosure(salt, path, value)?;
            let digest = disclosure_digest(&encoded);
            Ok(IssuedDisclosure {
                path: path.clone(),
                encoded,
                digest,
            })
        })
        .collect()
}

/// Issues an SD-JWT over `claims` using stored `salts`.
///
/// The issuer JWT is Ed25519 over `b64(header).b64(payload)` with header
/// `{alg: "EdDSA", kid, typ}` and payload `{...public_claims, iss, _sd_alg, _sd}`, both as JCS
/// bytes. `_sd` holds one digest per claim plus decoys up to [`padded_digest_count`], sorted.
///
/// # Errors
///
/// Fails when parameters, claims or salts are malformed, or the result would exceed
/// `MAX_PRESENTATION_BYTES`.
pub fn issue(
    params: &IssueParams,
    claims: &[(String, Value)],
    salts: &IssuanceSalts,
    signing_seed: &[u8; 32],
) -> Result<Issued> {
    let prepared = prepare(params, claims, salts)?;
    let signature = sign_ed25519(*signing_seed, prepared.signing_input());
    prepared.assemble(&signature)
}

/// An issuer JWT ready to sign: its signing input and the disclosures it commits to.
///
/// Signing is the caller's step, so a key held behind an async port (KMS, Vault) can sign without
/// this crate depending on that port. [`PreparedIssue::assemble`] finishes the SD-JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedIssue {
    signing_input: String,
    disclosures: Vec<IssuedDisclosure>,
}

impl PreparedIssue {
    /// The bytes to sign: `b64(header).b64(payload)`. The header already names `params.kid`.
    #[must_use]
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    /// Appends the Ed25519 `signature` over [`Self::signing_input`] and returns the SD-JWT.
    ///
    /// # Errors
    ///
    /// Fails when the result would exceed `MAX_PRESENTATION_BYTES`.
    pub fn assemble(self, signature: &[u8; 64]) -> Result<Issued> {
        let jwt = format!("{}.{}", self.signing_input, b64_encode(signature));
        let total: usize = jwt.len()
            + self
                .disclosures
                .iter()
                .map(|d| d.encoded.len() + 1)
                .sum::<usize>()
            + 1;
        if total > MAX_PRESENTATION_BYTES {
            return Err(DisclosureError::new(
                ErrorCode::InputTooLarge,
                "issued SD-JWT exceeds MAX_PRESENTATION_BYTES",
            ));
        }
        Ok(Issued {
            jwt,
            disclosures: self.disclosures,
        })
    }
}

/// Builds the issuer JWT's signing input and disclosures without signing.
///
/// `params.kid` goes into the header, so the caller learns the signing key's `kid` first and
/// checks that the signature it obtains was made under that key. Output is deterministic for the
/// same parameters, claims and salts.
///
/// # Errors
///
/// Fails when parameters, claims or salts are malformed.
pub fn prepare(
    params: &IssueParams,
    claims: &[(String, Value)],
    salts: &IssuanceSalts,
) -> Result<PreparedIssue> {
    check_params(params)?;
    let disclosures = build_disclosures(claims, salts)?;
    if disclosures
        .iter()
        .any(|d| params.public_claims.contains_key(&d.path) || d.path == "iss" || d.path == "cnf")
    {
        return Err(DisclosureError::new(
            ErrorCode::ReservedClaimName,
            "a claim path collides with a public claim",
        ));
    }
    let mut digests: Vec<String> = disclosures.iter().map(|d| d.digest.clone()).collect();
    for decoy in &salts.decoys {
        check_salt(decoy)?;
        digests.push(disclosure_digest(decoy));
    }
    digests.sort_unstable();
    if digests.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DisclosureError::new(
            ErrorCode::InvalidSalts,
            "two salts produce the same digest",
        ));
    }

    let mut payload = params.public_claims.clone();
    payload.insert("iss".into(), Value::String(params.iss.clone()));
    payload.insert("_sd_alg".into(), Value::String(SD_ALG.into()));
    payload.insert(
        "_sd".into(),
        Value::Array(digests.into_iter().map(Value::String).collect()),
    );
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(ALG_EDDSA.into()));
    header.insert("kid".into(), Value::String(params.kid.clone()));
    header.insert("typ".into(), Value::String(params.typ.clone()));

    let signing_input = format!(
        "{}.{}",
        b64_encode(&jcs(&Value::Object(header))?),
        b64_encode(&jcs(&Value::Object(payload))?)
    );
    Ok(PreparedIssue {
        signing_input,
        disclosures,
    })
}

/// Issues with fresh random salts and returns them for storage.
///
/// # Errors
///
/// See [`IssuanceSalts::generate`] and [`issue`].
pub fn issue_with_random(
    params: &IssueParams,
    claims: &[(String, Value)],
    rng: &dyn SecureRandom,
    signing_seed: &[u8; 32],
) -> Result<(Issued, IssuanceSalts)> {
    let paths: Vec<&str> = claims.iter().map(|(path, _)| path.as_str()).collect();
    let salts = IssuanceSalts::generate(rng, &paths)?;
    let issued = issue(params, claims, &salts, signing_seed)?;
    Ok((issued, salts))
}

fn check_params(params: &IssueParams) -> Result<()> {
    let bad = |message: &str| Err(DisclosureError::new(ErrorCode::InvalidParams, message));
    if params.iss.is_empty() || params.iss.len() > MAX_ISS_BYTES {
        return bad("iss is empty or too long");
    }
    if params.kid.is_empty() || params.kid.len() > MAX_NAME_BYTES {
        return bad("kid is empty or too long");
    }
    if params.typ.is_empty() || params.typ.len() > MAX_NAME_BYTES {
        return bad("typ is empty or too long");
    }
    for (name, value) in &params.public_claims {
        if matches!(name.as_str(), "iss" | "cnf" | "_sd" | "_sd_alg" | "...") {
            return bad("public claim uses a reserved name");
        }
        if scan_value(value, 0) != Scan::Clean {
            return bad("public claim nests too deeply or uses _sd or ...");
        }
    }
    Ok(())
}

/// Presents `issuer_jwt` with only the disclosures whose paths are in `paths`.
///
/// `paths` is an allowlist of exact claim paths: nothing outside it is disclosed. Disclosures keep
/// issuance (path) order regardless of the order of `paths`, so the presentation does not echo the
/// request. Output is `<issuer-jwt>~<disclosure>~...~`.
///
/// # Errors
///
/// Fails when `paths` repeats a path or names a path that is not a disclosure, or when a
/// selected disclosure's digest is not in the issuer JWT's `_sd` (stored parts that no longer
/// belong together).
pub fn present(
    issuer_jwt: &str,
    disclosures: &[IssuedDisclosure],
    paths: &[&str],
) -> Result<String> {
    let mut wanted: HashSet<&str> = HashSet::with_capacity(paths.len());
    for path in paths {
        if !wanted.insert(path) {
            return Err(DisclosureError::new(
                ErrorCode::DuplicatePath,
                "a path is requested twice",
            ));
        }
    }
    // Path and digest come from `encoded`, never from the struct: a mismatched struct must not be
    // able to steer the allowlist or the membership check.
    let mut derived = Vec::with_capacity(disclosures.len());
    for disclosure in disclosures {
        let path = disclosure_path(&disclosure.encoded)?;
        let digest = disclosure_digest(&disclosure.encoded);
        if path != disclosure.path || digest != disclosure.digest {
            return Err(DisclosureError::new(
                ErrorCode::MalformedDisclosure,
                "a disclosure struct does not match its encoded form",
            ));
        }
        derived.push((path, digest, disclosure));
    }
    let known: HashSet<&str> = derived.iter().map(|(path, _, _)| path.as_str()).collect();
    if wanted.iter().any(|path| !known.contains(path)) {
        return Err(DisclosureError::new(
            ErrorCode::UnknownPath,
            "a requested path is not a disclosure",
        ));
    }
    let listed = jwt_sd_digests(issuer_jwt)?;
    let mut out = String::from(issuer_jwt);
    out.push('~');
    for (path, digest, disclosure) in &derived {
        if !wanted.contains(path.as_str()) {
            continue;
        }
        if !listed.contains(digest.as_str()) {
            return Err(DisclosureError::new(
                ErrorCode::UnknownDigest,
                "a disclosure does not belong to this issuer JWT",
            ));
        }
        out.push_str(&disclosure.encoded);
        out.push('~');
    }
    Ok(out)
}

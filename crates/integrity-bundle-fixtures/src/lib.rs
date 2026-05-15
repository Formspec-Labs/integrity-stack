// Rust guideline compliant 2026-02-21
//! Walks cross-stack fixture bundle manifests.
//!
//! Fixture bytes stay in the owning product repos. This crate owns the shared
//! manifest vocabulary and directory walker used by verifier, emitter, and
//! governance conformance code that needs the same cross-stack corpus.

#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

/// One discovered fixture bundle directory and parsed manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureBundle {
    pub dir: PathBuf,
    pub id: String,
    pub name: String,
    pub description: String,
    pub manifest: Manifest,
}

/// Parsed cross-stack fixture manifest.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Manifest {
    pub bundle: BundleMeta,
    #[serde(rename = "required-adapters")]
    #[serde(default)]
    pub required_adapters: Adapters,
    #[serde(rename = "required-files")]
    #[serde(default)]
    pub required_files: RequiredFiles,
    #[serde(rename = "expected-outcomes")]
    pub expected_outcomes: ExpectedOutcomes,
    #[serde(rename = "cross-layer-byte-equality")]
    #[serde(default)]
    pub cross_layer_byte_equality: CrossLayerByteEquality,
}

/// Human-readable bundle identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct BundleMeta {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// Adapter families required to exercise a fixture.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Adapters {
    #[serde(default)]
    pub adapters: Vec<String>,
}

/// Required bundle member files.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RequiredFiles {
    #[serde(default)]
    pub formspec_response: bool,
    #[serde(default)]
    pub wos_provenance: bool,
    #[serde(default)]
    pub trellis_events: bool,
    #[serde(default)]
    pub trellis_export: bool,
    #[serde(default)]
    pub verification_receipt: bool,
    #[serde(default)]
    pub posture_declaration: bool,
}

/// Expected cross-stack outcomes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExpectedOutcomes {
    pub formspec: FormspecOutcome,
    #[serde(default)]
    pub wos: Option<WosOutcome>,
    #[serde(default)]
    pub trellis: Option<TrellisOutcome>,
}

/// Expected Formspec-side outcome.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FormspecOutcome {
    pub schema_valid: bool,
    #[serde(default)]
    pub semantic_valid: Option<bool>,
    #[serde(default)]
    pub expected_errors: Vec<String>,
    #[serde(default)]
    pub source_of_truth_invariants: SourceOfTruthInvariants,
}

/// Source-of-truth invariant expectations for Formspec signatures.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SourceOfTruthInvariants {
    #[serde(default)]
    pub response_id_matches_signed_payload: Option<bool>,
    #[serde(default)]
    pub definition_url_matches: Option<bool>,
    #[serde(default)]
    pub definition_version_matches: Option<bool>,
    #[serde(default)]
    pub signed_at_in_signed_payload: Option<bool>,
}

/// Expected WOS-side outcome.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct WosOutcome {
    #[serde(default)]
    pub present: Option<bool>,
    #[serde(default)]
    pub record_kind: Option<String>,
    #[serde(default)]
    pub primitive_verification_status: Option<String>,
    #[serde(default)]
    pub admission_failed_reason: Option<String>,
}

/// Expected Trellis-side outcome.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct TrellisOutcome {
    #[serde(default)]
    pub present: Option<bool>,
    #[serde(default)]
    pub custody_hook_present: Option<bool>,
    #[serde(default)]
    pub uca_corroborated: Option<bool>,
    #[serde(default)]
    pub export_present: Option<bool>,
}

/// Expected byte-equality invariants across layers.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CrossLayerByteEquality {
    #[serde(default)]
    pub formspec_signed_payload_digest_equals_wos: Option<bool>,
    #[serde(default)]
    pub signature_value_bytes_equals_trellis_uca: Option<bool>,
    #[serde(default)]
    pub verification_receipt_bytes_identical: Option<bool>,
    #[serde(default)]
    pub response_hash_equals_export: Option<bool>,
}

/// Discovers fixture bundles under `root`.
///
/// # Errors
/// Returns an error when `root` cannot be read or a discovered manifest cannot
/// be read or parsed.
pub fn discover_bundles(root: impl AsRef<Path>) -> Result<Vec<FixtureBundle>, String> {
    let cross_stack_dir = root.as_ref();
    let mut bundles = Vec::new();

    let entries = fs::read_dir(cross_stack_dir)
        .map_err(|e| format!("failed to read cross-stack dir {cross_stack_dir:?}: {e}"))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }

        let toml_str = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("failed to read manifest at {manifest_path:?}: {e}"))?;
        let manifest = toml::from_str::<Manifest>(&toml_str)
            .map_err(|e| format!("failed to parse manifest at {manifest_path:?}: {e}"))?;

        bundles.push(FixtureBundle {
            id: manifest.bundle.id.clone(),
            name: manifest.bundle.name.clone(),
            description: manifest.bundle.description.clone(),
            dir: path,
            manifest,
        });
    }

    bundles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(bundles)
}

/// Validates a fixture manifest against the sibling corpus schema.
///
/// # Errors
/// Returns an error when the schema cannot be found, the manifest cannot be
/// converted to JSON, or JSON Schema validation fails.
pub fn validate_manifest_schema(manifest_path: &Path) -> Result<(), String> {
    let schema_path = manifest_path
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("manifest.schema.json"))
        .ok_or("cannot locate manifest.schema.json")?;

    let schema_str =
        fs::read_to_string(&schema_path).map_err(|e| format!("cannot read schema: {e}"))?;
    let schema: serde_json::Value =
        serde_json::from_str(&schema_str).map_err(|e| format!("invalid schema json: {e}"))?;

    let toml_str = fs::read_to_string(manifest_path).map_err(|e| format!("cannot read: {e}"))?;
    let manifest_json =
        toml::from_str::<toml::Value>(&toml_str).map_err(|e| format!("toml parse error: {e}"))?;
    let manifest_value =
        serde_json::to_value(&manifest_json).map_err(|e| format!("conversion error: {e}"))?;

    let validator =
        jsonschema::validator_for(&schema).map_err(|e| format!("schema compile error: {e}"))?;

    validator
        .validate(&manifest_value)
        .map_err(|e| format!("schema validation failed for {manifest_path:?}: {e}"))
}

/// Returns all manifest paths under `cross_stack_root`.
///
/// # Errors
/// Returns an error when `cross_stack_root` cannot be read.
pub fn raw_manifest_paths(cross_stack_root: impl AsRef<Path>) -> Result<Vec<PathBuf>, String> {
    let cross_stack_root = cross_stack_root.as_ref();
    let mut paths = Vec::new();
    let entries = fs::read_dir(cross_stack_root)
        .map_err(|e| format!("failed to read cross-stack dir {cross_stack_root:?}: {e}"))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.toml");
        if manifest_path.exists() {
            paths.push(manifest_path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Returns all manifest paths that should validate against the corpus schema.
///
/// # Errors
/// Returns an error when `cross_stack_root` cannot be read.
pub fn all_manifest_schema_paths(
    cross_stack_root: impl AsRef<Path>,
) -> Result<Vec<PathBuf>, String> {
    raw_manifest_paths(cross_stack_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_schema(root: &Path) {
        fs::write(
            root.join("manifest.schema.json"),
            r#"{
              "type": "object",
              "required": ["bundle", "expected-outcomes"],
              "properties": {
                "bundle": {
                  "type": "object",
                  "required": ["id", "name", "description"],
                  "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                  }
                },
                "expected-outcomes": {
                  "type": "object",
                  "required": ["formspec"],
                  "properties": {
                    "formspec": {
                      "type": "object",
                      "required": ["schema_valid"],
                      "properties": {
                        "schema_valid": { "type": "boolean" }
                      }
                    }
                  }
                }
              }
            }"#,
        )
        .expect("write schema");
    }

    fn write_manifest(root: &Path, dir: &str, id: &str) -> PathBuf {
        let bundle_dir = root.join(dir);
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");
        let manifest_path = bundle_dir.join("manifest.toml");
        fs::write(
            &manifest_path,
            format!(
                r#"[bundle]
id = "{id}"
name = "{dir}"
description = "test fixture"

[expected-outcomes.formspec]
schema_valid = true
"#
            ),
        )
        .expect("write manifest");
        manifest_path
    }

    #[test]
    fn discovers_bundles_sorted_by_id() {
        let root = tempfile::tempdir().expect("tempdir");
        write_schema(root.path());
        write_manifest(root.path(), "002-second", "002");
        write_manifest(root.path(), "001-first", "001");
        fs::write(root.path().join("README.md"), "ignored").expect("write ignored");

        let bundles = discover_bundles(root.path()).expect("discover");

        let ids = bundles
            .iter()
            .map(|bundle| bundle.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["001", "002"]);
    }

    #[test]
    fn returns_sorted_manifest_paths() {
        let root = tempfile::tempdir().expect("tempdir");
        write_schema(root.path());
        write_manifest(root.path(), "002-second", "002");
        write_manifest(root.path(), "001-first", "001");

        let paths = raw_manifest_paths(root.path()).expect("paths");

        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("001-first/manifest.toml"));
        assert!(paths[1].ends_with("002-second/manifest.toml"));
    }

    #[test]
    fn validates_manifest_against_sibling_schema() {
        let root = tempfile::tempdir().expect("tempdir");
        write_schema(root.path());
        let manifest_path = write_manifest(root.path(), "001-first", "001");

        validate_manifest_schema(&manifest_path).expect("valid manifest");
    }

    #[test]
    fn reports_schema_validation_errors() {
        let root = tempfile::tempdir().expect("tempdir");
        write_schema(root.path());
        let bundle_dir = root.path().join("001-first");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");
        let manifest_path = bundle_dir.join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"[expected-outcomes.formspec]
schema_valid = true
"#,
        )
        .expect("write manifest");

        let error = validate_manifest_schema(&manifest_path).expect_err("invalid manifest");

        assert!(error.contains("schema validation failed"));
    }
}

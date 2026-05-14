// Rust guideline compliant 2026-05-13
//! Fixture-level parity harness tests.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use integrity_verify_parity::run_parity_for_fixture;

#[test]
fn known_export_fixture_runs_through_both_paths() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../../trellis/fixtures/vectors/verify/001-export-001-two-event-chain/input-export.zip",
    );
    let report = run_parity_for_fixture(&fixture).expect("run independent parity harness");

    assert!(report.oracle.structure_verified);
    assert!(report.metadata.archive_entry_count > 0);
    assert!(report.metadata.target_event_count > 0);
    assert!(
        report.byte_identical,
        "basic export fixture should already be byte-identical:\n{}",
        report.diff.as_deref().unwrap_or("<missing diff>")
    );
    assert!(report.diff.is_none());
}

#[test]
fn target_path_matches_oracle_manifest_kid_failures() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../../trellis/fixtures/vectors/verify/005-export-001-unresolvable-manifest-kid/input-export.zip",
    );
    let report = run_parity_for_fixture(&fixture).expect("run independent parity harness");

    assert!(report.byte_identical);
    assert!(
        report
            .target
            .event_failures
            .iter()
            .any(|failure| failure.kind == "unresolvable_manifest_kid"),
        "target path must preserve the production manifest-kid failure"
    );
}

#[test]
fn all_trellis_zip_fixtures_run_without_masking_diffs() {
    let mut paths = fixture_paths();
    paths.sort();
    assert!(!paths.is_empty(), "expected Trellis fixture ZIP corpus");

    for path in paths {
        let report = run_parity_for_fixture(&path).unwrap_or_else(|error| {
            panic!(
                "run independent parity harness for {}: {error}",
                path.display()
            );
        });
        assert_eq!(
            report.diff.is_some(),
            !report.byte_identical,
            "diff bookkeeping mismatch for {}",
            path.display()
        );
    }
}

#[test]
fn all_trellis_zip_fixtures_are_byte_identical() {
    let mut failures = Vec::new();
    for path in fixture_paths() {
        let report = run_parity_for_fixture(&path).unwrap_or_else(|error| {
            panic!(
                "run independent parity harness for {}: {error}",
                path.display()
            );
        });
        if !report.byte_identical {
            failures.push(format!(
                "{}\n{}",
                path.display(),
                report.diff.unwrap_or_else(|| "missing diff".to_string())
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "parity failures:\n{}",
        failures.join("\n\n")
    );
}

fn fixture_paths() -> Vec<PathBuf> {
    let pattern = format!(
        "{}/../../../trellis/fixtures/vectors/**/*.zip",
        env!("CARGO_MANIFEST_DIR")
    );
    glob::glob(&pattern)
        .expect("fixture glob compiles")
        .map(|entry| entry.expect("fixture glob entry"))
        .collect()
}

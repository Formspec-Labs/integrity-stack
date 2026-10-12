# Final CLI composition: independent static BEFORE review

VERDICT: APPROVE the bounded composition and staged qualification plan. The current standalone CLI lock is stale; this is not locked-ready approval. Reconciliation, successor lock review, tests, build and final binary designation remain pending.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-10. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, with relevant Rust guidance retained from preceding reviews. Static filesystem/source/TOML/hash inspection only. No Cargo, metadata, native commands, builds, tests, wrapper execution or HTTP calls. Only this certificate was written; preserved sources and earlier qualification evidence remain unchanged.

## 1. Patch summary and scope identity

Candidate `C`: `/private/tmp/integrity-final-cli-composition-v1-20261010`. Source manifest SHA-256: `6b3d2f77cd02f296635f2f3c7bd6004f999a28857dab041016ce8825d32e4e84`. Plan: `/Users/mikewolfd/Work/formspec-stack/thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/final-d1-offline/final-cli-composition-plan-v1.json`, SHA-256 `55106d7d0682d622b991c611e038674d731cc191a93b3f13d9dfa5b49a76d4cc`. Independently rehashed all 8,032 declared files: zero mismatches. This is identity checking, not behavioral review of 8,032 files.

Existing registry-pin CLI overlays the preserved `/private/tmp/core-form-pin-zip-inputs-v2-20261009` closure. CLI manifest, lock, main, cli.rs and integration tests match the current maintained overlay byte-for-byte. Adapter, validator, shared helper and schema match the qualified dependency base and previously reviewed native sources exactly. No new Rust production implementation is proposed.

Key identities independently checked through the manifest:

| File relative to C | SHA-256 |
| --- | --- |
| `integrity-stack/crates/integrity-verify-cli/Cargo.toml` | `a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a` |
| same crate `Cargo.lock` | `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e` |
| same crate `src/cli.rs` | `ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9` |
| `trellis/crates/trellis-verify-wos/src/native_provenance.rs` | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |
| same crate `src/validator.rs` | `e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0` |
| `work-spec/crates/wos-events/src/native_provenance.rs` | `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d` |
| `work-spec/schemas/wos-native-provenance-event.schema.json` | `18c370ffcc8a1274ba89cfe3a8aca3b1bd452e530b637d3e1349d71fc04c0304` |

Hypotheses: H1, composition could introduce a second local Integrity verifier identity, refuted by both CLI and WOS manifests resolving to the same candidate directory. H2, copied path dependencies could escape or be missing, refuted by independent static path checking. H3, the CLI lock could already capture the helper's dependency, refuted below. H4, old CLI tests alone qualify actual D1, refuted by plan's separate actual-case gates.

## 2. Function and dependency trace

Locations below are candidate-relative.

| Function / dependency | File:line | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| Standalone CLI manifest | `integrity-stack/crates/integrity-verify-cli/Cargo.toml:4,18–24` | local dependencies → intended crate graph | Own workspace; direct maintained Integrity dependencies and relative WOS verifier. |
| WOS verifier manifest | `trellis/crates/trellis-verify-wos/Cargo.toml:10–14` | relative dependencies → shared local Integrity/WOS source | Its Integrity path resolves to the same directory as CLI's direct dependency; WOS events resolves within C. |
| Shared helper dependency | `work-spec/crates/wos-events/Cargo.toml:11–12` | `integrity-cbor` json feature / jsonschema0.46 | Uses maintained decoder plus strict owning schema validator; default jsonschema features disabled. |
| `verify_export_command` | CLI `src/cli.rs:293–337` | retained archive path → JSON/error | Reads once, pin-checks owned ZIP bytes, passes same bytes to actual WOS verifier; failures or false structure/integrity return error. |
| `check_registry_pin` | same source:341–370 | owned ZIP / independent digest → match/error | Exact one root-relative registry, raw SHA, missing/duplicate/mismatch refusal before report emission. |
| `trellis_verify_wos::verify_export_zip` | WOS `src/lib.rs:47–49` | ZIP slice → WOS report | Maintained Integrity verification with actual `WosRecordValidator`. |
| Native path | WOS `src/validator.rs:22–26`, `src/native_provenance.rs:10–35` | borrowed events → findings | Shared strict native constructor; invalid/unavailable generic payload Failure; unrelated routes unchanged. |
| Shared constructor | events `src/native_provenance.rs:57–79,96–98` | bytes → validated retained value/error | Strict decoder and owning schema; unchanged previously reviewed API compatible with adapter call. |

## 3. Data flow and invariants

Independently parsed copied Cargo manifests and inspected 359 path entries: every target exists and resolves inside C, including binary/test paths. The manifest's missing/external dependency arrays are also empty. This establishes static pathname completeness, not Cargo's feature/version/target resolution or cache availability.

The standalone lock at `integrity-stack/crates/integrity-verify-cli/Cargo.lock:722` lists `wos-events` without jsonschema and contains no jsonschema package. The actual events manifest explicitly requires version0.46 (:12). Candidate Trellis lock contains jsonschema0.45.1 and0.46.1 (:1435,:1462), and events uses0.46.1 (:4490). That separate lock is evidence of a qualified sibling selection, not an interchangeable standalone CLI lock. Do not copy its unrelated packages/versions or manually merge a dependency list.

The intended sequence is safe only with gates preserved: owner-granted locked admission; retain failure; authorized private mechanical reconciliation; freeze source/lock successor; independent delta review; locked admission of that successor; existing CLI tests; build and copy/hash retained executable; paired result review. `cargo generate-lockfile --offline` may select other cached compatible versions, so its output is not automatically a minimal mechanical delta. Review unexpected changes before tests, and stop if closure cannot resolve offline. The reviewed plan already requires this inspection and freeze (:34–46). No command is authorized by this certificate.

CLI-owned archive bytes remain the internal pin/verifier boundary. Actual case identity, selected registry authority, business completeness, operator input races and immutable archive custody remain separate requirements. Old `b980…` artifact is not eligible merely because its old tests passed.

## 4. Test behavior and edge cases

Re-read the complete five integration tests and relevant pin unit assertions. Existing code is unchanged; prior source reviews cover remaining CLI branches. The proposed twenty-test run is unexecuted on this composition.

| Test / location | Actual assertion and expected role |
| --- | --- |
| `registry_pin_args_refuse_invalid_or_duplicate_selection`, cli.rs:803 | Refuses missing/short/uppercase/nonhex/oversize and duplicate selection; exact valid value retained. |
| `registry_pin_matches_exact_raw_member_and_refuses_other_snapshot`, :841 | Known abc hash matches; foreign hash errors; absent pin remains not_requested. |
| `registry_pin_refuses_missing_ambiguous_nested_and_malformed_members`, :852 | Missing/rootless/nested decoys, different/same root duplicates and malformed ZIP refuse. |
| `matching_registry_does_not_bypass_native_export_verification`, :885 | Matching hash of malformed registry still yields verifier error and verified=false. This is maintained export validation, not a generic native-provenance positive test. |
| `matching_registry_does_not_bypass_manifest_signature_failure`, :913 | Actual fixture001 manifest signature tamper keeps registry match but fails integrity. |
| Integration `verify_command_*`, tests/verify_bundle.rs:29,72,105 | Subprocess default text/JSON, JSON-only and missing-file behavior. |
| `verify_export_command_reports_wos_export_summary`, :120 | Actual fixture001 subprocess reports verified=true, zero WOS failures and absent pin status. |
| `verify_export_accepts_selected_snapshot_and_refuses_foreign_snapshot`, :165 | Same fixture001 with selected digest passes; alternate compiled digest refuses before stdout; matched report records exact digest. Fixture005 archive is not read. |

The fixture001 path is actual runtime file input (`tests/verify_bundle.rs:22–24`, cli.rs:914–917). The plan explicitly captures its hash before/after, closing the earlier provenance omission. Native helper/adapter acceptance itself remains supported by separately qualified owning tests; compiling this CLI composition does not rerun the complete638 suite or establish actual D1 verification.

## 5. Findings

WARNING 1 — dependency readiness. Location: standalone lock:722; events manifest:12. The current standalone lock lacks the required schema dependency, so locked readiness cannot be claimed. Remedy: owner-authorized Cargo-generated offline successor, exact delta review/freeze and locked admission before tests/build. The plan already accounts for this; it is a blocker to execution readiness, not a blocker to this staged plan approval.

OBSERVATION 2 — closure and execution limits. Location: plan:23–46,86–95. Existing local paths and prior qualified sibling versions do not establish cache availability, complete target graph, portable closure or future binary identity. Preserve exact admission diagnostics; stop rather than fetch or broadly upgrade without authority. A retained successful twenty-test/build receipt and reviewed graph are still missing inputs for eligible binary designation.

No new production/API incompatibility identified in the bounded static composition trace.

## 6. Conclusion

VERDICT: APPROVE the BEFORE plan, with locked readiness explicitly pending.

- The composition preserves maintained CLI registry gating and the qualified owning native helper/adapter; no new generic Rust production change is needed on inspected source evidence.
- Coverage of source identities, static local paths, key API seams and planned test scope: ADEQUATE. Cargo resolution, successor lock delta and execution are UNQUALIFIED.
- Confidence: HIGH for exact hashes/local path/API observations; no inference that metadata, tests or build will pass.
- Only a separately frozen and reviewed lock/source successor plus authorized retained test/build evidence may designate the final CLI. Actual D1 archive verification, deployment and adoption remain outside this certificate.

## Focused setup refinement addendum — plan v2

VERDICT: APPROVE the revised setup scope. Read the complete v1→v2 plan delta and independently verified v2 SHA-256 `77623af1d3773772f1cbf96d407b1835820f362c729938b89c7a41dc4493aed0`. The preserved `C/setup/cargo-lock.before` independently hashes to `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e`, matching the unreconciled lock reviewed above. No Cargo or other execution was performed.

V2 supersedes the initial generate-lockfile sequence with full `cargo metadata --offline --format-version 1` setup, omitting `--locked` only while the owner-authorized resolver may repair the private lock. It never uses `--no-deps`. The complete metadata result must be retained and its `packages` plus `resolve.nodes` reviewed for package/version/source/checksum/dependency changes, enabled features, single maintained package identities and internal local paths. Review must explain any departure from qualified owning jsonschema0.46.1 and any existing CLI package-version change. This is a setup result, not qualification by itself.

The plan then pauses progression, freezes reviewed successor source/lock/metadata pins, and requires full offline locked metadata admission with unchanged hashes before the existing twenty tests and binary build. Failure diagnostics/refusal attempts remain retained; the original lock remains recoverable. The setup timeout is narrowed to120 seconds. This preserves the required evidence gates and avoids treating shallow manifest inspection as complete graph admission.

No additional static concern identified. Missing inputs remain the actual Cargo-produced graph/lock successor, independent AFTER review and authorized execution receipts. V2 does not make the stale lock build-ready, establish full offline cache availability or grant execution. Its embedded review hashes refer to the pre-addendum certificates; this additive certificate now has a successor file hash rather than rewriting that historical plan evidence.

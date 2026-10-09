# Offline export registry pin: BEFORE code review

VERDICT: APPROVE the bounded implementation plan. This certificate reviews a proposed change, not completed code or runtime behavior.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Reviewed Integrity HEAD: `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Root owns implementation; this reviewer owns only this certificate. Other writers' files remain untouched.

Procedure: read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` in full and applied its source tracing, data-flow, branch, assertion and findings requirements. Read `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` in full before Rust review, plus its relevant application and universal guidelines. All observations below are static. No builds, tests, Cargo commands, live calls, cryptographic execution or private-key inspection occurred.

## 1. Patch summary

The CLI currently verifies an export using a signing registry supplied inside that export. The proposed optional `verify-export` argument supplies an independently selected SHA-256 digest of the exact registry bytes. The CLI checks that pin and then continues through the existing maintained Trellis/WOS verifier. This adds an external registry-snapshot selection step without changing the export format, production verification libraries, Trellis-owned code or cryptographic algorithms.

Proposed scope: Integrity CLI argument parsing, command orchestration, text/JSON output, direct existing-path `integrity-cbor` dependency and corresponding lockfile dependency list, documentation and focused tests. No D1-specific format or policy. The flag spelling remains an implementation choice; `--trusted-signing-registry-sha256 <64-lowercase-hex>` expresses its meaning clearly.

Important existing caller: `main` calls `cli::run` and maps errors to stderr and exit 1 (`crates/integrity-verify-cli/src/main.rs:27–36`). `run` dispatches `verify-export` through parsing and command execution (`src/cli.rs:86–88`). The generic `verify` branch is separate (`src/cli.rs:81–84`) and should retain its behavior.

Exploration notes: H1, the current CLI lacks external trust input, was confirmed by `VerifyExportArgs` and its parser (`src/cli.rs:102–105,144–179`). H2, raw registry pinning can reuse maintained primitives without copying COSE/profile interpretation, was confirmed by `integrity-cbor::sha256_bytes` and the verifier's registry resolution/signature/digest sequence. H3, selecting the first ZIP registry member would be equivalent to the verifier, was refuted by the verifier's overwrite behavior; unique selection is therefore a required plan invariant.

## 2. Function trace

Paths in this table are relative to `integrity-stack/`, except the explicitly marked sibling.

| Function | Source | Input → output | Verified behavior and proposed use |
| --- | --- | --- | --- |
| `main` | `crates/integrity-verify-cli/src/main.rs:27` | process args → exit status | Calls `run`; error means stderr and exit 1. |
| `run` | `crates/integrity-verify-cli/src/cli.rs:73` | args, writers → `Result` | Dispatches export command to parser and verifier. |
| `parse_verify_export_args` | `src/cli.rs:144` | strings → export args or error | Existing parser handles path/format; new optional pin must reject malformed values and repeated pin flags. |
| `verify_export_command` | `src/cli.rs:266` | parsed args → output or error | Reads ZIP once, calls WOS verifier, renders reports, rejects failures or failed structure/integrity. Add pin check on that same buffer before successful output. |
| `read_stored_zip` | `crates/integrity-bundle/src/lib.rs:91` | ZIP bytes → ordered entries or error | Validates supported ZIP structure and local payloads; retains individual entries (`:187–204`), permitting duplicate detection by the gate. |
| `BundleEntry::path` / `bytes` | `crates/integrity-bundle/src/lib.rs:41,47` | entry → borrowed path/raw bytes | Provides exact member selection and hash input. |
| `sha256_bytes` | `crates/integrity-cbor/src/lib.rs:132` | bytes → `[u8; 32]` | Calls maintained `Sha256::digest`; no JSON/CBOR decoding, framing or normalization. |
| WOS `verify_export_zip` | sibling `trellis/crates/trellis-verify-wos/src/lib.rs:46` | ZIP bytes → WOS report | Calls Integrity's verifier with maintained WOS record validator. No trusted-registry parameter exists on this entry point. |
| `verify_export_zip_with_record_validator` | `crates/integrity-verify/src/trellis/export.rs:162` | ZIP, validator → report | Parses embedded registry, resolves manifest kid, checks signature, checks required member digests (`:175–184,236–245,294–315`). |
| `parse_export_zip` | same file `:1680` | ZIP → member map | Strips first path component and inserts relative names into a `BTreeMap`; later duplicate relative names overwrite earlier ones. |
| `render_export_text` / `render_export_json` | `crates/integrity-verify-cli/src/cli.rs:494,524` | WOS report → serialized report | Existing fields describe maintained verification. Add distinct registry-pin evidence without changing the meaning of existing fields. |
| `verify_ed25519_sign1` | `crates/integrity-cose/src/lib.rs:621` | public key, COSE, optional detached bytes → result | Public maintained alternative exists for explicit-key verification, but using it here would add a second signature-verification path and policy selection. Registry pinning is the smaller change. |

## 3. Data flow and invariants

The independently supplied digest starts in process arguments, is validated before file verification, and is retained only as public expected-digest evidence. It must never be derived from the export and described as independent trust. Accept exactly 64 lowercase ASCII hexadecimal characters; reject duplicate pin flags even when identical.

The ZIP buffer is created by the command's existing single `fs::read` (`src/cli.rs:267`). Both pin extraction and maintained verification consume this same immutable buffer. Re-reading the pathname would allow file replacement between trust selection and verification.

Select entries using the same first-component split as the verifier: the relative name must equal `030-signing-key-registry.cbor`. Require exactly one matching entry, rejecting duplicates under the same or different roots. A broad suffix match could accept a nested decoy that the verifier would not use. A first-match selection could hash one entry while the verifier uses a later entry. Hash the raw selected bytes with `integrity_cbor::sha256_bytes`; do not decode and re-encode the registry.

When the supplied and observed digests match, continue the existing WOS call and all existing failure conditions (`src/cli.rs:273,299–306`). A matching pin alone must never produce successful verification. On mismatch, missing/ambiguous registry or malformed ZIP, return an ordinary error and prevent successful output. Untrusted file input must not trigger a new panic.

Report separate `matched` / `not_requested` pin state and expected/observed digest evidence where available. Existing `verified` reflects the maintained report checks (`src/cli.rs:550–558`); do not relabel it as exporter identity or agency authorization. With no flag, external registry selection was not requested. A matching registry snapshot can contain multiple signing keys and says nothing by itself about freshness, revocation, unique exporter identity or public-key provenance. Selecting the pin remains the caller's authority.

## 4. Test behavior and edge cases

Existing tests read: `verify_export_args_accept_flags` (`src/cli.rs:694`) asserts path and JSON format; `usage_declares_verify_export_command` (`:703`) asserts command presence. They should remain valid when the new argument is optional. The subprocess test `verify_export_command_reports_wos_export_summary` (`tests/verify_bundle.rs:112`) invokes a maintained fixture and asserts successful status, `verified=true` and `wos_failures=0` (`:122–139`). It establishes the legacy happy path only. The maintained hash test `sha256_bytes_matches_known_vector` (`integrity-cbor/src/lib.rs:749`) asserts the exact SHA-256 digest of `abc`.

No existing test covers the proposed pin path. The following are required test preparations, with predicted behavior rather than executed results:

| Case | Required assertions / predicted behavior |
| --- | --- |
| Pin absent | Existing verifier outcome unchanged; pin state explicitly `not_requested`. |
| Exact independently fixed fixture pin | Expected and observed digests equal; state `matched`; original successful verifier result remains successful. |
| Wrong pin | Non-success result/exit, mismatch diagnostic, no successful verification output. |
| Invalid length, uppercase, non-hex, non-ASCII, missing value | Argument refusal before verification. |
| Duplicate pin flag | Refusal, including two identical values; avoid last-value-wins trust selection. |
| Missing registry | Refusal with a concrete missing-member diagnostic. |
| Duplicate registry under same or different roots | Refusal; never first/last-match selection. A two-root bundle can be constructed with the maintained writer without duplicate full paths. |
| Nested suffix decoy | Does not count as the exact relative registry member. |
| Malformed ZIP | Maintained ZIP error becomes command error. |
| Correct registry pin plus damaged manifest/signature | Original verifier failure still controls exit; pin match cannot bypass crypto or structure checks. |
| Text, JSON and both output | Separate pin evidence is consistent; existing report fields retain meaning. |

No native execution is authorized in this review. Compilation, formatting/lint checks and focused/integration test execution remain unqualified until a later explicitly authorized execution window. An installed older binary cannot establish that the new flag works.

## 5. Findings

**F1 — WARNING / correctness — `integrity-verify/src/trellis/export.rs:1680–1692`.** The maintained parser overwrites duplicate relative member names, while `read_stored_zip` preserves entries (`integrity-bundle/src/lib.rs:187–204`). A first-match pin check could authenticate bytes different from those the verifier selects. Disposition: the approved plan explicitly requires exactly one matching registry member. No Trellis/core-parser edit is requested in this bounded task. The AFTER review must inspect the actual selection branch and negative assertions.

**F2 — OBSERVATION / test coverage — `integrity-verify-cli/tests/verify_bundle.rs:112–139`.** Current export tests assert embedded-registry verification only. They do not qualify independent trust pinning. Disposition: the test preparation above is required; all new behavior remains unexecuted at this BEFORE gate.

No blocker remains in the proposed shape when these invariants are implemented. A registry hash gate is intentionally narrower than single-exporter-key authorization; documentation must preserve that distinction.

## 6. Conclusion

VERDICT: APPROVE — static implementation-plan gate only.

Justification: an independently selected registry digest, checked against one exact raw registry member in the same ZIP bytes, composes with the existing signature and member-digest checks. Maintained ZIP and hash APIs avoid a custom format or cryptographic implementation. Existing report/exit checks remain authoritative. Coverage of proposed paths: ADEQUATE AS A TEST PLAN; IMPLEMENTATION AND EXECUTION NOT YET REVIEWED. Confidence: HIGH in the traced source and bounded design; no claim about unimplemented code or runtime results.

Reviewed-source SHA-256 pins:

```text
541d6e9954f089d7543296a2a5d7716c95361fa7881769be1553cd1ea2c16489  crates/integrity-verify-cli/src/cli.rs
2dcbd5cb26ee35b25b31f826d37019d4bed75f06520ad47d1a3640950fd561cf  crates/integrity-verify-cli/Cargo.toml
8b808b32522dadc7a0c8fdf80836fe033edfee81d47e32cb28423a8a15e0fb41  crates/integrity-verify-cli/tests/verify_bundle.rs
6047f50808c6bf5de093861dfa747a5d6d9e72f0cf5dd999e78ce234d7291467  crates/integrity-bundle/src/lib.rs
e7b15d2d259cfad8e0656e6dc19d67903863829d7d56c3240299565c43bd578b  crates/integrity-cbor/src/lib.rs
f086425340d4b71c495b926db53b7dc4bfe33765263e979f526b362379ee1fc9  crates/integrity-cose/src/lib.rs
95b42fe6b6c00e3c1bc7da24092d683f80cbfd48f30ce543113c52c73e70d0b6  crates/integrity-verify/src/trellis/export.rs
141c2a2c186fdec58d2407493b4845543640cfeff818346c496152adbef272db  ../trellis/crates/trellis-verify-wos/src/lib.rs
```

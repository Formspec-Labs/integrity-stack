# Offline export registry pin: AFTER code review

VERDICT: APPROVE for the bounded static code gate. No blocking correctness or security defect found. Native compilation, test execution and operational qualification remain pending.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Baseline: Integrity HEAD `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Reviewed current working-tree changes in exactly `crates/integrity-verify-cli/{Cargo.toml,Cargo.lock,src/cli.rs,tests/verify_bundle.rs}` and `docs/offline-export-registry-pin.md`. The four tracked code/configuration files' `git diff --binary HEAD -- <four paths>` SHA-256 is `cb34fe67d2488d668014630618ad8169a3d3d554f3a41a171562f8b071da1d45`; the separately pinned documentation file is listed below. This certificate is the reviewer's only write.

Procedure: fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` before review, including relevant application and universal Rust guidance. Read all five scoped files, the exact diff, important callers/callees and actual test assertions. This is static analysis: no builds, Cargo commands, test execution, native execution or live calls. Root reports rustfmt and whitespace checks passed; this reviewer did not execute or independently qualify those checks. The BEFORE certificate is `docs/offline-export-trust-before-code.md`.

## 1. Patch summary

The CLI adds optional `--trusted-signing-key-registry-sha256` to `verify-export`. It checks an operator-supplied digest against exactly one raw signing-registry ZIP member before running the maintained Trellis/WOS verification on the same bytes. It reports registry selection separately from archive verification. No export format, cryptographic algorithm, public verification-library API or Trellis-owned implementation changes.

Directly affected functions are `parse_verify_export_args` (`crates/integrity-verify-cli/src/cli.rs:150`), `verify_export_command` (`:293`), new `check_registry_pin` (`:341`), new `registry_pin_status` (`:373`), `render_export_text` (`:564`) and `render_export_json` (`:603`). `run` is their important dispatcher caller (`:91–93`); process `main` maps `run` errors to stderr and exit 1 (`src/main.rs:27–36`). Generic `verify` parsing, orchestration and serialization remain outside the changed paths.

The manifest adds a direct path dependency on existing `integrity-cbor` (`Cargo.toml:21`). The lockfile adds only that dependency edge to the CLI package (`Cargo.lock:333–345`); the existing package and SHA-256 dependency already exist (`:284–292`). No new version resolution or registry package is introduced by the diff.

Exploration hypotheses: H1, the implementation checks precisely the bytes used by the verifier, is confirmed by one file read and borrowed-buffer calls (`cli.rs:294–302`). H2, duplicate relative registry names could bypass selection, is refuted for the new gate by counting entries before map collection (`:349–359`). H3, a matching pin could bypass archive verification, is refuted by the unconditional maintained verifier call and unchanged failure predicates (`:302,328–335`). H4, report evidence might be inferred without checking, is refined: serializers reuse the expected digest as observed only after the command's successful equality check; their private production caller preserves that invariant.

## 2. Function trace

Paths below are relative to `crates/integrity-verify-cli/` unless specified.

| Function | File:line | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| `main` | `src/main.rs:27` | args → process status | Calls `run`; errors produce stderr and exit 1. |
| `run` | `src/cli.rs:78` | args/writers → `Result` | Export branch parses args and calls export command; generic branch stays separate. |
| `parse_verify_export_args` | `src/cli.rs:150` | tokens → args/error | Keeps path/format handling; accepts one pin, requires value, validates 64 ASCII lowercase hexadecimal bytes, rejects duplicates (`:166–183`). |
| `verify_export_command` | `src/cli.rs:293` | args → output/error | Reads once, pin-checks before output, calls WOS verifier, renders chosen format, retains all original failure conditions. |
| `check_registry_pin` | `src/cli.rs:341` | ZIP bytes + optional expected digest → `Result` | No pin returns immediately; otherwise maintained ZIP parse, exact relative member count, raw SHA-256, equality or error. |
| `registry_pin_status` | `src/cli.rs:373` | optional pin → static label | `Some` yields `matched`; command only renders after pin validation. `None` yields `not_requested`. |
| `render_export_text` | `src/cli.rs:564` | WOS report + validated optional pin → string | Adds separate pin state; prints expected/observed only when selected; preserves report fields. |
| `render_export_json` | `src/cli.rs:603` | same → JSON/error | Adds pin object; `None` serializes to null digest fields. Original `verified` conjunction is unchanged (`:636–642`). |
| `export_failure_count` and helpers | `src/cli.rs:673,677,683` | WOS report → count | Counts event/checkpoint/proof failures and WOS severity `Failure`; unchanged. |
| `read_stored_zip` | `../integrity-bundle/src/lib.rs:91` | bytes → entries/error | Maintained ZIP validation preserves entries individually (`:187–204`), enabling duplicate refusal. |
| `sha256_bytes` | `../integrity-cbor/src/lib.rs:132` | raw bytes → 32-byte digest | Existing maintained `Sha256::digest`; CLI only formats lowercase hexadecimal. |
| WOS `verify_export_zip` | sibling `trellis/crates/trellis-verify-wos/src/lib.rs:46` | ZIP → report | Existing adapter delegates to maintained Integrity export verifier and WOS validator. |
| Export verification | `../integrity-verify/src/trellis/export.rs:162` | ZIP/validator → report | Embedded registry resolution, manifest signature validation, registry member-digest validation remain at `:175–184,236–245,294–315`. |

## 3. Data flow and invariants

The expected digest enters from process arguments, is cloned into `VerifyExportArgs` after strict validation (`cli.rs:166–183`), then borrowed by the gate and serializers (`:301–304`). It is public evidence, not private material. The CLI cannot determine whether an operator actually selected it independently; documentation makes that caller responsibility explicit (`docs/offline-export-registry-pin.md:3`).

The owned ZIP buffer starts at the single `fs::read` (`:294`), is never mutated, and reaches both `check_registry_pin` and WOS verification (`:301–302`). There is no pathname re-read between checks. Gate-local parsed entries and observed digest do not escape; the observed digest is compared before returning success (`:361–370`).

Selection follows the verifier's first-root-component rule exactly: `split_once('/')` with exact relative equality to `030-signing-key-registry.cbor` (`:349–354`). Missing entries and a second matching entry are errors (`:355–359`). The maintained verifier's `parse_export_zip` currently inserts relative names into a `BTreeMap`, overwriting duplicates (`integrity-verify/src/trellis/export.rs:1680–1692`). The new gate prevents that selection differential for the registry, including same-path and different-root duplicates. It does not claim broader archive path-policy changes.

Hash input is `registry.bytes()` (`cli.rs:361`), with no decoding, re-encoding, normalization or domain framing. Expected and observed lowercase hexadecimal strings must match (`:365`). Mismatch returns before the WOS call or any stdout write (`:301–313`). A missing pin preserves existing embedded-registry semantics (`:342–344`), visibly labeled `not_requested`.

The serializer's observed digest equals the expected digest because the only production caller first obtains a successful equality result. This is sound in the current private call graph, including a matched pin followed by failed archive verification: the report may correctly say `matched` and `verified=false`. Existing report/exit predicates remain unchanged (`:328–335,636–642`); pin equality never grants archive success.

The documentation accurately limits registry selection: no agency authority, signer identity, freshness, disclosure authorization, service activation, missing evidence creation or new library API (`docs/offline-export-registry-pin.md:3–7,11–19`). Real D1 evidence and coordinated runtime publication remain separate requirements. The practical simplification is reuse of maintained ZIP, hash and verification primitives rather than a second COSE/profile verifier. No performance improvement is claimed; the pinned path intentionally performs a second ZIP parse.

## 4. Test behavior and edge cases

All outcomes below are source-based predictions, not executed results.

| Test | Source | Assertion trace and predicted behavior |
| --- | --- | --- |
| `verify_export_args_accept_flags` | `src/cli.rs:784` | Existing path/format assertions remain valid with optional pin absent. |
| `registry_pin_args_refuse_invalid_or_duplicate_selection` | `:803` | Empty, short, uppercase, non-hex and long strings fail; missing value and repeated identical flags fail; known valid pin is preserved. Parser predicates support each assertion. |
| `registry_pin_matches_exact_raw_member_and_refuses_other_snapshot` | `:841` | Maintained writer embeds raw `abc`; hardcoded known SHA-256 succeeds; zeros mismatch and diagnostic includes observed digest; absent pin succeeds with `not_requested`. |
| `registry_pin_refuses_missing_ambiguous_nested_and_malformed_members` | `:852` | Missing/rootless/nested-only paths fail; different-root duplicates fail as ambiguous; modifying both ZIP filename copies produces same-path duplicates that must also fail; malformed ZIP fails. Payload bytes/CRC remain unchanged in duplicate construction. |
| `matching_registry_does_not_bypass_native_export_verification` | `:885` | Raw `abc` pin matches but invalid registry/archive fails maintained verification; asserts error, `verified=false`, pin `matched`. |
| `matching_registry_does_not_bypass_manifest_signature_failure` | `:913` | Rebuilds native fixture after flipping final manifest byte; preserves registry; asserts command error, `verified=false`, pin `matched`, integrity false. Existing verifier checks manifest signature (`integrity-verify/src/trellis/export.rs:245`). |
| `verify_export_command_reports_wos_export_summary` | `tests/verify_bundle.rs:112` | Existing native-fixture success assertions retained; new assertions require `not_requested` and null expected digest. |
| `verify_export_accepts_selected_snapshot_and_refuses_foreign_snapshot` | `tests/verify_bundle.rs:150` | Same native fixture tested against its fixed expected pin and a different fixed registry pin. Match requires successful status, verified true, matched state and both digest fields. Mismatch requires failed status, empty stdout and mismatch stderr. |

The last test exercises a foreign snapshot digest against fixture 001; it does not execute verification of fixture 005 or prove a full attacker-generated substitution scenario. The exact-equality gate makes that narrower test sufficient for its stated input behavior. The fixture's expected registry pin is a retained synthetic test constant, not production trust provenance.

Coverage gaps: no dedicated assertions for text/both pin output, null observed digest when unselected, non-ASCII syntax, or a nested decoy alongside a valid exact member. Static branch tracing supports the intended behavior; these are nonblocking omissions for the bounded change. Unit and integration compilation/execution remain entirely unqualified. Existing generic `verify` tests and code were read; their production paths are unchanged.

## 5. Findings

**F1 — OBSERVATION / correctness — `src/cli.rs:349–359`.** BEFORE duplicate-selection concern is resolved: the gate counts raw entries and refuses a second exact relative registry name before hashing. Tests at `:852–881` explicitly prepare both root and same-path ambiguity cases. No unresolved selection bypass found in the reviewed call graph.

**F2 — OBSERVATION / test coverage — `src/cli.rs:564–575` and `tests/verify_bundle.rs:150–192`.** JSON positive/negative evidence is asserted, while text/both pin serialization has no dedicated regression assertion. Current private callers and output branches are straightforward and consistent. Suggested follow-up: add text/both assertions when completing native test qualification; no correctness defect found that requires blocking this static gate.

**F3 — OBSERVATION / qualification — `docs/offline-export-registry-pin.md:11,19`.** Prepared tests have not been compiled or executed. The documentation correctly states the limitation. This approval provides no native-build authorization, installed-binary capability claim, operational trust claim or actual D1 export proof.

## 6. Conclusion

VERDICT: APPROVE.

The patch achieves the bounded intent: a strict independently supplied registry-snapshot digest gates the maintained verifier on the same archive bytes, rejects ambiguous selection, and leaves all original verification requirements intact. Coverage of changed paths: ADEQUATE for static code review, with minor output assertion gaps explicitly recorded; execution coverage remains pending. Confidence: HIGH in source/data-flow review; compilation and runtime behavior are unqualified.

Exact reviewed file SHA-256 pins:

```text
a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a  crates/integrity-verify-cli/Cargo.toml
c3549e67ad697f4cd03f9752a53d308b88ec469b5abf8c60eebd85d880ecec66  crates/integrity-verify-cli/Cargo.lock
ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9  crates/integrity-verify-cli/src/cli.rs
addf2343978168bb92439332db0af34ae0dbcfb19de6908580a854aa19bc2ea8  crates/integrity-verify-cli/tests/verify_bundle.rs
1ee7d1511a3b4d8cb2109a92df621d78c99ce575db6b2f87d450107d945548c2  docs/offline-export-registry-pin.md
```

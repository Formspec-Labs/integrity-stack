# Native provenance whole-ZIP successor: static code review

VERDICT: APPROVE the bounded two-file test successor. The maintained verifier API and report assertions are sound. Compilation, execution, dependency/lock closure, complete D1 and adoption remain unqualified.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-09. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, including relevant Rust guidance consulted during the preceding reviews. Static inspection only: no Cargo/build/native execution, tests or live calls. Only this certificate was written. Existing execution receipts and certificates remain unchanged.

## 1. Patch summary and identity

Private source root `C`: `/private/tmp/core-native-zip-verification-v1-20261009/work-spec`; base `2f712020b9255168395e814c5209f493c585af16`. Read both touched files in full and inspected the complete diff: one development dependency and 44 test/helper lines, no production implementation change.

Independently recomputed pins:

| Input | SHA-256 |
| --- | --- |
| `/private/tmp/core-native-zip-verification-v1-20261009/source-pins.json` | `ea94e8c6dcf85601384688373c53b6dd0b553ac9ecf307eeaf6c6e92b9d2db89` |
| `C/crates/wos-runtime/Cargo.toml` | `a0cf304006bc0de5958c933408528faf5437a72161408f2ba0d0ee4a9806575e` |
| `C/crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs` | `ff34f93246cf88282fae38891a6f6ce0b45a8ba0a847478bf816f9128d078cf6` |
| Two-file binary diff against base | `6ebf640c18c4e644bc5132cc91fb5121e22f9b2176a379c82d58109efd1f8089` |

The existing full-window router test now passes the exact fetched `head_before` ZIP to `trellis_verify_wos::verify_export_zip`, requires structural/integrity/overall validity, and tests refusal of a separately repacked archive with an altered generic record. The Cargo dependency is under `[dev-dependencies]` (:29–39). The test file is included inside the runtime test module (`C/.../src/runtime.rs:742–745`).

Hypotheses before tracing: H1, the owning API might not return these report fields, refuted by actual exports/report definitions. H2, structural archive refusal might leave integrity true, refuted by the fatal-report constructor. H3, mutable map access might return a temporary or wrong value, refuted by the explicit input lifetime and reference to the original tuple value. H4, the tamper test reaches domain schema validation, refined: it normally stops earlier at manifest member-digest refusal. No unresolved static blocker.

## 2. Function trace

`T` below is `/Users/mikewolfd/Work/formspec-stack/.trellis-native-provenance-v1`; `I` is `/Users/mikewolfd/Work/formspec-stack/integrity-stack`. Read maintained callees. The inspected `I` export.rs/types.rs hashes match the corresponding private Integrity dependency used by `T` exactly (`95b42fe6…` / `dca252be…`).

| Function / rule | File:line | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| `native_provenance_full_window_preserves_every_original_record_and_replays` | `C/.../custody_trellis_router_tests.rs:108–243` | actual runtime window → maintained local router ZIP, verifier reports | Fetches full head at :162; calls verifier on those exact bytes at :166; preserves original record/order/stamp/replay assertions. |
| `native_test_cbor_field` | same file:245–248 | `&'a mut Value`, field name → `&'a mut Value` | Requires map, finds matching text key, returns tuple value reference; missing/wrong controlled fixture shape panics. No copying or lifetime escape. |
| `trellis_verify_wos::verify_export_zip` | `T/crates/trellis-verify-wos/src/lib.rs:47–49` | ZIP slice → `WosVerificationReport` | Delegates to maintained Integrity verifier with actual `WosRecordValidator`; converts substrate/domain report. |
| `verify_export_zip_with_validator` | `I/crates/integrity-verify/src/trellis/export.rs:43–70` | ZIP/validator → substrate plus findings | Runs substrate checks first; structural failure returns without domain validation. Otherwise parses domain events and runs event/export validators. |
| `verify_export_zip_with_record_validator` | same file:161–250,293–328 | archive bytes → substrate report | Parses embedded registry; checks manifest signature; hashes required members including `010-events.cbor`; mismatch returns ArchiveIntegrityFailure. |
| `VerificationReport::fatal` | `I/.../trellis/types.rs:211–229` | failure kind/message → report | Sets structure, integrity and readability false. Justifies negative integrity assertion even on early structural refusal. |
| `WosVerificationReport::relying_party_valid` | `T/.../src/findings.rs:33–50` | report → boolean | Derives substrate/domain verdict and requires `RelyingPartyResult::Valid`. Substrate structure/integrity failure fails cryptographic tier (`I/.../trellis/validator.rs:82–89`). |
| Bundle construction/encoding | `I/crates/integrity-bundle/src/lib.rs:32,216–267` | entry paths/bytes → stored ZIP | Adds owned entries; deterministic writer sorts and validates paths, regenerates ZIP checksums, rejects duplicates. It does not rewrite retained manifest or event signatures. |
| `encode_cbor_value` | `I/crates/integrity-cbor/src/lib.rs:209–213` | Value → bytes | Maintained ciborium serialization without recursive canonicalization; suitable for deliberately altered evidence. |

## 3. Data flow and invariants

`head_before` is an owned fetched byte vector (:162). The positive verifier receives its borrowed slice; its digest is captured before tampering (:163). Parsed `events` are cloned at :198. Only the cloned selected event's COSE payload slot 2 changes (:200–213); protected/unprotected headers and signature slot remain intact. The mutation descends through `payload_ref.ciphertext.record.recordKind`, setting a different literal. Existing payload and canonical-event hashes are deliberately not recomputed.

The selected position comes from the same full input order already checked against event sequence/type/record equality (:173–193), so it targets an existing generic event, not a fabricated replacement. The CBOR helper's mutable borrow ends after each use; Rust nonlexical lifetimes allow encoding the parent after the child assignment. Both tagged COSE tag18 and untagged array shapes are handled. Unexpected shapes/absent generic input panic, which correctly fails this controlled test.

Repacking replaces only the selected events member bytes; all other entries are cloned byte-for-byte (:215–220). The manifest therefore retains its signature and original events digest. The ZIP writer regenerates archive checksums, so refusal exercises maintained export validation rather than merely a stale ZIP CRC. Changed member bytes cause the required manifest digest comparison to fail before event/domain checks (`I/.../export.rs:293–328`); fatal sets integrity false. The original ZIP digest is checked at :225, and actual server head byte equality remains asserted after replay/conflict/stamped retry at :241–242.

## 4. Test behavior and edge cases

The one changed test is `native_provenance_full_window_preserves_every_original_record_and_replays` (`C/.../custody_trellis_router_tests.rs:108`). Its existing actual runtime actions generate OnEntry, timer/task creation/presentation and state-transition records (:112–139); the complete window is appended through the maintained in-memory HTTP router (:141–162).

- Positive path (:166–169): requires structure, cryptographic integrity and overall relying-party validity on the exact original head ZIP. This meaningfully closes the earlier separation between window export and owning verifier in the prepared test. Actual pass is not established until authorized execution.
- Tamper path (:198–224): changes original generic recordKind, preserves signatures/manifest, repacks via maintained Bundle, and requires both overall invalidity and integrity false. Static expectation: passes by required events-member digest refusal, not a claim that the unknown kind reached the schema.
- Preservation (:225–242): original byte hash and later head equality guard against modifying original evidence or persistent state during negative verification; existing field/order/stamp/replay/conflict checks continue.
- Edge cases: malformed/missing controlled CBOR fields panic rather than silently skip; no generic record also panics. Existing full-window assertions ensure generic OnEntry is present. Independent publisher/agency trust is explicitly excluded at :164–165; this test uses embedded registry authority.

No tests were run by this reviewer. The successor has no retained execution receipt yet; prior successful suites cannot be relabeled as execution of these new assertions. The added development dependency's lock reconciliation and compilation remain pending owner work.

## 5. Findings

OBSERVATION 1 — test-coverage. Location: test :222–224; maintained export.rs:293–328. The negative proves whole-archive rejection of tampered signed evidence, normally through manifest digest mismatch. It does not independently prove domain-specific unknown-kind refusal on an otherwise valid re-signed archive. This is appropriate for the requested tamper test; retain the prior six adapter tests as separate domain coverage. No change required.

OBSERVATION 2 — qualification boundary. Location: Cargo.toml:39; source-pins.json:2. The patch is a private uncompiled successor. Exact source approval does not establish resolved sibling paths, locked dependency closure, runtime pass or independent trust. Owner must retain a new pinned authorized run before claiming whole-window ZIP verification passed. No execution authorization is granted by this certificate.

No blocking static finding.

## 6. Conclusion

VERDICT: APPROVE.

- The two-file successor uses the maintained owning verifier on the same runtime-window ZIP and prepares a valid archive-tamper refusal check while preserving original evidence.
- Coverage of changed paths: ADEQUATE for the stated positive whole-ZIP and preserved-signature tamper test.
- Confidence: HIGH for API/report/data-flow reasoning; compilation and runtime behavior remain unexecuted and unqualified.
- Existing execution evidence remains unchanged. Complete D1, independent agency trust, portable build closure, live service state and adoption are outside this approval.

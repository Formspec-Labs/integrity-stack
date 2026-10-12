# Native provenance shared source: static AFTER code review

VERDICT: APPROVE the actual shared helper/schema and unchanged offline adapter alignment within this review scope. No blocking static defect found. Compilation, dependency-lock closure, portable patch closure, native tests, real custody-window execution and adoption remain unqualified.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, with relevant Rust guidance from this session. Read the complete actual helper, schema and helper tests; traced maintained decoder, conversion, enum, native ID, schema-library and custody-encoder seams. Compared all three integrated offline files with preparation pins. No Cargo, native command, build, test execution or live call. Only this certificate was written.

## 1. Patch summary and scope

Core root: `/private/tmp/core-native-provenance-v1-20261009/work-spec`. Source manifest: `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-source-v1.json`, SHA-256 `d2ff5275a96069351e1984ca750f636f5741b5f30c51979555ac6bc285d649b3`. Its status explicitly says uncompiled and closure pending. This review focuses on `crates/wos-events/src/native_provenance.rs`, its `tests.rs`, owning schema, exports/dependency declarations and offline adapter alignment. It does not certify every runtime/wider producer file in the twelve-file manifest; Core's wider reviews cover those.

The helper implements the agreed constant and raw-value-owning constructors/accessors. Shared policy validates explicit known noncanonical kinds, native record IDs, closed schema and JSON-compatible numeric/depth bounds. Wrapped and bare CBOR constructors share strict byte admission, with a narrowly allowed timestamp tag in the bare source only. The offline adapter calls the wrapped constructor directly and emits safe blocking findings on errors.

Integrated offline root: `/Users/mikewolfd/Work/formspec-stack/.trellis-native-provenance-v1`. Its three file hashes exactly match `native-provenance-after-code-preparation.md`; the reviewed patch remains `bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97`.

Exploration hypotheses: H1, actual helper admission preserves all accepted raw fields, confirmed by `value.clone()` after validation. H2, lossy CBOR conversion can hide ambiguity before validation, refuted by strict subset and duplicate checks preceding conversion. H3, bare timestamp policy accidentally relaxes wrapped payloads, refuted by the explicit bare flag and exact path test. H4, JSON and CBOR depth bounds differ by the added wrapper, refuted by bare decoding starting at depth 1 while JSON/wrapped start at 0. H5, schema-library API assumptions are unsupported, refuted by inspecting locally retained locked jsonschema 0.46.1 source.

## 2. Function trace

Core locations are relative to its root unless otherwise marked.

| Function / interface | File:line | Input → output | Verified behavior |
| --- | --- | --- | --- |
| `from_json` | `crates/wos-events/src/native_provenance.rs:57` | raw wrapped JSON → helper/error | Subset first, explicit enum parse, canonical exclusion, native ID validation, cached schema validation, exact input clone. |
| `from_record` | same file:86 | typed source → helper/error | Serializes once, wraps, delegates to `from_json`; not used to validate raw custody bytes. |
| `from_dcbor_slice` | same file:97 | wrapped bytes → helper/error | Strict decode with bare=false, then raw JSON admission. |
| `from_record_dcbor_slice` | same file:109 | bare authored bytes → helper/error | Strict bare decode, adds wrapper, delegates to JSON admission. |
| `payload` / `record` / kind / ID accessors | same file:116–126 | validated helper → borrowed values/copy | Exposes retained values; fields are private and no mutating accessors exist. |
| `validate_json_subset` | same file:129 | value + depth → result | Signed-i64 integers, finite nonnegative-zero floats, recursive depth ≤128. |
| `decode_original` | same file:148 | bytes + bare policy → JSON/error | Complete maintained decode → bounded subset → recursive canonical validation → conversion of ORIGINAL decoded value. Sorted validation clone is discarded. |
| `validate_cbor_subset` | same file:159 | CBOR, path, depth, bare → result | Text map keys only; no bytes/tags except bare root timestamp tag0/text; traverses arrays/maps with depth checks. |
| `decode_cbor_value` | maintained Integrity `integrity-cbor/src/lib.rs:140` | bytes → CBOR/error | Rejects trailing input. Underlying ciborium 0.2.2 uses a 256 recursion limit (`src/de/mod.rs:847`), before helper's depth128 traversal. |
| `canonicalize_cbor_value` | same Integrity file:158 | CBOR → validated clone/error | Recursively rejects duplicate canonical map keys, nonfinite floats and negative zero before inspection conversion. |
| `cbor_value_to_json` | same Integrity file:298 | admitted CBOR → JSON/error | Signed-i64 conversion, supported floats; duplicate insertion/tag stripping cannot bypass prior validation. |
| `is_valid_record_type_id` | maintained `stack-common-typeid/src/lib.rs:292` | text → bool | Parses native TypeID, restricts record families; helper calls directly. |
| Schema construction/validation | helper:70–78 | embedded schema + JSON → result | Cached `Result`; initialization errors refuse; formats explicitly enabled; errors report path rather than original value. |
| Offline `validate_native_provenance` | integrated `trellis-verify-wos/src/native_provenance.rs:10` | events → findings | Uses exact shared constant and wrapped constructor; unavailable/error → Failure/hash; unrelated event types unchanged. |

## 3. Data flow and invariants

The helper owns a clone of the entire original accepted JSON payload (`:79`), not a typed deserialize/reserialize of the record. Only `recordKind` is parsed into the shared enum and ID is separately retained; arbitrary permitted application `data` and all accepted structural fields survive unchanged. Constructors are fallible and private fields preserve their validated invariant. Schema initialization is cached as success or failure and never silently falls back to permissive admission.

The schema closes both wrapper and record (`schema:7,14`), requires id/recordKind/timestamp/auditLayer/definitionVersion (`:15–22`), includes the current twenty serialized native fields, and preserves unconstrained application data within preflight limits. Local `$defs` describe snapshot and outcome fields; there is no external schema retrieval reference. Existing canonical kind exclusion is independently enforced by `canonical_event_literal().is_some()` (`helper:64`) as well as the remaining-kind schema enum. Generic interpretation therefore cannot bypass specialized canonical routes.

JSON depth starts at zero and counts value nesting. Wrapped CBOR also starts at zero; bare CBOR starts at one (`:151`) to account for the wrapper added afterward. The same final `from_json` validation applies in all cases. JSON rejects unsigned integers above i64::MAX and negative-zero floats; CBOR conversion rejects integers outside i64 and canonical validation rejects nonfinite/negative-zero floats. Finite floats retain the maintained bridge's accepted domain. No claim is made that integer-versus-float representation or JSON spelling is byte-identical; signed bytes remain independent substrate evidence.

CBOR subset checking bounds recursion before maintained recursive canonical validation and JSON conversion. Map keys must be text. Duplicate keys are still present in the CBOR map when canonical validation runs, so none can be erased by subsequent JSON insertion. Wrapped payloads allow no tags or byte strings. Bare policy permits only tag0 with a text child when the tracked path is exactly `[timestamp]` (`:165–168`). Array components add path segments, preventing a nested/array timestamp from impersonating the bare root. The owning custody encoder actually tags that field (`custody.rs:313`); its text then receives schema RFC3339 format validation. Original custody bytes are never modified.

Offline files still use the existing WOS-owned dependency boundary. Their fixed messages discard detailed Core errors and raw record values; unavailable/invalid generic payloads become blocking domain findings. The actual shared exports now resolve the earlier API-shape prerequisite statically (`wos-events/src/lib.rs:16–21`). No additional decoder or schema exists in the adapter.

The Core private manifest currently uses absolute sibling paths and declares jsonschema 0.46 with default features disabled. Those are explicit private graph setup, not portable release wiring. The lock contains 0.46.1; its local `options.rs:350` confirms format enforcement override, `validator.rs:348` confirms validate's Result API, and error.rs confirms instance_path access. Native compilation and final lock consistency are not established by this source inspection.

## 4. Actual test assertions and edge cases

All tests below were read; none were executed in this review.

| Core helper test | tests.rs line | Assertion trace / predicted result |
| --- | --- | --- |
| Registry parity and every known route | 18 | Iterates owning registry; 28 canonical kinds return CanonicalKind; 106 remaining kinds retain full record, kind and ID; schema enum equals registry remainder. Supports accepted vocabulary consistency without adapter list duplication. |
| Original JSON and actual timestamp tag | 48 | Uses actual custody context/metadata/encoder; asserts original root timestamp has tag0, bare constructor retains entire JSON and input bytes, wrapped maintained encoder round-trips with no tags. |
| Missing/unknown/malformed fields | 68 | Removes each required field, mutates IDs/kinds/time/audit/types/hash, adds unknown wrapper/record fields and malformed roots; requires errors. |
| Numeric and depth bounds | 88 | Rejects u64::MAX/negative zero; accepts i64 extremes and finite float through JSON and CBOR; depth128 succeeds, one additional nesting fails through both constructors. |
| Duplicate keys | 107 | Duplicate wrapped key and bare map key must yield InvalidCbor before conversion. |
| Bytes/tags/trailing input | 119 | Unsupported bytes/tag32/tag0 in wrapped payload yield InvalidCbor; bare misplaced tag and trailing wrapped input refuse. |

The unchanged offline suite supplies complementary duplicate recordKind/nested-key tests, wrapped timestamp-tag rejection in an otherwise valid record, byte data, excessive depth, complete raw-record preservation, mixed event dispatch and a blocking relying-party verdict. Existing record fields, constructors, report/finding aliases and enum variants match the test interfaces. No static test interface defect found.

Coverage gaps: helper tests do not separately exercise all bare tag edge cases (nested timestamp, non-text tag child, repeated tags), every raw unsigned-CBOR/nonnumeric scalar edge, or failing schema construction. Code paths are explicit and offline negatives cover several complementary branches. Registry parity iterates registry entries and checks schema agreement; it is not proof that a separate future Rust enum variant absent from the registry would be discovered automatically. Joint owner qualification still needs the genuine complete runtime window and signed export verification, not just these helper/DomainEvent tests.

## 5. Findings

**F1 — OBSERVATION / correctness — helper:148–168.** The actual helper resolves the earlier lossy-conversion concern: complete decoding, bounded type policy and maintained duplicate validation precede conversion. Bare timestamp exception is narrow and wrapped policy remains strict. Disposition: APPROVE the inspected behavior; no adapter correction required.

**F2 — OBSERVATION / fidelity — helper:57–79 and schema:7–22.** Explicit kind/ID/schema checks operate on raw values and retain the complete admitted input. Unknown structural fields refuse rather than disappear. Disposition: APPROVE field-preservation alignment.

**F3 — OBSERVATION / qualification — source manifest status and private Cargo.toml:11–17.** Absolute private graph paths and final lock/compilation/test closure remain pending. This review must not be used as portable patch approval, runtime PASS or adoption authority. Disposition: retain those gates and the narrower source verdict.

No blocking static correctness, privacy or baseline interface defect found in the focused shared-source/adapter scope.

## 6. Conclusion and pins

VERDICT: APPROVE the actual helper/schema and integrated offline adapter alignment. Coverage: ADEQUATE for focused static review and meaningful prepared assertions; execution remains unqualified. Confidence: HIGH in inspected source behavior and maintained API traces. Wider runtime producer changes remain under separate owner reviews.

```text
d2ff5275a96069351e1984ca750f636f5741b5f30c51979555ac6bc285d649b3  native-provenance-core-source-v1.json
09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d  Core crates/wos-events/src/native_provenance.rs
c078ca577dcde0e4da7fe35d26071843086b842d47c60797c73dc554a7189e14  Core crates/wos-events/src/native_provenance/tests.rs
c0de3586a1880ead199c8aa12b8543e8e62c422c674f00e53f576226daf2cd54  Core schemas/wos-native-provenance-event.schema.json
b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9  integrated offline src/lib.rs
e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0  integrated offline src/validator.rs
82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67  integrated offline src/native_provenance.rs
```

Complete twelve-file Core closure independently rehashed at finalization; all match the manifest. These identity checks do not expand this certificate's behavioral review to the wider runtime files:

```text
df68298fac7a7e3cc71e6d9322cfa20c001b67df62b1f9e50d693c535aca43d6  Cargo.lock
f33d7aa7f5f83186486ac8b9c1a2c98980d486b5eca4fbee65ea6200fd2883f1  Cargo.toml
3e72b553b9ecb6da3eae38a303f3b90d6663941b34a452b2492a8a833069bfde  crates/wos-events/Cargo.toml
aa0b000c99c5a22e4ff51e20b7e7bdcdb8afc6384e7c3ee9dcff1f43788f548b  crates/wos-events/src/custody.rs
dd05c4049dad3397ddf734a9b9ae729d297fe96db97df2eea64a81720dd19f33  crates/wos-events/src/lib.rs
09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d  crates/wos-events/src/native_provenance.rs
c078ca577dcde0e4da7fe35d26071843086b842d47c60797c73dc554a7189e14  crates/wos-events/src/native_provenance/tests.rs
2af3ef357457de0743ea3f6145dd2ffea23334afba0362b0f3a08b3425df4b18  crates/wos-runtime/Cargo.toml
a061bb4c8673d9fba022fd1c128b3b208cb2a56ddc6e44c0d46089b1c06e4ee0  crates/wos-runtime/src/runtime.rs
fa176f423798224ea349e4e072508027d64ef40b0543e04fa5495f1fc674dee4  crates/wos-runtime/src/runtime/custody_trellis.rs
cc77c3863df3ea9baa5270403a52de29f6bc5b7b6e2cbc4a53df8b2269b3b0b7  crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs
c0de3586a1880ead199c8aa12b8543e8e62c422c674f00e53f576226daf2cd54  schemas/wos-native-provenance-event.schema.json
```

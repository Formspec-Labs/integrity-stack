# Native provenance offline interpretation: BEFORE code review

VERDICT: APPROVE the bounded adapter plan, with the shared helper API and strict byte-decoding behavior required to be frozen before implementation. This is a static plan gate, not approval of an unimplemented helper or execution result.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`; consulted relevant universal, application and library guidance. No builds, tests, Cargo commands, live calls or implementation edits. This certificate is the only reviewer write. Trellis-owned checkout remains untouched.

## 1. Patch summary

The joint plan retains existing canonical WOS event kinds and represents other known native provenance kinds under neutral `wos.provenance.recorded`, with payload exactly `{record: <full original JSON record>}`. Explicit `recordKind` remains mandatory inside the original record. Core owns the shared `NativeProvenanceEvent` helper and kind policy; Trellis owns registration, admission and client integration. The proposed offline contribution is a private candidate patch to Trellis's WOS validator, integrating a small `native_provenance` module through `validator.rs` and a module declaration in `lib.rs`, plus narrow tests. Trellis owner integrates the patch. No WOS dependency is introduced into Integrity core.

The owner's 134 total / 28 canonical / 106 remaining counts are intended acceptance inventory, not independently counted in this review. The adapter must not copy the remaining-kind list. Existing `ProvenanceKind` is the shared serde discriminator (`work-spec/crates/wos-events/src/provenance/kind.rs:6–8`); `canonical_event_literal` is the existing canonical-kind authority (`:503–511`).

Direct behavior change: `WosRecordValidator::validate_events` currently composes rescission and clock checks (`trellis/crates/trellis-verify-wos/src/validator.rs:22–26`). Add native-provenance validation there, preserving both existing checks and `validate_export` behavior. The shared API is pending; no exact signature is certified yet.

Exploration hypotheses: H1, one validator integration point covers export and ledger paths, confirmed by Integrity export.rs:61 and trellis/mod.rs:925. H2, a maintained CBOR-to-JSON inspection conversion alone is strict wire validation, refuted: it overwrites duplicate map keys and transforms byte strings/tags. H3, resolving the ambiguity requires a custom duplicate-key walker, refuted by the existing recursive canonicalization validator.

## 2. Function trace

| Function / type | File:line | Input → output | Verified behavior / intended use |
| --- | --- | --- | --- |
| WOS `verify_export_zip` | `trellis/crates/trellis-verify-wos/src/lib.rs:46` | ZIP → WOS report | Maintained adapter invokes Integrity export verification with WOS validator. |
| `verify_export_zip_with_validator` | `integrity-stack/crates/integrity-verify/src/trellis/export.rs:43` | ZIP + validator → layered result | Validates substrate, builds domain events, invokes `validate_events` then `validate_export` (`:45–70`). |
| `parse_domain_export` | same file `:80` | ZIP → readable domain event context | Exposes type, optional payload bytes, hash and authored time (`:110–122`). |
| Ledger domain dispatch | `integrity-stack/crates/integrity-verify/src/trellis/mod.rs:776,925` | verified event details → domain events/findings | Builds the same `DomainEvent` shape and calls the supplied validator. |
| `DomainEvent` | `integrity-stack/crates/integrity-verify/src/trellis/validator.rs:192` | type, optional bytes, hash, time | Payload is explicitly optional; new generic-event check must treat `None` as a failure rather than skip. |
| `WosRecordValidator::validate_events` | `trellis/crates/trellis-verify-wos/src/validator.rs:22` | event slice → findings | Existing composition point; append new findings without changing prior dispatch. |
| `DomainFinding::new` | Integrity validator.rs `:32` | kind/hash/severity/message → finding | Emit `Severity::Failure` with actual event hash and safe diagnostic. |
| `RelyingPartyVerdict::from_parts` | same file `:87` | substrate + findings → verdict | A non-projection domain Failure blocks domain admissibility (`:110–117`) and relying-party validity. |
| `decode_cbor_value` | `integrity-stack/crates/integrity-cbor/src/lib.rs:140` | bytes → CBOR/error | Consumes one complete value and rejects trailing bytes (`:144–148`). |
| `canonicalize_cbor_value` | same file `:158` | CBOR → validated/sorted CBOR | Recurses into arrays/maps/tags; rejects duplicate canonical map-key encodings (`:166–190`) and unsupported float representations. |
| `dcbor_bytes_to_json` / `cbor_value_to_json` | same file `:285,298` | CBOR → JSON inspection view | Converts bytes to base64 and removes supported tags; map insertion overwrites duplicates (`:315,323–335`). Requires stricter validation composition before acceptance. |
| `ProvenanceKind::canonical_event_literal` | `work-spec/crates/wos-events/src/provenance/kind.rs:506` | known kind → optional canonical literal | Shared authority for rejecting generic wrapping of canonical kinds; adapter must not duplicate its list. |

## 3. Data flow and invariants

For an unrelated event type, the new validator returns no new finding and preserves existing domain checks. Match the generic event identifier through Core's shared exported authority, not a divergent local vocabulary. For a generic event, require readable payload; decode the whole byte slice; reject malformed/trailing/ambiguous wire data; then invoke the shared strict payload helper. Any failure produces a blocking domain finding attached to `canonical_event_hash`.

Recommended minimal frozen API: Core exposes a strict native payload validation entry accepting raw payload bytes or a CBOR value in addition to its JSON constructor/validator. It composes maintained decode, recursive canonical validation, JSON conversion and raw-Value policy validation. Core's `wos-events` already depends on `integrity-cbor` with `json` enabled (`work-spec/crates/wos-events/Cargo.toml:11`). This keeps the offline adapter thin and avoids another schema implementation. Alternatively, the WOS validator may explicitly depend on maintained `integrity-cbor` with `json`; that would add a manifest/lock change beyond the originally named three source paths and must be agreed before implementation. `trellis-types` already re-exports complete decode and recursive canonical validation (`src/lib.rs:11–18`), but not the JSON conversion API.

Required shared payload policy: outer object contains exactly `record`; record is an object; `recordKind` is explicitly present, correctly typed and deserializes to a known `ProvenanceKind`; `canonical_event_literal()` is `None`. Do not round-trip the original record through a typed struct that drops unknown fields, fills defaults or normalizes values. Preserve nested JSON, extension fields, explicit nulls, arrays, timestamps and all original keys. Keep accepted raw JSON semantics separate from byte-exact CBOR identity, which remains the substrate verifier's responsibility.

Decoder qualification must be explicit at API freeze. Recursive canonical validation rejects duplicate text keys before JSON map insertion erases them. The inspection conversion also accepts CBOR byte strings and tag wrappers; the shared helper must define and test which are permitted by the actual producer's JSON→CBOR representation. Do not accept a non-JSON wire shape merely because the inspection view turns it into a plausible JSON record. No custom 106-kind list or copied JSON schema is needed to enforce this.

Findings should report event type, event hash and stable error category without dumping the complete record or private payload. An empty findings vector means this bounded shape check passed, not that every native kind's business semantics, legal validity, disclosure policy or full history is established. Existing canonical events retain their specialized checks; rejecting canonical kinds under the generic event prevents bypassing those paths.

## 4. Tests and edge cases

Existing tests read: `validator_reports_rescission_terminality_as_wos_finding` (`trellis-verify-wos/src/tests.rs:567`) asserts finding count/kind/hash; `validator_allows_determination_after_reinstatement` (`:578`) asserts no finding; `validator_ignores_clock_shaped_payload_on_non_clock_event_type` (`:593`) asserts dispatch remains tied to event type. New composition must preserve those assertions. Existing Integrity CBOR test `canonicalize_cbor_value_rejects_duplicate_nested_map_keys` (`integrity-cbor/src/lib.rs:797`) prepares nested duplicate-key refusal; this supports reuse rather than a new traversal. No existing test qualifies the proposed new generic path.

Required prepared tests, with expected behavior only:

| Case | Required assertion |
| --- | --- |
| Known noncanonical kind, complete record with extension/nested/null fields | Shared helper accepts and preserves raw JSON; WOS validator adds no native-provenance failure. |
| Every shared canonical kind in generic payload | Shared authority rejects; adapter emits Failure/hash. Iterate shared vocabulary, no copied list. |
| Missing/null/scalar/array record or missing/non-string/unknown recordKind | Failure, never skip or successful default. |
| Extra outer payload field or wrong outer root | Strict payload refusal. |
| Generic event payload `None` | Failure attached to its hash. |
| Invalid CBOR, trailing bytes, duplicate outer record, duplicate recordKind, duplicate nested keys | Failure before lossy JSON conversion. |
| Byte strings and tag wrappers in record/discriminator | Explicit producer-compatible policy assertions; ambiguous/unsupported representations fail. |
| Unrelated and existing canonical event types | No new generic finding; existing rescission/clock behavior unchanged. |
| Mixed slice containing valid/unrelated/invalid generic events | Findings identify only offending event hashes; no early-success short circuit. |
| Structurally valid substrate plus native-provenance Failure | Domain admissibility fails and relying-party result is Invalid. |

Read-only tests are planned, not run. No new implementation exists for assertion review. Compilation, helper semantics and fixture/execution proof remain pending subsequent source review and a separately authorized build window.

## 5. Findings

**F1 — WARNING / correctness — `integrity-cbor/src/lib.rs:323–331`.** JSON inspection conversion overwrites duplicate map keys. A raw JSON helper cannot recover ambiguity already lost by decoding. Disposition: approved plan requires maintained recursive duplicate validation before conversion, preferably inside the shared byte helper. Implementation must not call inspection conversion alone and label it strict admission.

**F2 — OBSERVATION / integration boundary — `trellis-verify-wos/src/validator.rs:22–26`.** The existing consumer-owned validator provides the correct shared integration point, and its crate already depends on `wos-events`. No new WOS dependency belongs in Integrity core. Disposition: use the private lent-file candidate, with Trellis owner integrating it; preserve unrelated validator behavior.

**F3 — OBSERVATION / specification and coverage — pending shared helper API.** The final byte/JSON acceptance API and producer-compatible CBOR subset are not yet frozen or implemented. Disposition: approve the bounded shape and test requirements, but hold implementation until the joint API agreement. A later AFTER gate must inspect actual helper code and adapter assertions; this certificate is not that gate.

## 6. Conclusion

VERDICT: APPROVE the bounded static plan, subject to the explicit pre-implementation API freeze above. The consumer-owned adapter is small, reuses maintained decode/validation and singular kind authority, preserves canonical specialization, and turns malformed/unreadable/unknown/bypass payloads into blocking findings. Coverage: ADEQUATE AS A TEST PLAN; implementation and execution not yet qualified. Confidence: HIGH in current source traces; pending helper behavior remains unverified.

Reviewed baseline SHA-256 pins:

```text
2403d1f82b9acfe92dbdc4790bd05767aea9488f85ee68d6fb401204495ce3f4  trellis/crates/trellis-verify-wos/src/validator.rs
141c2a2c186fdec58d2407493b4845543640cfeff818346c496152adbef272db  trellis/crates/trellis-verify-wos/src/lib.rs
2753d2833d2dd0ff22759b243d7a490fa4e47979770a669d49bb707e053ed26a  trellis/crates/trellis-verify-wos/Cargo.toml
9edfaab7343ed3d9e030826a7413662ebb64e8bacdccd91f6b6473dbd0430f6d  integrity-stack/crates/integrity-verify/src/trellis/validator.rs
e7b15d2d259cfad8e0656e6dc19d67903863829d7d56c3240299565c43bd578b  integrity-stack/crates/integrity-cbor/src/lib.rs
72f829655d85ecc12b45830304317f945366cf339333dfb70663859d850304c5  work-spec/crates/wos-events/src/provenance/kind.rs
```

## Agreed API scope addendum

The lead and Core owner have now frozen the narrow adapter entry points: `WOS_NATIVE_PROVENANCE_EVENT_LITERAL` is the shared neutral `wos.provenance.recorded` identifier, and `NativeProvenanceEvent::from_dcbor_slice(&[u8]) -> Result<Self, NativeProvenanceError>` owns byte admission. JSON/record constructors and accessors remain Core-owned. This API agreement resolves the earlier integration-shape question sufficiently for private hook and test preparation to proceed.

Core's agreed decoding plan is complete decode → depth-bounded JSON-compatible CBOR validation (text keys, no CBOR tags or byte strings, maximum depth 128) → maintained recursive canonical validation for duplicate-key/float refusal, discarding its sorted clone → JSON view of the original decoded value → strict raw JSON schema validation. Core also owns the exact closed wrapper and native-record schema, required id/kind/timestamp/auditLayer/definitionVersion fields, RFC3339 validation and known-enum/noncanonical-kind restriction. These are reported design commitments; the implementation has not yet been inspected by this reviewer.

The earlier preservation requirement applies to every admitted field: retain its original raw JSON value rather than typed reserialization/default filling. The final Core schema determines which fields may be admitted; preserve supported optional fields and reject unsupported fields explicitly. Do not silently drop fields to make a record pass. The adapter must not reproduce the schema's field list, RFC3339 parser, depth limit, CBOR walker or kind list.

The private adapter may now match only the exported constant, require `DomainEvent.payload`, and call `from_dcbor_slice` once. Any missing payload or returned error becomes a non-projection `Severity::Failure` finding with the event hash; successful helper validation adds no failure. Continue all existing rescission and clock checks. Tests can prepare representative accepted record and refusal cases through this agreed API, with no claim that they compile or pass yet.

Authorized candidate scope is `/private/tmp/integrity-native-provenance-v1-20261009/candidate/trellis/crates/trellis-verify-wos/`, with retained source/base pins. No shared Trellis checkout edits, builds or live calls are authorized by this gate. AFTER review must inspect the actual shared helper, schema and adapter assertions before certifying their behavior. In particular it must verify duplicate checks occur before lossy map conversion, no-tag/no-byte and depth boundaries are enforced, required explicit fields are checked, and canonical kinds cannot use the generic path.

Addendum verdict: APPROVE thin private integration and unexecuted test preparation against the agreed constant/byte API. The earlier implementation/execution limitations remain. No native-build authorization is implied.

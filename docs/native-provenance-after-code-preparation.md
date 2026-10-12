# Native provenance private adapter: static AFTER preparation review

VERDICT: APPROVE the private adapter and test preparation. No blocking defect found in the supplied three-file patch against the agreed API. This is not approval of the pending Core helper implementation, compilation, execution, adoption or complete custody qualification.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, with relevant Rust guidance previously consulted. Read all three candidate files, exact patch, baseline interfaces, actual prepared assertions, handoff/base pins and both successor proposals. No builds, Cargo commands, tests, native commands or live calls. This certificate is the only write; shared Trellis source remains untouched.

## 1. Patch summary

Private source root: `/private/tmp/integrity-native-provenance-v1-20261009/candidate/trellis/crates/trellis-verify-wos/`. Reviewed patch `/private/tmp/integrity-native-provenance-v1-20261009/native-provenance-offline.patch`, SHA-256 `bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97`.

The patch adds one private module declaration (`src/lib.rs:21`), one call extending existing event findings (`src/validator.rs:25`) and `src/native_provenance.rs`. The new validator examines only the shared generic event constant, delegates raw payload bytes to `NativeProvenanceEvent::from_dcbor_slice`, and reports unavailable or invalid payloads as blocking domain findings. Existing rescission/clock composition and export validation remain intact. The existing WOS crate already depends on `wos-events`; no manifest change or WOS dependency in Integrity core is introduced.

Exact governing proposals read and hashes verified: Trellis `examples/d1-export/native-provenance-routing-proposal-v2.md`, `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8`; Core `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md`, `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82`. Core v3 explicitly allows timestamp tag 0 only at the original bare record root timestamp, while wrapped archive payloads forbid all tags. The adapter uses only the wrapped constructor, so its timestamp-tag refusal test agrees with that source-specific distinction.

Exploration notes: H1, the patch interprets or copies kind/schema rules, refuted by the single shared constructor call. H2, failure may be silently skipped, refuted by exhaustive payload match and Failure construction. H3, the tests assume mismatched baseline types, refuted for existing `DomainEvent`, report/finding aliases, provenance fields and enum variants; the new helper symbols remain a declared pending dependency. H4, generic payload content could trigger specialized routing, refuted by exact outer event-type dispatch and positive preservation of nested canonical-looking recordKind text.

## 2. Function trace

Candidate-relative source locations unless otherwise identified:

| Function / interface | File:line | Input → output | Verified behavior |
| --- | --- | --- | --- |
| `validate_native_provenance` | `src/native_provenance.rs:10` | event slice → findings | Skips different outer event types; missing payload fails; shared constructor error fails; success continues. Exactly one helper call per readable generic event. |
| `WosRecordValidator::validate_events` | `src/validator.rs:22` | events → combined findings | Preserves rescission and clock checks, appends native-provenance findings. |
| `NativeProvenanceEvent::from_dcbor_slice` | Core proposal v3:20 | wrapped raw CBOR → validated helper/error | Signature is agreed; implementation unavailable. No strict-decoder behavior inferred from its name. |
| `DomainFinding::new` | Integrity `crates/integrity-verify/src/trellis/validator.rs:32` | kind/hash/severity/message → finding | Compatible with new call; Failure/hash preserved. |
| `DomainEvent` | same file:192 | outer type, optional bytes, hash, time | All candidate construction and borrowed payload use match actual baseline fields and types. |
| WOS `verify_export_zip` | candidate `src/lib.rs:47` | ZIP → WOS report | Existing adapter invokes Integrity verifier with WOS validator. Integrity export.rs:61 calls `validate_events`. |
| Ledger validation | Integrity `crates/integrity-verify/src/trellis/mod.rs:776,925` | event details → domain events/findings | Existing ledger path also uses the same validator. |
| `WosVerificationReport::verdict` | baseline `src/findings.rs:36` | report → relying-party verdict | WosFinding aliases DomainFinding; struct literal and unavailable-payload verdict test match actual interfaces. |
| `payload` test helper | candidate `src/native_provenance.rs:49` | known kind → wrapped JSON | Uses real `ProvenanceRecord::blank`, then explicitly fills required timestamp/audit/version and nested data. Baseline blank mints a native ID (`work-spec/.../record.rs:728–750`). |
| `encoded` / `encoded_cbor` | candidate `:65,71` | JSON/CBOR → bytes | Maintained ciborium encoder; deliberately uses unsorted CBOR for duplicate negative cases. No production byte rewriting. |
| `event` / `assert_invalid` | candidate `:77,89` | payload → event/assertions | Calls actual WOS validator and requires one invalid finding with Failure and exact hash. |

## 3. Data flow and invariants

Events are borrowed immutably. Payload slices are passed directly from `DomainEvent.payload` to the Core byte helper (`:16–25`), with no JSON inspection conversion, copied schema, typed reserialization or kind list in production. The helper result is used only for success/error classification. It cannot mutate the original event through this interface; the positive test additionally compares the event slice before and after validation (`:105–108`).

Outer type comparison uses the shared constant (`:13`). Unrelated and canonical event routes retain existing handling. For the generic route, `None` yields `native_provenance_payload_unavailable`; helper error yields `native_provenance_invalid`. Both attach `Some(canonical_event_hash)` and `Severity::Failure` (`:28–33`). Every event is visited; an invalid record does not stop validation of the remainder. Messages are fixed strings and omit original record values and schema error details, preventing payload disclosure through findings.

Existing `RelyingPartyVerdict::from_parts` treats these non-projection Failure kinds as failed domain admissibility (Integrity validator.rs:110–117). This blocks a valid relying-party verdict even when cryptographic integrity passes. The adapter does not promote the record's nested event/kind into signature, intake, clock or legal semantics.

The entire strict admission guarantee remains delegated and unverified until actual Core code is available. Its proposed decoder must consume complete CBOR, bound depth before recursive validation, enforce wrapped no-tag/no-byte policy, reject duplicate keys before map conversion, retain original admitted JSON and reject missing/unknown/canonical kinds. The source currently cannot compile against unmodified baseline `wos-events`, which does not yet export the new helper/constant. That is an explicit staged prerequisite, not a hidden successful-build claim.

## 4. Test behavior and edge cases

All six tests are prepared and unexecuted; predicted results depend on the promised Core implementation.

| Test | Candidate line | Actual assertion value |
| --- | --- | --- |
| `original_on_entry_and_notice_records_validate_without_specialized_promotion` | 98 | Two known noncanonical kinds; helper record equals complete original JSON including nested canonical-looking kind text; no new findings; events unchanged. |
| `unavailable_payload_blocks_domain_admissibility` | 112 | Missing payload gives exact kind/hash; actual report verdict preserves crypto Pass but fails domain admissibility and relying-party result. |
| `malformed_wrapper_discriminator_and_original_fields_refuse` | 131 | Null/empty wrapper, null record, extra wrapper field, five absent required fields, wrong/unknown discriminator, invalid IDs/timestamp/types and unknown structural field must produce Failure/hash via `assert_invalid`. |
| `every_existing_canonical_kind_refuses_generic_bypass` | 168 | Asserts current 28-entry inventory, iterates shared canonical literals, resolves owning enum and rejects generic wrapping. No copied 106-kind allowlist. |
| `invalid_cbor_and_ambiguous_maps_refuse_before_json_view` | 177 | Invalid/trailing CBOR, duplicate wrapper/recordKind/nested keys, non-text keys, tags/bytes at record or valid nested field, and excessive depth must fail. Timestamp tag under wrapped record intentionally refuses, consistent with v3. |
| `mixed_events_keep_existing_routes_and_identify_only_invalid_generic_record` | 266 | Valid generic, canonical, malformed unrelated and invalid generic together yield only the invalid generic hash; diagnostic excludes unknown recordKind text. |

Existing rescission/clock tests reviewed in the BEFORE certificate remain outside the patch and should retain behavior. Not covered here: every remaining kind, exact depth boundary success, numeric subset edges, missing field null/type permutations, bare timestamp tag acceptance/refusal, real router admission, signed export mutation or a genuine full runtime custody window. Those belong primarily to the shared helper and joint integration qualification. The generic canonical-exclusion test can establish adapter-wide rejection but does not prove exact original canonical payload bytes remain unchanged through producer/client paths.

Assertions use typed blank construction only to generate synthetic test records. They do not claim actual runtime records were generated, appended, admitted or exported. The supplied patch's tests are not stand-alone evidence that Core's strict helper works until that source is inspected and tests execute.

## 5. Findings

**F1 — OBSERVATION / integration prerequisite — `src/native_provenance.rs:7,21,102–103`.** The new constant, constructor and record accessor match the agreed Core API at proposal v3:14–22, but actual exports/implementation are pending. Disposition: APPROVE private preparation only; full AFTER qualification must inspect the actual helper and its tests, then compile the composed candidate in an authorized window. No additional adapter source correction found.

**F2 — OBSERVATION / coverage — `src/native_provenance.rs:177–263`.** Prepared CBOR refusals meaningfully guard against lossy inspection-view acceptance, including duplicate keys and wrapped timestamp tags. They do not qualify bare custody timestamp policy or exact boundary acceptance. Disposition: retain these assertions and require Core/joint tests for the complementary paths; no duplicated decoder should be added to this adapter.

**F3 — OBSERVATION / privacy and maintainability — `src/native_provenance.rs:21–33`.** Single shared-owner call and fixed safe diagnostics avoid duplicated policy and raw record disclosure. This meets the bounded simplification goal. No performance claim is made.

No blocking static defect found in the adapter against the agreed API. The incomplete Core prerequisite and unexecuted tests remain explicit limits.

## 6. Conclusion and pins

VERDICT: APPROVE private source/test preparation. Coverage: ADEQUATE for this thin adapter's static branches and prepared tests; shared helper, compilation, execution and complete-custody qualification remain pending. Confidence: HIGH in inspected adapter/baseline compatibility, limited to the frozen API for unresolved Core symbols.

```text
bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97  native-provenance-offline.patch
b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9  candidate src/lib.rs
e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0  candidate src/validator.rs
82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67  candidate src/native_provenance.rs
083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8  Trellis routing proposal v2
b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82  Core API proposal v3
```

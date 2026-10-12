# Native provenance: bounded AFTER execution-evidence review

VERDICT: APPROVE the retained execution evidence for the reviewed offline adapter and its six tests within the 63-test owning verifier suite. This does not qualify the complete native-window ZIP through that verifier, complete D1, portability or adoption.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Applied `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, both read in full again for this audit; relevant Rust guidelines were consulted in the preceding source reviews. This is static source and retained-evidence inspection. No Cargo, builds, tests, executable invocation or live calls were performed by this reviewer. Only this certificate was written; earlier certificates remain immutable.

## 1. Patch summary and exact scope

No adapter/helper production delta is proposed. This audit connects the frozen v3 source review in `native-provenance-after-code-shared-source-v3.md` to the authorized owner's subsequent execution. Snapshot root, abbreviated `S` below: `/private/tmp/core-native-provenance-inputs-v1-20261009`.

The parent receipt `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-qualification-receipt-v1.json` and `S/execution/qualification-receipt.json` both independently hash to `bd388601cd21c705ba26cb56646eab533372a432a27c8cb21a52dcbfc23fa2cb`. The receipt explicitly separates owning-verifier tests from the native-window ZIP exercise (`qualification-receipt.json:684`). Broader Core final reviews remain separate.

Independently recomputed identities:

| Snapshot-relative input | SHA-256 |
| --- | --- |
| `execution/trellis-adapter-3.log` | `4aa2bdd7881c40b1079652465849c3cce748a7a7178d05e12255fd5fdff2979d` |
| `execution/trellis-adapter-3.json` | `602174e1aea62aa232a9b7cebf74a46b7a69dc09ad47463209bd31cf2cca8b8a` |
| `execution/test-executables/trellis_verify_wos-e4462662aacfe845` | `582faca16e9c3ef26458a9530909b52f9e5b97d5b52b3374de5c2e6b589610f2` |
| `trellis/crates/trellis-verify-wos/src/lib.rs` | `b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9` |
| `trellis/crates/trellis-verify-wos/src/validator.rs` | `e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0` |
| `trellis/crates/trellis-verify-wos/src/native_provenance.rs` | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |
| `work-spec/crates/wos-events/src/native_provenance.rs` | `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d` |
| `work-spec/crates/wos-events/src/native_provenance/tests.rs` | `22410eabf117f86870b6c653c715493aea9fe279de00e9b596aba0b8639bf73a` |
| `work-spec/schemas/wos-native-provenance-event.schema.json` | `18c370ffcc8a1274ba89cfe3a8aca3b1bd452e530b637d3e1349d71fc04c0304` |

These adapter/helper/schema/test hashes match reviewed v3 exactly. The retained verifier executable is 20,531,296 bytes, matching receipt identity (`qualification-receipt.json:664–666`); the log names its corresponding target executable at line 35. This is retained owner-run provenance, not independent replay or a clean-build claim.

Exploration notes: H1, execution may use different adapter/helper bytes, refuted by exact hashes and source guards. H2, failures may have been hidden by filters, refuted for the final verifier suite by 63 passed/zero filtered at log:102 and six named adapter results. H3, repairs may change production behavior, refuted within the declared three-file delta below. H4, the suite proves full native-window ZIP verification, refuted by receipt:684 and the actual adapter test inputs.

## 2. Function trace

All code locations below are relative to `S`.

| Function / stage | File:line | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| Owner stage runner | `run_stage.py:5–12,24–29` | command/cwd → process log and JSON receipt | Starts separate process group, waits for leader, checks group clearance, records exit/status. Bounds time, log size and disk floor at lines 14–21. |
| Final adapter stage | `execution/qualification-receipt.json:145–175` | offline locked `cargo test -j1`, three packages, `--lib` → exit 0 | Final stage records no stop reason, groupClear=true and 11/7/63 passing suite summaries. Prior failed attempts remain retained. |
| `WosRecordValidator::validate_events` | `trellis/crates/trellis-verify-wos/src/validator.rs:22–26` | borrowed domain events → combined findings | Existing rescission/clock validation continues; generic provenance findings are appended. |
| `validate_native_provenance` | same crate `src/native_provenance.rs:10–35` | event type, optional original payload → findings | Unrelated types continue; unavailable or rejected generic bytes produce Failure with event hash and fixed safe message; valid bytes continue. |
| `NativeProvenanceEvent::from_dcbor_slice` | `work-spec/crates/wos-events/src/native_provenance.rs:96–98` | original wrapped bytes → validated retained JSON/error | Calls strict original-byte decoder with bare-timestamp exception disabled, then shared JSON validation. Unchanged v3 callee trace remains applicable. |
| `NativeProvenanceEvent::from_json` | same helper:57–79 | raw JSON → validated clone/error | Checks subset, known noncanonical kind, native ID, maintained schema; clones original fields only after validation. |

## 3. Data flow and invariants

The adapter reads borrowed `DomainEvent` payload bytes, delegates acceptance to the WOS-owned helper, and emits only findings. It neither rewrites the event nor promotes generic records to canonical routes. Failure messages omit original record values (`native_provenance.rs:27–33`); the mixed-event assertion checks that an unknown discriminator does not escape (`:278–282`).

The source guards independently hash to `b9c8211bfc400a5df4e3b7f38e3fec0bab2955bc690fec5072f3727457200918` (before) and `7fb286f3a537f6b399c1ca82c2cd81e69100c8d8381448ddacd19dd61efb54c3` (final). Compared both 7,712-entry maps: only the three declared repairs differ, with no added or removed entries. Independently read and hashed all 7,712 final guarded files: zero mismatches. This establishes continuity for the guarded inputs; it is not a claim about unlisted files or future mutation.

Reviewed all three repairs against retained source predecessors:

- `work-spec/crates/wos-runtime/src/runtime.rs:2826–2830`, inside the test module beginning at :742–743: replaces a broad `wos.kernel.` prefix assertion with exact maintained canonical-or-generic route equality. This strengthens route checking for the updated behavior.
- `trellis/crates/trellis-service-client/src/wos_ext.rs:125–157`: the test now compares the typed input record's maintained serialization with the produced request. That is the actual typed API boundary; empty optional collections may disappear during its original serialization. This test does not establish raw arbitrary JSON fidelity. Raw-record fidelity remains separately asserted by the unchanged shared helper and offline adapter tests.
- `trellis/fixtures/conformance/native-provenance-routing.json:6`: the ID gains the maintained `default_` namespace prefix. No production branch changes.

The source guard deltas and direct diffs support receipt:20's `productionCodeChangedDuringExecution=false` within this snapshot. Lock and broader dependency qualification are not re-reviewed here.

## 4. Test behavior and edge cases

Each test below was re-read, invokes the actual validator/helper, and appears as `ok` in the retained final log. Locations are `trellis/crates/trellis-verify-wos/src/native_provenance.rs`; log locations refer to `execution/trellis-adapter-3.log`.

| Test / source line | Assertion path | Observed log line |
| --- | --- | --- |
| `original_on_entry_and_notice_records_validate_without_specialized_promotion`:98 | Complete decoded record equality; no findings; original event vector unchanged. | 99 |
| `unavailable_payload_blocks_domain_admissibility`:112 | Exact finding and event hash; cryptographic Pass remains separate from domain Fail and Invalid relying-party result. | 40 |
| `malformed_wrapper_discriminator_and_original_fields_refuse`:131 | Missing/extra wrapper fields, required fields, unknown kinds, malformed IDs/time/types produce exact Failure/hash through assert_invalid:89. | 100 |
| `every_existing_canonical_kind_refuses_generic_bypass`:168 | All 28 maintained canonical literals resolve to kinds and fail generic routing. | 76 |
| `invalid_cbor_and_ambiguous_maps_refuse_before_json_view`:177 | Invalid/trailing CBOR, duplicate wrapper/kind/nested keys, tags/bytes/nontext keys and excess depth fail via shared byte helper. | 47 |
| `mixed_events_keep_existing_routes_and_identify_only_invalid_generic_record`:266 | Valid generic, canonical and unrelated events coexist; only invalid generic event is identified; original invalid value is absent from report. | 98 |

The final log reports 63 verifier tests passed with zero failures, ignored or filtered tests (:35–102). Admission and service-client suites separately report 11 and 7 passing tests (:20,33). These are actual retained owner results; this reviewer did not execute tests. Earlier failed stages remain in the receipt and were resolved by the declared test/fixture repairs, rather than erased.

## 5. Findings

OBSERVATION 1 — test-coverage / authority boundary. Location: `execution/qualification-receipt.json:684`; adapter tests :98–282. The six tests qualify the offline generic-event path on their constructed payloads within the owning suite. They do not run the full actual native-window ZIP through the owning verifier. Keep the separate Core ZIP/order/stamp/replay evidence and verifier-suite evidence distinct. No change is required for the bounded claim reviewed here.

OBSERVATION 2 — execution provenance. Location: `execution/trellis-adapter-3.log:35`, receipt:664–666. The retained executable identity and source continuity support the reported owner execution. This audit does not independently replay the binary, attest the toolchain, establish a fresh isolated target build, or qualify portable dependency closure. No such stronger claim is approved.

No blocking finding in this bounded audit.

## 6. Conclusion

VERDICT: APPROVE.

- The retained final run supports all six adapter tests passing within the owning verifier's 63-test suite, against the unchanged reviewed v3 adapter/helper/schema bytes.
- Coverage of the adapter branches and retained execution evidence: ADEQUATE for this bounded claim.
- Confidence: HIGH for inspected source identities, log consistency, test assertions and repair scope; execution remains owner-reported retained evidence, not independent replay.
- Complete native-window ZIP verification by the owning verifier, complete D1, adoption, live service state, broader Core final acceptance and portable build/lock closure remain outside this approval.

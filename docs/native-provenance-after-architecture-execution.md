# Native provenance — focused execution architecture audit

**VERDICT: APPROVE the bounded private qualification evidence.** Retained logs record401 selected tests passing, including the owning WOS verifier's63 tests and all six new offline-adapter tests. Reviewed helper, schema and three adapter files retain their approved identities. The runtime-window test checks original records in the emitted ZIP, order, receipt stamping and replay. **That ZIP was not submitted to the full owning verifier.** The separate verifier suite does not establish that missing end-to-end result. No full D1, agency trust, portability/adoption or live system qualification follows.

## 1. Artifact summary and method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime model identity not independently exposed. Applied the full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full during this continuous review. All six phases appear below. Static audit of retained owner evidence: read qualification receipt, adapter-3 log/receipt, relevant failed-attempt diagnostics, source guards, current test sources and runtime ZIP assertions. Recomputed receipt/all stage-log hashes and all final source-guard file hashes. No Cargo/build/native/test rerun/live commands, key operations or source changes. Only this certificate written; other owners' work preserved.

Category: proof infrastructure for native custody/offline interpretation. Snapshot root `/private/tmp/core-native-provenance-inputs-v1-20261009`; execution artifacts beneath `execution/`. Snapshot-relative code references below use that root. Workspace receipt path: `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-qualification-receipt-v1.json`.

| Exact evidence | SHA-256 |
| --- | --- |
| Workspace qualification receipt | `bd388601cd21c705ba26cb56646eab533372a432a27c8cb21a52dcbfc23fa2cb` |
| `frozen-source.json` | `b9c8211bfc400a5df4e3b7f38e3fec0bab2955bc690fec5072f3727457200918` |
| `frozen-source-final.json` | `7fb286f3a537f6b399c1ca82c2cd81e69100c8d8381448ddacd19dd61efb54c3` |
| `execution/trellis-adapter-3.log` | `4aa2bdd7881c40b1079652465849c3cce748a7a7178d05e12255fd5fdff2979d` |
| `execution/core-lib-2.log` | `0094256b52932a9b80adfcf5d9b6d0b98550e28d1af5837b5e2c86567251d6d6` |
| Unchanged helper `work-spec/crates/wos-events/src/native_provenance.rs` | `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d` |
| Unchanged schema `work-spec/schemas/wos-native-provenance-event.schema.json` | `18c370ffcc8a1274ba89cfe3a8aca3b1bd452e530b637d3e1349d71fc04c0304` |
| Unchanged adapter `trellis/crates/trellis-verify-wos/src/native_provenance.rs` | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |
| Unchanged verifier `src/lib.rs` | `b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9` |
| Unchanged verifier `src/validator.rs` | `e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0` |

Both guards contain7712 file pins. All final pinned files currently match. Before/final guards differ in exactly the receipt's three declared test/fixture paths, listed below. Guard equality is file-identity evidence; it is not evidence that every possible external input was captured. Stage cleanup is assessed from retained receipts, not a fresh process inspection.

## 2. Lineage and relationships

| Artifact | Relationship | Evidence |
| --- | --- | --- |
| Workspace `integrity-stack/docs/native-provenance-after-architecture-shared-source-v3.md` | Exact static helper/schema approval | v3 pins and kind-specific TaskFailed expiry correction; execution then unqualified |
| Workspace `integrity-stack/docs/native-provenance-after-architecture-preparation.md` | Exact adapter shape | Shared wrapped helper, domain Failure, fixed messages and ownership |
| Joint routing proposal v2/Core API supplement v3 | Runtime/full-verifier gates remain distinct | Their verification gates and source-specific decoder policy |
| Workspace `trellis/specs/wos-trellis-verification.md:13–43` | Normative cryptographic/domain boundary | Core proof first, offline evidence only, separate verdict tiers |
| Qualification receipt | Retained execution and repair lineage | `stages`, `passedTestNames`, `declaredTestFixtureRepairs`, `scope` |

WOS owns original record/schema/producer semantics; Trellis owns admission/client/offline integration; Integrity supplies generic proof and the consumer-validator interface. This audit consumes owner execution evidence; it adds no API or semantic rule. Wider Core final reviews and portability/adoption decisions remain separate.

Hypothesis H1(high), prepared shared/adapter tests now have retained executable evidence: **CONFIRMED** by unchanged pins and passing named tests. H2(high), the runtime-window ZIP passed full WOS verification: **REFUTED** by test source and receipt scope. H3(high), failures were erased or production semantics changed to obtain success: failed attempts remain; guard deltas are exactly declared test/fixture paths, and inspected corrections are consistent with the intended rules. Root's `productionCodeChangedDuringExecution=false` remains its execution assertion; this review independently checks file deltas and the relevant corrected assertions, not a new broad Core implementation review.

## 3. Invariants, results and corrections

| Evidence | Recorded result | Architectural meaning |
| --- | --- | --- |
| core-lib-2 | exit0,32 events +285 runtime tests | Shared helper tests and native runtime-window test executed |
| trellis-adapter-3 | exit0,11 admission +7 client +63 verifier tests | Owning composed adapter suites executed; six native offline tests included |
| trellis-schema-1 | exit0,1 selected test,10 filtered | Focused offline schema-resource resolution |
| trellis-openapi-1 | exit0,2 selected tests,88 filtered | Focused OpenAPI parity |
| Total successful selected tests | 401 | Sum of successful suites; not every workspace test |

All stage-log hashes match the receipt. Retained stage receipts record groupClear=true for all attempts; final adapter stage pgid8626 exited0 after6.09seconds. Core-lib-1 and adapter-1/2 exited101 and remain retained, rather than being counted as success. Times are diagnostic receipt observations, not performance claims.

The six adapter test names in adapter-3 log cover unavailable payload/domain blocking; malformed CBOR/ambiguous maps; every canonical-kind generic exclusion; mixed-event isolation; OnEntry/notice original-record preservation; and malformed wrapper/discriminator/original fields. Existing owning canonical/signature/catalog/clock checks also pass in the63-test suite. This supports the existing fixed-message/domain Failure and canonical-separation design; it does not make generic custody a specialized semantic attestation.

Exactly three declared guard changes occurred:

| Path | Correction and evidence |
| --- | --- |
| `work-spec/crates/wos-runtime/src/runtime.rs` | Test replaces kernel-prefix assumption with exact canonical-or-generic expectation. Inspected diff at2823–2830; initial core-lib-1 diagnostic identifies that obsolete prefix assertion. Final pin `9702f3e6c01b79f63090919129fcd576bb3cd2ce53c5b4b67d5ea547785984a9`. |
| `trellis/fixtures/conformance/native-provenance-routing.json` | Controlled fixture now includes empty inputs/outputs/transitionTags compatible with maintained shape. Remains explicitly controlled input, not actual history. Final pin `c25be87e3598edeb03fa7363a65c24ffa0b8da589eb47542fb193d01e2e0de88`. |
| `trellis/crates/trellis-service-client/src/wos_ext.rs` | Typed-client test compares request record to serialization of its actual typed input, which omits empty optional collections. Source136–157 and adapter-2 diagnostic show the exact prior collection-presence mismatch. Final pin `7e57ce296cdae460a221f554a45c69df6b80f16ead764c060090b0f3a9a03bb6`. |

These corrections preserve the distinction between raw-value fidelity and the typed client's original serialization. They do not authorize stripping fields from existing raw custody inputs. The helper and all three offline files are unchanged. Broader source/fixture correctness remains with owning final reviews.

## 4. User-value and evidence boundaries

The runtime test starts with original OnEntry history and drives the maintained private router/client. At `work-spec/crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:160–186`, it obtains the head ZIP, decodes its event member, compares event count/order/type, validates generic payloads and compares complete original JSON and identifiers. At188–204 it checks receipt-only hash stamping, exact replay identity, changed-body409 refusal, stamped retry skip and unchanged bundle. Its pass appears in core-lib-2.log:349.

That source decodes COSE structures but never calls the full owning export verifier on this ZIP. Decoding is not signature/proof verification. The63-test verifier suite is separate evidence. Therefore the supported user outcome is native custody preservation/replay plus independently exercised owning validation behavior, with a remaining end-to-end archive-verification gate. Actual D1 Source/WOS history, issued notice, original evidence coverage, current grants, external registry custody and agency trust are not supplied by these controlled tests.

This pays down previously unexecuted behavior without adding new design debt. No speed/resource improvement or deployment benefit is claimed. Source-path normalization/lock resolution in this private snapshot establishes only its selected execution context; portable source closure and adoption remain separate.

## 5. Counterfactual and kill criteria

Kill criteria are reviewed-file hash disagreement, unexplained guard changes, suppressed native failures, canonical bypass, original-value loss, or treating separate suite success as full verification of the runtime ZIP. None appears within this bounded evidence. Removing this addendum leaves static approvals but loses precise qualification of the executed suites. Existing owner receipts subsume execution facts; this certificate supplies their bounded architectural interpretation. A future reviewer should first request full owning verification of the exact emitted archive and actual operational evidence before expanding the claim.

## 6. Findings and dispositions

- **KEEP — OBSERVATION / provenance:** retain successful and failed stage evidence, matching final guard and declared repair lineage. Qualified count is401 selected tests.
- **KEEP — OBSERVATION / commitment:** exact helper/schema/adapter identity and existing domain/privacy/ownership separation. No required architecture reshape for this bounded audit.
- **REVERSE — OBSERVATION / intent-vs-shape:** reject any statement that the runtime-window ZIP passed full owning verification, or that controlled fixture success proves full D1/agency trust/adoption.
- **DEFER — OBSERVATION / scope:** exact native-window archive full verification, wider Core final reviews, portable closure and authorized adoption/actual-record qualification. No rerun or live action is granted here.

## 7. Verdict

```text
VERDICT: APPROVE bounded private execution evidence
Intent vs. shape: MATCHES within stated runtime/suite separation.
User-value claim: SUPPORTED — native preservation/replay and owning tests executed.
Commitment status: HONORED — shared validation, canonical separation and evidence limits preserved.
Conceptual debt delta: PAYS DOWN — execution uncertainty reduced, no new API.
Sibling subsumption: PARTIAL — receipts establish facts; end-to-end archive verification remains distinct.
Confidence: HIGH for retained log/hash/source-guard consistency; actual D1/adoption unqualified.
```

This is an audit of retained owner execution, not independent reproduction. No native command, service operation, signing, key generation, browser/authentication or live provider action was performed by this reviewer.

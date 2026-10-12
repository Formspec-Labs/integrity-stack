# Native provenance shared source v3: focused static AFTER review

VERDICT: APPROVE the coherent frozen v3 schema/test correction and unchanged helper/offline alignment. Execution, lock closure, portable dependency closure, actual complete-custody qualification and adoption remain unqualified.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, including relevant Rust guidance already consulted. Read the changed schema/tests and actual maintained producer/constructor code; reused unchanged helper/callee analysis from `native-provenance-after-code-shared-source.md`. No builds, Cargo/native commands, test execution or live calls. Only this new certificate was written; v1 remains immutable.

## 1. Patch summary and exact scope

Core root: `/private/tmp/core-native-provenance-v1-20261009/work-spec`, base `22296385f4ef179ad330f55d80592194f8b3af6b`. Frozen v3 manifest: `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-source-v3.json`, SHA-256 `3a410dfebd233e7604dbf30b17ec900e51e131c3313117ea420ee4bf23536268`. Independently rehashed all twelve declared files; all match. Relative to v1 only native helper tests and native schema changed. Actual helper remains `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d`; integrated offline three-file hashes remain unchanged.

The schema now admits the maintained `expired` outcome only when serialized `recordKind` equals `taskFailed`. Tests construct the actual task-lifecycle shape, assert original-field preservation and refuse other-kind/unknown outcomes. Additional negatives target duplicate recordKind and narrow bare timestamp-tag errors, requiring decoder-specific refusal.

Review history matters for exact identity: the initial v2 request pinned schema `e6f6f60e…`, while the file observed during review already hashed `18c370ff…`. This reviewer reported the mismatch and held exact certification. The owner then supplied frozen v3, documenting correction of the schema const from Rust variant spelling `TaskFailed` to serialized lower-camel `taskFailed`. V3 coherently pins the actually reviewed bytes. No v2 approval certificate was issued.

Exploration hypotheses: H1, expiry is a real producer outcome, confirmed at runtime/tasks.rs:687–698. H2, allowing expired broadens all native kinds, refuted by the schema conditional. H3, new CBOR negatives might pass only because schema rejects extra fields, refuted by mutating existing fields and requiring InvalidCbor. H4, other obvious maintained top-level outcomes remain mismatched, refuted within the bounded assignment search below.

## 2. Function and schema trace

Core-root-relative locations:

| Function / rule | File:line | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| `retire_expired_tasks` producer | `crates/wos-runtime/src/runtime/tasks.rs:687–698` | expired task → TaskFailed provenance | Uses task_lifecycle with detail object, timestamp/system actor and top-level outcome expired. |
| `ProvenanceRecord::task_lifecycle` | `crates/wos-events/src/provenance/record.rs:1029` | kind/task ID/actor/detail → record | Adds data.taskId and data.details; new test uses this actual constructor. |
| Expiry conditional | `schemas/wos-native-provenance-event.schema.json:15–25` | present outcome=expired → required kind constraint | Requires outcome presence in the if condition, then constrains recordKind to taskFailed; global required kind remains intact. |
| Outcome field | same schema:104–109 | outcome value → acceptance | Existing ProvenanceOutcome or exactly expired. Unknown literals fail; existing reserved/vendor rules remain. |
| `NativeProvenanceEvent::from_record` / `from_json` | helper:86 / 57 | record/raw JSON → validated retained value | Unchanged: typed serialization once, raw subset/enum/ID/schema validation, original value clone. |
| Wrapped/bare constructors and strict decoder | helper:97,109,148,159 | raw bytes → helper/error | Unchanged complete decode, bounded subset, duplicate validation before JSON conversion; bare-only exact root timestamp tag0/text exception. |
| Offline validator | integrated `trellis-verify-wos/src/native_provenance.rs:10` | domain events → findings | Unchanged single shared constructor; invalid/unavailable generic payload blocks; unrelated events unaffected. |

The prior certificate's detailed helper/schema-library/ID/decoder traces remain applicable to unchanged code. This focused correction does not expand the review to all runtime files in the manifest.

## 3. Data flow and invariants

The maintained expiry producer creates a TaskFailed record with original detail fields `taskStatus`, `outcome`, `expiresAt`, `timerRef`, sets timestamp and system actor, and assigns top-level outcome `expired`. The new test follows that construction and explicitly supplies runtime-required audit/version fields. The schema accepts that original fact rather than rewriting its outcome to a different reserved value.

Schema `outcome` permits expired through an additional exact const. The record-level conditional then restricts that value to taskFailed. Changing the kind to taskCreated while preserving expired must fail; changing TaskFailed's outcome to an unknown non-vendor value must fail. Missing recordKind cannot exploit properties-only conditional semantics because the schema independently requires it. Records with no outcome do not activate the conditional. Raw-field preservation remains the unchanged helper's full-value clone.

Bounded maintained-producer outcome scan: runtime/tasks.rs:698 assigns expired to TaskFailed. events/provenance/record.rs:1120 assigns preconditionNotSatisfied to CapabilityInvocation, a canonical route excluded from this generic helper and still covered by the shared outcome definition. core/eval_mode.rs:90–111 creates ConvergenceCapReached with convergenceCapReached, already permitted by that definition. Tool/arazzo `ok`/`failed` strings are nested application data, which stays arbitrary JSON. runtime/intake.rs:255 assigns IntakeRecord.outcome rather than ProvenanceRecord.outcome. No additional top-level native outcome mismatch found in this bounded static search; this is not exhaustive proof of every future/dynamic producer value.

The bare timestamp exception remains source-specific. Wrapped payloads forbid all tags. The new tests target existing data/timestamp fields and require InvalidCbor, so schema-only refusal cannot satisfy them. Original values and source bytes remain unmodified; no transport-byte-identity claim is introduced.

## 4. Tests and edge cases

All assertions are prepared and unexecuted.

| Test / change | `native_provenance/tests.rs` line | Static assertion assessment |
| --- | --- | --- |
| Native task expiry preservation | 68–90 | Real constructor, same system actor/detail shape/top-level expiry outcome; helper output equals full original JSON; wrapped byte constructor preserves record; TaskCreated+expired and TaskFailed+unknown refuse. Coherent with v3 lower-camel discriminator. |
| Duplicate-key test | 132–142 | Bare duplicate now explicitly selects and repeats recordKind; requires InvalidCbor. Maintained duplicate validation precedes conversion, so the intended branch is exercised. |
| Bare tag negatives | 153–171 | Tag0 at data, nested data.timestamp, non-text root timestamp child and nested root timestamp tags each require InvalidCbor. The unchanged path/text match rejects each before schema. |
| Existing wrapped negatives | 145–152 | Bytes/tag32/tag0 require InvalidCbor. Preserved tests complement unchanged offline wrapped timestamp-tag and duplicate nested-key assertions. |
| Prior helper/adapter assertions | unchanged portions | Registry parity, full original JSON, actual valid bare timestamp tag, missing fields, numeric/depth boundaries and offline Failure/verdict tests retain prior static analysis. |

The producer-shaped test is synthetic and uses the owning constructor; it does not run retire_expired_tasks or a genuine full custody window. It validates the specific emitted shape, not service admission, signed export completeness or original receipt stamping. Additional source-specific cases resolve several coverage gaps recorded in v1. Native compilation and test results remain pending.

## 5. Findings

**F1 — OBSERVATION / correctness — schema:15–25,104–109; runtime/tasks.rs:698.** The original schema rejected a maintained top-level expiry fact. V3 admits it narrowly for taskFailed and preserves all raw values. Correct serialized kind spelling is now present. Disposition: correction APPROVED; no adapter change needed.

**F2 — OBSERVATION / evidence identity — v2 versus v3 manifests.** V2 request/file mismatch prevented exact certification. Frozen v3 matches all twelve independently rehashed files. Disposition: identity concern resolved for v3; v1/v2 historical artifacts remain preserved and do not authorize successor adoption.

**F3 — OBSERVATION / test quality — tests.rs:132–171.** New negatives require InvalidCbor while mutating existing fields, preventing a false-positive schema-only refusal. Disposition: meaningful static coverage improvement; execution unqualified.

No unresolved blocker found in the focused v3 schema/test correction or unchanged offline alignment. Lock consistency, private absolute paths, portable patch closure and actual runtime execution remain separate gates.

## 6. Conclusion and exact pins

VERDICT: APPROVE frozen v3 focused static source review. Coverage: ADEQUATE for the correction and prepared assertions. Confidence: HIGH in inspected behavior; no compilation, execution, lock, portability or adoption approval implied. This supersedes v1 for this focused correction while preserving its immutable historical certificate and unchanged-code analysis.

```text
3a410dfebd233e7604dbf30b17ec900e51e131c3313117ea420ee4bf23536268  native-provenance-core-source-v3.json
df68298fac7a7e3cc71e6d9322cfa20c001b67df62b1f9e50d693c535aca43d6  Cargo.lock
f33d7aa7f5f83186486ac8b9c1a2c98980d486b5eca4fbee65ea6200fd2883f1  Cargo.toml
3e72b553b9ecb6da3eae38a303f3b90d6663941b34a452b2492a8a833069bfde  crates/wos-events/Cargo.toml
aa0b000c99c5a22e4ff51e20b7e7bdcdb8afc6384e7c3ee9dcff1f43788f548b  crates/wos-events/src/custody.rs
dd05c4049dad3397ddf734a9b9ae729d297fe96db97df2eea64a81720dd19f33  crates/wos-events/src/lib.rs
09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d  crates/wos-events/src/native_provenance.rs
22410eabf117f86870b6c653c715493aea9fe279de00e9b596aba0b8639bf73a  crates/wos-events/src/native_provenance/tests.rs
2af3ef357457de0743ea3f6145dd2ffea23334afba0362b0f3a08b3425df4b18  crates/wos-runtime/Cargo.toml
a061bb4c8673d9fba022fd1c128b3b208cb2a56ddc6e44c0d46089b1c06e4ee0  crates/wos-runtime/src/runtime.rs
fa176f423798224ea349e4e072508027d64ef40b0543e04fa5495f1fc674dee4  crates/wos-runtime/src/runtime/custody_trellis.rs
cc77c3863df3ea9baa5270403a52de29f6bc5b7b6e2cbc4a53df8b2269b3b0b7  crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs
18c370ffcc8a1274ba89cfe3a8aca3b1bd452e530b637d3e1349d71fc04c0304  schemas/wos-native-provenance-event.schema.json
b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9  integrated offline src/lib.rs
e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0  integrated offline src/validator.rs
82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67  integrated offline src/native_provenance.rs
```

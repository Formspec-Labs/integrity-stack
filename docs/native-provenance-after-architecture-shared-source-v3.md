# Native provenance source v3 — focused AFTER architecture review

**VERDICT: APPROVE the frozen v3 static correction and unchanged offline alignment.** The separate native schema now admits the maintained `expired` outcome only for serialized `recordKind: "taskFailed"`. Other outcomes retain their previous rules; canonical kinds still cannot use the generic route. The producer-shaped regression and stronger decoder negatives are appropriate preparation. No compilation/test PASS, locked dependency closure, portability, integration, adoption or actual D1 proof is qualified.

## 1. Artifact summary and review method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime model identity not independently exposed. Applied the full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full during this continuous review. This focused successor addresses all six phases and carries forward unchanged-boundary reasoning from `integrity-stack/docs/native-provenance-after-architecture-shared-source.md`. The v1 certificate remains immutable historical evidence; its exact source identity is superseded for adoption by this successor.

Read the actual revised schema/tests and maintained runtime producer; independently recomputed all12 v3 pins and compared v1/v2/v3 manifest identities. Static source inspection only: no Cargo/native/build/tests/live commands or production source edits. Only this certificate written; others' work preserved.

Category: product capability/proof infrastructure. Core private root `/private/tmp/core-native-provenance-v1-20261009/work-spec`, base `22296385f4ef179ad330f55d80592194f8b3af6b`. Core-relative citations below refer to that private root.

| Exact artifact | SHA-256 |
| --- | --- |
| Workspace `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-source-v3.json` | `3a410dfebd233e7604dbf30b17ec900e51e131c3313117ea420ee4bf23536268` |
| `schemas/wos-native-provenance-event.schema.json` | `18c370ffcc8a1274ba89cfe3a8aca3b1bd452e530b637d3e1349d71fc04c0304` |
| `crates/wos-events/src/native_provenance/tests.rs` | `22410eabf117f86870b6c653c715493aea9fe279de00e9b596aba0b8639bf73a` |
| Unchanged `crates/wos-events/src/native_provenance.rs` | `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d` |
| Unchanged private offline patch | `bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97` |

All12 current v3 pins match independently. Only schema and helper tests differ from v1. V3 differs from v2 only in schema identity. During v2 review the current schema hash changed from its manifest's `e6f6f60e…` to `18c370ff…`; exact approval was held and root notified. No v2 approval certificate was written. Owner reports that mutation corrected enum spelling `TaskFailed` to serialized `taskFailed`. V3 now pins the observed coherent bytes and uses the correct serialized discriminator. The earlier v2 manifest hash `c51a1aa64d82a587218f8b674198c6f0430efad481c35f2045cd2b14677c0471` is historical, not current closure evidence.

## 2. Lineage and relationships

| Artifact | Relation | Evidence |
| --- | --- | --- |
| Maintained runtime producer | Establishes actual native outcome requiring preservation | `crates/wos-runtime/src/runtime/tasks.rs:687–699` constructs TaskFailed, system actor, expiry details and outcome expired |
| Original separate native schema | Source-v1 rejection mismatch identified in wider Core architecture review | Historical v1 schema pin `c0de3586…`; original outcome reference allowed reserved/x-prefixed outcomes only |
| Revised schema | Corrects transport admission without rewriting original facts | schema:15–24 and104–109 |
| Parent static-source certificate | Preserves shared helper and adapter architecture reasoning | Workspace `integrity-stack/docs/native-provenance-after-architecture-shared-source.md` §§2–7 |
| Joint v2/Core v3 proposal | Requires full original native record with shared owning validation | Previously pinned proposal bodies; preservation, decoder policy and verification gates |

WOS owns the maintained producer, schema and validator. Trellis admission/offline consumers use the same helper; generic Integrity remains responsible for byte proof and the domain-validator interface. This correction introduces no API, literal, decoder, registry or dependency change. It changes acceptance of one existing native fact, not the source fact or specialized canonical route.

H1(high), `expired` must be rewritten into an x-prefixed outcome to pass: **REFUTED**. The actual producer emits expired and preservation requires admitting that exact supported native fact. H2(high), correction admits expired on every remaining kind: **REFUTED** by schema's record-level implication and still-required discriminator. H3(high), exact v2 closure was stable: **REFUTED** by observed hash mismatch; held approval is superseded by independently matching v3. H4(high), v3 source establishes execution: **REFUTED**; manifest remains uncompiled with lock/frozen closure pending.

## 3. Invariants and commitments

| Invariant | Status | Evidence / failure mode |
| --- | --- | --- |
| Preserve native TaskFailed expiry fact | PRESERVED by correction | Producer tasks.rs:687–699; schema104–109 accepts expired; tests68–84 retain entire serialized record and wrapped decode. Rewriting outcome would lose source fidelity. |
| Expired applies only to TaskFailed | PRESERVED | schema15–24: if outcome is expired, recordKind must equal taskFailed; recordKind remains required26–31. TaskCreated negative at tests85–86. |
| Other outcome rules remain unchanged | PRESERVED | schema106–108 keeps shared ProvenanceOutcome reference alongside exact expired; arbitrary unknown-native-outcome refuses in prepared test87–89. |
| Canonical-kind exclusion, closed structure and known-kind checks | PRESERVED | Unchanged helper57–79; schema required/closed record remains; existing canonical28 parity tests retained. This correction cannot override helper canonical refusal. |
| Duplicate/tag checks precede lossy JSON conversion | PRESERVED, stronger negative preparation | Unchanged helper148–189; tests139–141 target duplicate recordKind; tests153–166 target misplaced/nested tags, nontext tag child and nested tag0. |
| Domain/privacy/dependency separation | PRESERVED | Unchanged offline patch invokes wrapped helper, emits fixed Failure messages/hash only; no generic Integrity WOS dependency added. |

The new regression mirrors the actual `task_lifecycle(TaskFailed, ...)` constructor, original expiry detail object, system actor and native outcome, then supplies the persisted timestamp/tier/version fields. It asserts complete original JSON equality and wrapped decoding, plus TaskCreated/unknown-outcome refusal. It is producer-shaped test preparation, not an executed runtime-expiry test. Maintained bare timestamp-tag policy and wrapped tag refusal remain unchanged. No original bytes or values are normalized by this schema correction.

## 4. User-value analysis

The correction prevents legitimate native task-expiry records from being blocked by a transport schema narrower than the maintained producer. It preserves history without inventing outcome translation or broadening every kind. This pays down a real producer/schema mismatch with one conditional and regression; no speed/resource benefit is claimed. Accepting expired globally would add unnecessary semantics; changing the producer's existing fact to satisfy a transport schema would violate preservation. Value is falsified if a genuine TaskFailed expiry still refuses, a different kind accepts expired or admission/offline differ through separate validation rules.

## 5. Counterfactual check

Kill criteria: discriminator spelling does not match serialization, expired succeeds for another kind, arbitrary outcomes enter TaskFailed, canonical bypass succeeds or frozen source hashes disagree. Current v3 resolves the observed spelling/closure mismatch and preserves the other static exclusions. Removing the correction restores refusal of the maintained expiry fact. Existing shared outcome schema does not subsume this native TaskFailed case; its original reserved/vendor rules remain the default branch. A future reviewer should first demand actual coordinated execution and full runtime-window evidence, rather than treating these prepared tests as proof.

## 6. Findings and dispositions

- **KEEP — OBSERVATION / intent-vs-shape:** exact TaskFailed-only expired allowance and original source fact. Schema15–24,104–109; producer tasks687–699. No required reshape.
- **KEEP — OBSERVATION / commitment:** unchanged shared raw-value/decoder and thin offline adapter boundaries; prepared producer-shaped and stronger decoder regressions.
- **KEEP — OBSERVATION / provenance:** retain v1 and historical v2 artifacts, recording the held v2 mismatch and coherent v3 replacement. Do not relabel mutable v2 as approved.
- **REVERSE — OBSERVATION / scope:** reject broad expired admission, producer normalization, test-PASS claims or adopting source-v1 approval as final approval for the corrected schema.
- **DEFER — OBSERVATION / scope:** native execution, lock resolution, portable private dependency/source closure, broader integration/adoption and actual D1. These remain owner gates, not new approval pauses imposed by this review.

## 7. Verdict

```text
VERDICT: APPROVE frozen v3 static correction and unchanged offline alignment
Intent vs. shape: MATCHES — preserve native TaskFailed expiry with kind-specific admission.
User-value claim: SUPPORTED — removes producer/schema mismatch without rewriting facts.
Commitment status: HONORED — canonical, strict-record, decoder and domain/privacy boundaries preserved.
Conceptual debt delta: PAYS DOWN — bounded owning schema correction.
Sibling subsumption: PARTIAL — shared outcome rules remain; native expiry needed this exact branch.
Confidence: HIGH for static correction and matching identities; execution/adoption unqualified.
```

This is a focused successor to the prior full static review, not a claim to have compiled or run the corrected helper, exercised live history, established custody completeness or approved deployment.

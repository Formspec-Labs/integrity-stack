# Final offline CLI composition — BEFORE architecture review

**VERDICT: APPROVE the bounded composition and admission/reconciliation plan. The current candidate is not build-ready or an eligible final CLI.** Its standalone lock omits the `jsonschema0.46` dependency required by the composed WOS helper and its transitive closure. Retain the expected locked-admission failure, reconcile privately only in the assigned serial window, review/freeze the actual lock delta, then run the existing20 CLI tests and retain a hashed build. No generic production change, custom verifier or repeat of the638-qualified suites is required by the inspected shape.

## 1. Frame and method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime model identity not independently exposed. Read **in full** `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` and applied all six phases below. Static inspection only: no Cargo/metadata/build/native/test/HTTP/live commands. Only this certificate written; preserved other owners' work and prior qualified evidence.

Category: proof infrastructure serving operators who need a maintained offline CLI with both the existing independently selected registry snapshot gate and current native WOS semantics. Private root `/private/tmp/integrity-final-cli-composition-v1-20261010`; candidate-relative paths below use that root. Workspace plan: `thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/final-d1-offline/final-cli-composition-plan-v1.json`.

| Exact artifact | SHA-256 |
| --- | --- |
| Plan | `55106d7d0682d622b991c611e038674d731cc191a93b3f13d9dfa5b49a76d4cc` |
| Candidate source-pins.json | `6b3d2f77cd02f296635f2f3c7bd6004f999a28857dab041016ce8825d32e4e84` |
| CLI Cargo.toml | `a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a` |
| Current stale standalone CLI Cargo.lock | `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e` |
| CLI src/cli.rs | `ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9` |
| WOS helper | `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d` |
| WOS schema | `18c370ffcc8a1274ba89cfe3a8aca3b1bd452e530b637d3e1349d71fc04c0304` |
| Offline adapter | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |

All8032 `sourceFiles` pins independently match current candidate files. The manifest reports no missing or external path references. This source identity/path evidence does not establish actual Cargo resolution or feature selection. No exact eligible executable yet exists in this reviewed packet.

## 2. Lineage and relationships

| Artifact | Relation | Evidence |
| --- | --- | --- |
| Existing Integrity registry-pin CLI, owner revision4dc55bc | Retained production source, previously qualified on older graph | Exact unchanged CLI hash; workspace docs/offline-export-trust-execution-architecture.md |
| Qualified dependency source base | Current native WOS helper/adapter closure | source-pins.json qualifiedDependencyBase `/private/tmp/core-form-pin-zip-inputs-v2-20261009`; workspace full-d1/form-pin-zip-qualified-handoff-v2.json status/limits |
| Native static/execution architecture certificates | Own helper/schema/adapter boundaries and evidence limits | Workspace docs/native-provenance-after-architecture-shared-source-v3.md and native-provenance-after-architecture-execution.md |
| WOS-Trellis verification specification | Normative Core-first consumer semantics | Candidate trellis/specs/wos-trellis-verification.md:13–43 |
| Composition plan | Staged graph/build qualification and real-case limits | stages, executionControls, qualificationSuccess, actualCaseGatesRemain |

| Component/seam | Owner | Dependency/consumer | Evidence |
| --- | --- | --- | --- |
| CLI snapshot gate/formats | Integrity CLI | Maintained ZIP/hash primitives; calls WOS verifier | CLI src/cli.rs:293–304,341–378,603–614 |
| WOS domain validation | Trellis WOS verifier | Shared WOS helper and generic Integrity verifier | trellis-verify-wos/Cargo.toml; src/lib.rs:46–47; native adapter |
| WOS shape validator | WOS events | Cached jsonschema0.46, maintained CBOR/typeid | wos-events/Cargo.toml:10–18; helper |
| Standalone graph/eligible binary | Assigned native execution owner/root | CLI's own workspace lock; retained receipts | CLI Cargo.toml workspace declaration; plan stages |

The CLI is its own workspace root, so a coherent Trellis workspace lock does not repair its lock automatically. The owning Trellis lock has jsonschema0.45.1 and0.46.1 for separate consumers; the helper manifest requests0.46 with default features disabled. Do not collapse those versions or substitute0.45 merely to reuse an older graph.

H1(high), source composition needs a new generic verifier: **REFUTED** by maintained `trellis_verify_wos::verify_export_zip` delegation. H2(high), the old CLI lock already closes the new helper graph: **REFUTED** by absent jsonschema package/edge. H3(high), owning workspace lock suffices for standalone CLI: **REFUTED** by its own workspace declaration. H4(high),8032 matching pins qualify a final executable: **REFUTED**; resolution/tests/build remain gated.

## 3. Invariants and actual readiness gaps

| Invariant | Status | Evidence / failure mode |
| --- | --- | --- |
| Same ZIP bytes reach snapshot gate and maintained verifier | PRESERVED | CLI:294–302; separate reads would permit substitution. |
| Exact snapshot equality is distinct from archive validity/agency trust | PRESERVED | CLI:341–378; plan actualCaseGatesRemain and prior architecture decision. |
| Existing text/json/both outputs retain meaning | PRESERVED | CLI OutputFormat:24–27; JSON pin fields:609–614; selected final invocation uses JSON, not a new format. |
| Generic Integrity remains free of WOS-specific parsing | PRESERVED | Trellis WOS consumer owns helper invocation; no new production delta. |
| Manifest and standalone lock agree before execution | CURRENTLY UNMET | wos-events/Cargo.toml:12 requires jsonschema0.46; CLI lock's wos-events entry omits it and contains no jsonschema package. |
| Actual admitted graph is frozen before tests | REQUIRED / planned | Plan stages admission→reconciliation→review/freeze→tests/build; failures retained. |

Static comparison to the owning0.46.1 lock shows absent transitive package names including ahash, bytecount, data-encoding, email_address, fancy-regex, fraction, idna, num-cmp, num-traits, percent-encoding, referencing, regex, regex-syntax, unicode-general-category and uuid-simd. This is illustrative missing closure, not a complete resolver result or mandate to copy the whole Trellis lock. Mechanical reconciliation must inspect all new packages/versions/checksums/features and any changes to previously selected packages. `generate-lockfile --offline` may resolve more than one missing edge; its output is not automatically approved as mechanical. Unexplained upgrades require reshape/review before qualification.

Metadata without a host filter may also expose uncached nonhost dependencies; preserve the exact refusal and distinguish cache availability from a missing owning declaration. No download or alternate command is authorized by this static review. Plan control names Common as current window owner while parent mentions WOS ownership; the operative authority is root's next explicit serial assignment, not this certificate or either label.

## 4. User-value analysis

The composition joins already maintained capabilities so an eventual exact binary can assess the real final archive with independently retained registry selection. It pays down a stale graph/qualification gap without adding custom formats or duplicate verification. Existing20 CLI tests qualify the unchanged gate against the new dependency closure; their fixtures do not qualify an actual D1 archive. The plan adds fixture001 pre/post hashes, closing the previously documented missing fixture provenance comparison. The foreign digest is a compiled constant, not a read of fixture005 ZIP.

The smaller alternative is using the old binary, but its dependency graph lacks this helper and cannot qualify latest semantics. Repeating638 tests adds no identified value while their exact source closure remains unchanged. Value is falsified if the final CLI resolves a different helper/Integrity identity, tests pass on a graph different from the retained binary, or operators mistake registry equality for agency authority. No speed/resource claim is made.

## 5. Counterfactual and kill criteria

Kill criteria: unexplained production hash drift; duplicate Integrity verifier identity; wrong jsonschema family; unreviewed broad lock upgrade; fixture/source mutation; failed tests/build; missing binary digest or conflation with an older executable. The plan correctly fails closed at these gates. Removing composition leaves current offline CLI unable to establish the final helper graph. Custom D1 verification would duplicate maintained semantics and should be reversed. A future reviewer should demand the exact qualified executable/lock/fixture receipts and separately assess the actual archive and independent registry provenance.

## 6. Findings and dispositions

- **CONCERN / named-seam — RESHAPE the private lock only:** reconcile the actual standalone dependency graph under assigned authority, retain original lock/admission failure, inspect exact resolver delta and freeze successor pins before tests. No production-source change identified.
- **OBSERVATION / ownership — KEEP:** existing maintained CLI→WOS verifier→shared helper composition and formats; no custom verifier or638 repeat.
- **OBSERVATION / provenance — KEEP:** source/fixture pre/post guards, cleanup receipts, exact retained binary hash and separate failure lineage; preserve old baseline/qualified artifacts.
- **OBSERVATION / scope — REVERSE:** any designation of the current candidate or old baseline binary as final eligible verifier, or any claim that metadata/build proves full D1/agency authority.
- **OBSERVATION / scope — DEFER:** exact eligible binary designation until paired lock/source/result reviews; actual archive/current grants/registry custody and adoption remain separate owner gates.

## 7. Verdict

```text
VERDICT: APPROVE composition and bounded qualification plan
Intent vs. shape: MATCHES — reuse maintained capabilities without production delta.
User-value claim: SUPPORTED — closes standalone graph/executable gap.
Commitment status: HONORED by planned gates; lock readiness currently unmet.
Conceptual debt delta: PAYS DOWN — resolves stale dependency closure.
Sibling subsumption: PARTIAL — qualified owning source reused; standalone binary needs its own qualification.
Confidence: HIGH static identities/dependency gap; resolution/execution unqualified.
```

No native window, Cargo operation, eligible binary, actual archive verification, trust decision or deployment is authorized or certified by this report.

## Refined setup addendum — plan v2

**APPROVE the refined setup scope.** Plan v2 SHA-256 `77623af1d3773772f1cbf96d407b1835820f362c729938b89c7a41dc4493aed0` supersedes v1's locked-failure/broad-generate-lockfile sequence with one root-assigned **full offline metadata resolution** using the existing lock, without `--no-deps` and without `--locked` during that setup step. This is an explicitly bounded private lock mutation, not build qualification. Its preserved `setup/cargo-lock.before` independently hashes to `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e`.

The new ordering is sound: retain complete resolution/stdout/stderr/exit/cleanup and before/after lock; independently inspect every package/source/checksum/dependency/version/feature and local path identity; freeze successor metadata/source/lock pins; require full `--offline --locked` metadata before the existing20 tests and retained binary build. Inspect `resolve.nodes`, not just manifest/package lists. Preserve qualified jsonschema0.46.1 where resolution permits, explain every deviation, and refuse unexplained upgrade expansion. Root's serial assignment remains the execution authority; this report runs no setup command.

All previous boundary conclusions remain: no generic production delta, custom verifier or638 repeat; cached archives and static path checks are not graph-admission proof; no current eligible binary or actual D1/adoption claim. The addendum improves evidence completeness and reduces unnecessary fresh lock selection while retaining exact-delta review. No new architecture concern or required reshape beyond the planned lock reconciliation.

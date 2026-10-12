# Final CLI metadata — AFTER architecture disposition

**VERDICT: RECONSIDER progression on this resolved graph.** The bounded setup succeeded and retained a complete graph; it did not qualify a CLI. Before tests/build, perform owner-assigned targeted offline reconciliation toward qualified `jsonschema0.46.1` and `referencing0.46.1`, preserve existing CLI versions where compatible, retain each attempt, then review/freeze fresh full metadata and lock delta. The current0.46.8 selection and accompanying transitive upgrades have no demonstrated necessity or qualification. No source redesign, custom verifier or638-suite repeat is recommended.

## 1. Frame and method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime identity not independently exposed. Applied `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full during this continuous final-CLI review. All six phases below. Static reading/hash/TOML/JSON comparison only; no Cargo, metadata, build/test/native/network/HTTP command or lock edit. Only this certificate written; others' artifacts preserved.

Category: proof infrastructure. Candidate `/private/tmp/integrity-final-cli-composition-v1-20261010`; evidence in its `setup/`. Goal is a maintained CLI joining existing registry equality and current WOS semantics, not changing schema-library behavior. The root-granted full offline metadata setup exited0 after2.219seconds; receipt records leader71664 reaped and group clear. This is retained owner cleanup evidence, not fresh process inspection.

| Frozen artifact | SHA-256 |
| --- | --- |
| metadata-setup-receipt.json | `f7d1d03efbfb570c82e922ea621a34bae89a627cfbabcba3c964ec8dcbd69992` |
| graph-delta.json | `64e7e041dfd484d396dfa9ec652532e6955a349632d0a62302ec5e9b200cc59b` |
| source-pins.after.json | `c577c369ca66157f61b8dbadd6e1fd4d8a0c87697b56100018b48eab9bf7fa5a` |
| cargo-lock.before | `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e` |
| cargo-lock.after | `d8454f024e8d930bb2133d0c5baed0dbb998c33ac50f4596f527503d09b1fa09` |
| metadata.after.json | `e27a040ff4d3d05512a6fe8e8e1df7c93a2a12c2c50b9da2d38ac48ae9c77057` |
| metadata.stderr.log | `c588bd6206f241e799e018c1281f57ed00d2a9e3a34a6d0473e48325f8b79511` |

Receipt/delta/after-pins hashes independently match. All8032 after source pins match current files. Only standalone CLI lock changed from the initial source packet; helper/schema/production source remain unchanged. Metadata has158 packages and158 resolve nodes. Maintained `integrity-verify`, `integrity-cbor`, `trellis-verify-wos` and `wos-events` each have one identity; no external local manifests are reported. Full graph success is distinct from locked admission, compilation or tested behavior.

## 2. Lineage and relationships

| Artifact | Relation | Evidence |
| --- | --- | --- |
| Workspace docs/final-cli-composition-before-architecture.md | Parent setup approval with review-before-progression | Refined setup addendum and lock delta conditions |
| Composition plan v2 | Requires qualified versions where possible and exact feature/package review | stages exact package graph/lock review; executionControls selectedQualifiedVersions |
| Candidate trellis/Cargo.lock | Qualified owning version reference | jsonschema/referencing0.46.1 and distinct0.45.1 consumers |
| Candidate work-spec/crates/wos-events/Cargo.toml:12 | Owning semantic dependency | jsonschema0.46, default-features=false |
| Existing CLI production source | Maintained composed call, no custom semantics | CLI src/cli.rs:293–304; shared WOS helper/adapter unchanged pins |

WOS owns schema semantics; standalone Integrity CLI owns its lock/build; root assigns serial execution; review decides whether a resolved version change is appropriate. Dependency source manifests permit0.46 patch movement, but permissibility is not inherited qualification. Copying the entire larger Trellis lock would change scope rather than establish the smallest standalone graph.

H1(high), missing owning dependency is now resolved: **CONFIRMED** by full metadata. H2(high), resulting graph reuses qualified schema behavior: **REFUTED**; jsonschema/referencing selected0.46.8. H3(high), unchanged Rust source implies unchanged schema behavior: **REFUTED**; owning library implementation changed. H4(high), current metadata success permits tests/build without further review: **REFUTED** by parent explicit freeze gate and unnecessary version drift.

## 3. Invariants and actual delta

The lock comparison records79 additions,5 removals and2 changed package entries. Five removed packages are old js-sys0.3.105 and wasm-bindgen0.2.128 family, replaced by0.3.106/0.2.129. Same-key changed entries are WOS events adding jsonschema, and getrandom0.4.3 disambiguating r-efi6.0.0 after added getrandom0.3.4/r-efi5.3.0. The latter is not an upgrade/replacement of existing getrandom0.4.3. No same-version source/checksum substitution appears in these two changes.

| Commitment | Status | Evidence / consequence |
| --- | --- | --- |
| One maintained local verifier identity | PRESERVED | metadata/delta identity counts and internal paths. |
| Owning schema features stay disabled | PRESERVED | metadata node for jsonschema0.46.8 has empty enabled features; no default HTTP/file retrieval added. |
| Qualified schema-library behavior reused | NOT YET PRESERVED | qualified0.46.1 vs resolved0.46.8; helper uses this validator for load-bearing shape/timestamp decisions. |
| Existing CLI selections preserved where possible | UNPROVED | wasm/js patch family moved without necessity evidence. |
| No source/format/custom verifier scope expansion | PRESERVED | only CLI lock changed; reviewed sources unchanged. |
| Resolution separate from execution/adoption | PRESERVED in receipt | scope says no tests/build/networkdownload/archive/eligiblebinary claim. |

Added schema closure also resolves fancy-regex0.18.0 vs qualified0.17.0, regex1.13.1 vs1.12.3, and ICU normalization2.3.0 vs2.2.0. These libraries support actual schema pattern/format interpretation. New transitive packages are needed, but newest compatible choices are not automatically needed. Nonhost wasm entries may not execute on the selected host, yet are part of the retained full graph and must not be silently represented as baseline-preserved.

## 4. User-value analysis

Successful full metadata pays down the missing-graph uncertainty and identifies the exact unresolved version choice. Operators need a reproducible verifier using maintained qualified semantics; they gain no stated benefit from incidental patch/transitive upgrades. Pinning the qualified schema/referencing pair is the smaller next correction. Preserve original CLI selections wherever constraints allow; compare unavoidable transitive selections with the qualified closure and explain deviations. Do not assume targeted pinback will succeed: only a future owner-granted resolver receipt can prove compatibility/cache availability.

Existing20 CLI tests chiefly verify registry-gate/subprocess behavior; they do not independently requalify every changed schema-format implementation. Reusing qualified dependencies avoids reopening that behavioral scope. If necessary changes remain, their owning compatibility/behavior evidence must be explicitly reviewed instead of claiming638 evidence transfers unchanged. No benchmark/performance claim is made.

## 5. Counterfactual and kill criteria

Kill criteria: using0.45 for the owning helper, duplicate local identity, outside paths, unreviewed source/feature change, unexplained library drift, or calling setup qualified execution. Current local identity/features are sound; version-drift gate remains unmet. Opposite decision would accept new schema behavior solely because semver and metadata permit it, expanding validation scope without user value. Removing setup evidence loses exact graph discovery; retain it even after pinback. A future reviewer will ask why final validation differs from qualified library versions and whether binary/tests actually used the same frozen graph.

## 6. Findings and dispositions

**F1 — CONCERN / scope / RESHAPE.** Current setup graph selects unqualified jsonschema/referencing0.46.8 and newer associated interpretation libraries. Reconcile toward qualified0.46.1 pair under explicit owner setup authority; review the actual resulting full graph/features/delta, freeze successor identities and perform full offline locked admission before tests/build. If incompatible, retain refusal and bring the exact constraint to review; do not silently accept upgrades.

**F2 — CONCERN / intent-vs-shape / RESHAPE.** Existing wasm/js patch family shifted. Preserve old CLI family where compatible or document the actual forcing constraint and platform scope in the successor graph. Treat this as version-selection review, not a production source change.

**F3 — OBSERVATION / ownership / KEEP.** Complete metadata, original lock, receipts, clean-release record, after source pins and unchanged maintained composition. No manifest/source redesign or whole Trellis lock replacement.

**F4 — OBSERVATION / scope / REVERSE.** Any claim that this setup qualifies final executable/schema behavior/actual archive or agency trust.

**F5 — OBSERVATION / scope / DEFER.** Next tests/build until paired independent successor graph approval; actual D1/adoption remain separate. This certificate grants no native command or retry.

## 7. Verdict

```text
VERDICT: RECONSIDER current graph for tests/build progression
Intent vs. shape: DIVERGES on unnecessary qualified-version departure.
User-value claim: SUPPORTED for graph discovery; WEAK for incidental upgrades.
Commitment status: DRIFTING — qualified dependency preservation not established.
Conceptual debt delta: ACCRETES if new interpretation libraries adopted without need.
Sibling subsumption: PARTIAL — owning qualified versions offer smaller semantic scope.
Confidence: HIGH on retained identities/delta; resolver pinback feasibility untested.
```

Specific reshape: targeted offline qualified-schema/referencing pinback with compatible old CLI selections, exact successor graph review/freeze, then locked admission and existing20tests/build. No638 repeat or custom verifier is prescribed absent a demonstrated remaining semantic change.

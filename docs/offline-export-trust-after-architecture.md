# Offline export registry pin — AFTER architecture review

**VERDICT: APPROVE the exact static implementation boundary.** The optional CLI snapshot pin composes with the maintained native verifier, preserves same-byte verification and distinguishes matched from unrequested selection. No required architectural reshape remains. Native compilation and test execution remain pending; this is not executable qualification, actual D1 archive proof or agency-origin evidence.

## 1. Scope and reviewer

Independent non-author reviewer `/root/handoff_before_review`, parent-requested gpt-6.1-sol/medium; runtime model identity not independently exposed. Read in full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` for this AFTER gate; all six phases completed. Category: offline proof infrastructure/operator tooling. Only this certificate written; all implementation and unrelated files preserved. No Cargo, native build/test, verifier execution, live call or private input.

Base Integrity HEAD: `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Reviewed current changes to four tracked CLI paths plus the new usage document. SHA256 of `git diff --binary d2dd482 --` those four tracked paths: `cb34fe67d2488d668014630618ad8169a3d3d554f3a41a171562f8b071da1d45`. Untracked usage document is separately pinned below; the tracked diff digest does not include it or review certificates.

| Exact file within integrity-stack | SHA256 |
| --- | --- |
| crates/integrity-verify-cli/Cargo.toml | `a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a` |
| crates/integrity-verify-cli/Cargo.lock | `c3549e67ad697f4cd03f9752a53d308b88ec469b5abf8c60eebd85d880ecec66` |
| crates/integrity-verify-cli/src/cli.rs | `ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9` |
| crates/integrity-verify-cli/tests/verify_bundle.rs | `addf2343978168bb92439332db0af34ae0dbcfb19de6908580a854aa19bc2ea8` |
| docs/offline-export-registry-pin.md | `1ee7d1511a3b4d8cb2109a92df621d78c99ce575db6b2f87d450107d945548c2` |
| docs/offline-export-trust-before-architecture.md | `673d9f6e2cd809860cd0c3fb4b68c3ee556d8085014c6a4401cb01371a132a3e` |

Paths in evidence below are relative to `/Users/mikewolfd/Work/formspec-stack`; `CLI` abbreviates `integrity-stack/crates/integrity-verify-cli/src/cli.rs`.

## 2. Lineage and relationships

| Prior artifact | Relation | Evidence |
| --- | --- | --- |
| BEFORE architecture certificate | Immediate accepted shape: CLI-only exact registry selection, explicit limits | before certificate:§§2–7,I1–I7 |
| Trellis Core §§18–19 | Native archive and embedded registry verification authority, unchanged | `trellis/specs/trellis-core.md:1325–1343,1738–1747` |
| Trellis Core §20 | Trust-honesty/absence of legal sufficiency claims | Core:2486–2530 |
| Existing native verifier | Signature/proof/domain mechanisms remain owning truth | `integrity-stack/crates/integrity-verify/src/trellis/export.rs:153–245,1680–1693` |
| WOS/Python wrappers | Siblings deliberately retain existing API semantics | `trellis/crates/trellis-verify-wos/src/lib.rs:46–47`; `trellis/trellis-py/src/trellis_py/verify.py:4596–4654`; `verify_wos.py:229–246` |
| User outcome | Offline complete case proof still depends on actual archive, signer/source/history coverage | `thoughts/plans/benefits-scenarios/artifact/01-appendix-requirements.md:45,53,99` |

| Component / seam | Owner | Input → output / consumer |
| --- | --- | --- |
| Expected snapshot argument | Operator supplies; Integrity parses | Independently retained64lowercasehex → explicit selection |
| Raw registry admission | Integrity CLI | Same ZIP bytes, one relative030 member → equality/refusal |
| ZIP and SHA primitives | Maintained integrity-bundle/integrity-cbor | Reader entries/raw bytes and SHA256 digest |
| Native archive/WOS verification | Existing Integrity/Trellis WOS | Unchanged ZIP buffer → owning native report |
| Actual exporting authority and records | Deployment/root/bindings/Trellis | Independent provenance/records → future operation inputs |

No archive shape, deployment profile, library exporter-trust API or Trellis/Python ownership change. Cargo.toml and lock add only the maintained sibling integrity-cbor dependency; no new crypto implementation or package version upgrade.

## 3. Invariants and commitments

**I1 — One owned candidate: PRESERVED.** CLI:293–302 reads once, passes the same `zip_bytes` slice to `check_registry_pin` and existing WOS verification. No refetch or pathname reread separates gate from verifier. Gate uses maintained reader:345–346 and unchanged entry bytes:361–364.

**I2 — Member selection matches native path handling: PRESERVED.** CLI:349–359 removes exactly one root component and requires relative030 equality, counting before map collection. Existing Core parse_export_zip:1680–1693 strips the same component. Missing, nested, rootless and multiple relative matches refuse. This matches actual native lookup rather than a filename suffix. Even two different root prefixes with the same registry relative name refuse ambiguity. No duplicate is silently overwritten at this new gate.

**I3 — Strict caller-selected pin: PRESERVED.** CLI:166–184 requires exactly64 lowercase ASCII hex digits and rejects duplicate selection flags or missing values. Expected pin comes from arguments; observed hash comes from maintained SHA256 of exact member bytes. Mismatch includes expected/observed and returns before native/report output:365–368. Argument text cannot manufacture independent key provenance; docs explain that copying the archive's own hash is not independent origin evidence.

**I4 — Gate does not replace native verification: PRESERVED.** CLI:301–302 gates then delegates unchanged verifier. CLI:328–335 retains existing failure-count/structure/integrity exit conditions. A valid pin with invalid manifest/registry/native structure still fails. No custom profile registry or fake WOS validator is introduced. Existing native report remains the source of archive validity.

**I5 — Outcome meanings remain explicit: PRESERVED.** CLI:373–378 distinguishes `matched`/`not_requested`; text:564–577 and JSON:603–616 report selected expected/observed values. After gate success they are necessarily equal; reproducing the expected value as observed is justified by the preceding exact equality and private sequential call path. With no pin both JSON digest fields are null, not an assertion of observed external trust. Mismatch/selection errors return before a success report, while matched-pin/native-failure reports preserve `verified:false`. Existing `verified` describes archive verification, and success invocation with a supplied pin requires both stages.

**I6 — Whole snapshot is not exporter-only or human/agency authority: PRESERVED.** Usage text and owning document explicitly deny agency authority, signer identity, freshness and disclosure permission. Selected snapshot may contain historical rotation keys. Current capability does not select exactly one manifest signer from that snapshot and does not authenticate how the operator acquired it. Native report and this CLI result must not be promoted to those stronger claims.

**I7 — Maintained dependencies and direction: PRESERVED.** CLI imports public `integrity_cbor::sha256_bytes`; existing helper is `integrity-stack/crates/integrity-cbor/src/lib.rs:132`. Cargo.toml declares that sibling directly and lock records the dependency. Maintained bundle reader remains direct. No public API is added merely to expose a hash helper; no WOS/Python wrapper changes.

**I8 — Prepared checks versus execution: PRESERVED.** Unit cases CLI:792–951 cover parser refusal, raw-member match/mismatch, missing/nested/rootless/duplicate/malformed members, matching bytes with invalid native archive and actual manifest signature corruption. Integration test:142–192 prepares native fixture001 correct-pin success and the same valid fixture with a different fixture's digest refusal, plus explicit no-pin JSON assertions:130–132. The latter is an incorrect externally selected snapshot against a valid archive, not execution of fixture005 as a replacement archive; do not describe it otherwise. All cases remain uncompiled/unexecuted in this review. Owner reports rustfmt/diff checks only.

## 4. User-value analysis

The operator gains one integrated offline refusal and machine-readable observation for an independently selected registry snapshot, replacing a manual precheck. Actual archive validity still uses existing code. This pays down repeated operator composition without cross-owner API churn. It adds CLI argument/report logic and an additional maintained ZIP parse/copy when pinning; no speed or memory improvement is claimed or measured.

Exporter-key-only library APIs remain a valid different requirement but would change multiple owned surfaces unnecessarily for this snapshot workflow. A shell precheck is smaller library footprint but lacks integrated same-buffer result/exit handling. The current shape is proportionate. Six-month falsifier: users cannot distinguish unrequested versus matched selection, or the output is treated as agency identity/full D1 completeness despite absent provenance/history.

## 5. Hypotheses and counterfactuals

H1(high), implementation matches BEFORE boundary: **CONFIRMED** by CLI path, dependency and output. H2(high), gate and native verifier select different030 bytes: **REFUTED** by matching one-component path handling, uniqueness check and same buffer. H3(high), matched digest alone produces success: **REFUTED statically** by preserved delegate/exit checks and prepared negative tests. H4(high), output expands trust semantics: **REFUTED** by explicit matched/not_requested and documentation limits. H5(high), native verification is now qualified: **REFUTED**, tests are only prepared.

Kill criteria remain wrong-pin success, ambiguous registry accepted, different candidate buffers, native failure suppressed or no-pin labeled external trust. None is apparent in inspected implementation. Counter-decision: broad manifest-key library API adds ownership cost for a different selection scope. Removal probe leaves native verification but loses integrated external snapshot constraint. Sibling subsumption partial: maintained primitives own all cryptographic/archive mechanisms. Future critic should require executed exact-binary results and independent actual registry provenance before claiming operational proof.

## 6. Findings and dispositions

**F1 — OBSERVATION / named-seam / KEEP.** Same-buffer gate, native-relative path/unique member selection, strict digest parsing, maintained SHA dependency and unchanged verifier match approved design. No required RESHAPE.

**F2 — OBSERVATION / scope / DEFER execution qualification.** Coordinated native compilation and prepared tests must run separately before representing this as a working binary or passing it to the old installed CLI. Static approval is not test PASS. No real archive/record evidence was inspected or created here.

**F3 — OBSERVATION / ownership / REVERSE stronger claims.** Do not characterize the snapshot as agency trust, one authorized exporter, human identity, freshness, disclosure permission or legal sufficiency. Keep docs and explicit no-pin evidence. Actual D1 events/member bytes remain owned dependencies.

**F4 — OBSERVATION / sibling-conflict / DEFER wider APIs.** No Trellis/Python library parity claim for this CLI-only operator constraint. Revisit coordinated library API only when non-CLI or exporter-only consumers actually require it.

## 7. Verdict and limitations

```text
VERDICT: APPROVE
Intent vs. shape: MATCHES — narrow CLI registry snapshot admission.
User-value claim: SUPPORTED — integrated equality/refusal and explicit output.
Commitment status: HONORED — native semantics/dependency boundaries unchanged.
Conceptual debt delta: PAYS DOWN — manual composition reduced without broad API churn.
Sibling subsumption: PARTIAL — maintained primitives/verifier reused.
Confidence: HIGH for static architecture; compilation/tests/actual operation unqualified.
```

Read full skill, approved BEFORE certificate in continuous review, exact scoped diff, usage document and maintained callee/path/hash boundaries. Hashes independently recomputed. No native build/test or live execution authorized or performed; prepared test correctness at runtime remains unresolved. This architecture certificate does not substitute for independent code review or executed validation. Only this report added; other owners' work preserved.

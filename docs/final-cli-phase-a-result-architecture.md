# Final CLI Phase A — proportional architecture result acknowledgment

**VERDICT: APPROVE the retained Phase A result and close the focused actual-CLI-graph qualification finding. Phase B's existing twenty CLI tests and build are ready for a separate root grant.** The seven maintained WOS helper tests and six Trellis adapter tests actually passed in the joint CLI-root invocation. This does not designate a final executable or qualify an actual D1 export.

Independent reviewer `/root/handoff_before_review`, parent-requested gpt-6.1-sol/medium. Applied `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full in this continuous review. Static inspection of retained JSON, logs, metadata and hashes only; no Cargo, native command, runner, test, build, HTTP or live-process inspection. Only this certificate written; other owners' edits preserved.

## Exact evidence and findings

Evidence directory: `/private/tmp/integrity-final-cli-composition-v1-20261010/execution/phase-a-20261010-v1`. Independently matching SHA-256 identities:

| Artifact | SHA-256 |
| --- | --- |
| receipt.json | `9521ecc5d0a1e5335c7ce60f20986ce957f3e8a66ed8cdb8902610a84d596865` |
| owning-artifact-comparison.json | `d4a7b787519e47412a0ff0f3bcd1aae8de76652463e34c1d4841b1243b55c5a0` |
| host-artifact-comparison.json | `4922299c58722dd238956cd7c2ba4e6bb415e88353f69deeee961f56af6935d9` |
| host-feature-explanation.json | `8035be61f7d6c5c22765f7e39b54d9ea3a004a0056f6b05913bd3806336fd24a` |
| joint-native-tests.stdout | `5a60eca30c67864e56838ef68d76ba776f008c9eba72f0d4ec925a166723b7d7` |
| locked-metadata.stdout | `58e0ff66009f4899e080ee7d78d8f5d45fd9b3a0be4d6a80f0d8abd756245b5e` |

All receipt-declared stdout/stderr log hashes independently match. The receipt binds final plan `69c3bc77b0b9e1c7a6bb15294a83a696834407015345f7a112c9d09b7a63d6c3`, the paired prior review hashes, successor source packet `3e704e021742e4724d295f0de84088a9f6a5d43cca0fe26c031d776ea4b102df`, 8,032 source pins, no changed source files, and unchanged CLI lock `08752bd38d551e765565a938765976cf341509bc5cc59b93cd25827695cfab1b` (`receipt.json:sourceCount/changedSourceFiles/afterCliLockSha256`). Source preservation is retained operator evidence here, not a fresh reviewer traversal of all source files.

**F1 — OBSERVATION / KEEP:** The previously unresolved package-selection feasibility is resolved for retained Cargo/rustc 1.89.0 on `aarch64-apple-darwin`. Receipt argv matches the reviewed full offline locked metadata and joint CLI/helper/adapter test commands. Every stage exited zero; recorded leaders were reaped and groups clear; root reports the window released. Test elapsed time was 47.795 seconds, total 50.253 seconds (`receipt.json:stages`; identity stdout files). These are execution timings, not comparative performance measurements.

**F2 — OBSERVATION / KEEP:** Raw mixed test output shows six adapter and seven helper named passes, including original JSON/timestamp preservation, ambiguous CBOR refusal, canonical bypass refusal, bounded schema/numeric/depth checks and kind-specific expiry behavior (`joint-native-tests.stdout:test native_provenance::tests / test result`). The CLI harnesses show zero passes with fifteen and five tests filtered out; this provides no coverage of the twenty CLI tests.

**F3 — OBSERVATION / KEEP:** Full metadata has 158 packages and 158 resolve nodes. Independently compared complete `packages` and `resolve` structures equal the retained pinback metadata, beyond a count-only check. Owning artifact records identify the actual local helper/adapter and maintained jsonschema/referencing 0.46.1, fancy-regex 0.17.0 and Integrity primitives with matching features; helper/adapter ordinary library and test harness profiles remain distinguishable (`owning-artifact-comparison.json`). This closes the focused actual-graph finding in `final-cli-pinback-result-architecture.md:Concrete next gate`, rather than borrowing proof from another workspace.

**F4 — OBSERVATION / DEFER cross-target claims:** Host comparison records 156 artifacts from 130 packages; 32 of 39 introduced reference differences were observed. The remaining seven belong to unobserved conditional/platform branches; full metadata membership does not establish host activation. `getrandom` 0.3.4 host artifacts have empty features while full metadata includes `wasm_js`. Retained metadata identifies `wasm_js` requests on `cfg(target_arch = "wasm32")` jsonschema/referencing edges, while the ahash host edge requests no features. This supports the host-versus-all-target distinction, not blanket feature equality or cross-target qualification (`host-artifact-comparison.json:featureMismatches/introducedResidualNotObserved`; `locked-metadata.stdout:packages.dependencies`).

## Decision, lineage and limits

The retained `host-feature-explanation.json:featureDifferences` independently pins and explains both getrandom build-script and library records against their declared/resolved incoming edges. Phase B must match actual Phase A host features; forcing the all-target metadata feature union would change the selected host qualification rather than resolve a demonstrated mismatch.

The six-phase parent reasoning remains valid. This is proof infrastructure serving reliable offline interpretation. It refines the pinback decision and crosses the named WOS-owned strict helper → Trellis-owned domain adapter → Integrity-owned CLI composition seams without adding production logic or reversing dependencies. Maintained behavior remains the authority; execution supplies the missing actual-host-graph evidence. Removing this gate would leave residual interpretation dependencies untested; repeating all 638 sibling tests or matching every historical patch is not justified by this bounded result.

**KEEP** the exact source/lock packet, raw output, artifact identities and root cleanup receipts. **RESHAPE:** none required by this result. **DEFER** eligible executable designation until separately granted Phase B executes the existing fifteen unit and five integration tests plus build, preserves fixture/source/lock pins, and compares relevant ordinary-library package/features/target identities to Phase A while allowing test-harness/profile differences (`plan-v4:phaseB`). Any source drift, mismatch, missing tests, refusal or failed build stops progression. Phase A emitted compiler artifacts, including a CLI path; their existence is not final executable qualification.

**REVERSE** any claim of full dependency/platform qualification, actual D1 archive verification, independently selected agency trust, live deployment or adoption. Actual archive, registry custody and workflow evidence remain separate gates (`plan-v4:actualEvidenceGatesRemain`). Confidence is high in the retained focused host result; final CLI behavior and executable qualification remain pending. No reviewer execution or further native grant is implied.

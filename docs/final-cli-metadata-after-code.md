# Final CLI metadata: independent AFTER graph review

VERDICT: REQUEST CHANGES to the qualification plan before tests/build progression. The resolved graph is coherent and its retained setup evidence matches, but it changes the owning schema-validation implementation beyond the previously qualified closure. Either preserve qualified dependency selections where compatible or add focused native-helper/adapter qualification on this exact successor graph. This is a coverage finding, not an identified validator defect.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-10. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`; relevant Rust guidance retained from previous reviews. Static retained metadata/lock/source/archive inspection only. No Cargo, metadata rerun, native execution, test/build or live calls. Only this certificate was written; no source/lock changes.

## 1. Patch summary and exact evidence

Candidate `C`: `/private/tmp/integrity-final-cli-composition-v1-20261010`; setup files reside under `C/setup`. Actual setup was full offline metadata without `--locked`, as authorized in plan v2. The receipt records exit0, leader reaped and process group clear; test/build did not run (`metadata-setup-receipt.json:1–26`, scope at file end). This reviewer checks retained evidence rather than replaying it.

Independently recomputed SHA-256:

| Input | SHA-256 |
| --- | --- |
| `setup/metadata-setup-receipt.json` | `f7d1d03efbfb570c82e922ea621a34bae89a627cfbabcba3c964ec8dcbd69992` |
| `setup/graph-delta.json` | `64e7e041dfd484d396dfa9ec652532e6955a349632d0a62302ec5e9b200cc59b` |
| `setup/source-pins.after.json` | `c577c369ca66157f61b8dbadd6e1fd4d8a0c87697b56100018b48eab9bf7fa5a` |
| `setup/metadata.after.json` | `e27a040ff4d3d05512a6fe8e8e1df7c93a2a12c2c50b9da2d38ac48ae9c77057` |
| `setup/metadata.stderr.log` | `c588bd6206f241e799e018c1281f57ed00d2a9e3a34a6d0473e48325f8b79511` |
| Original standalone CLI lock | `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e` |
| Successor standalone CLI lock | `d8454f024e8d930bb2133d0c5baed0dbb998c33ac50f4596f527503d09b1fa09` |

Rehashed all8,032 successor source pins: zero mismatch. Source continuity remains CLI-lock-only; source/manifest implementation is unchanged. Independently derived lock deltas:79 added,5 removed,2 changed entries, matching the report arrays. Read every delta package's name/version/source/checksum/dependency list and every metadata node's dependencies/target kinds/features. Compared with the previously qualified Trellis lock as reference, not as a drop-in lock.

Hypotheses: H1, mechanical setup could duplicate local verifier identities, refuted. H2, external local source paths could appear, refuted. H3, changes might be just missing schema-package bookkeeping, refined: schema0.46.8 plus other newly selected validation dependencies differ from qualified0.46.1. H4, planned20tests validate that behavioral change, refuted by actual test assertions. The remaining qualification gap follows from H3/H4.

## 2. Function and graph trace

Locations below are relative to C unless a cache path is stated.

| Function / node | Location | Input → output | Verified behavior |
| --- | --- | --- | --- |
| CLI owned ZIP flow | `integrity-stack/crates/integrity-verify-cli/src/cli.rs:293–337` | file bytes → pin gate → owning verifier/report | Unchanged source; pin and verifier consume same owned buffer. |
| Actual WOS verifier | `trellis/crates/trellis-verify-wos/src/lib.rs:47–49` | ZIP → maintained substrate/domain validation | Same single local Integrity verifier identity as CLI. |
| Native adapter | same crate `src/validator.rs:22–26`, `src/native_provenance.rs:10–35` | generic event bytes → helper result/findings | Still delegates to actual shared strict byte helper; no copied schema/kind list. |
| Shared schema validator construction | `work-spec/crates/wos-events/src/native_provenance.rs:70–78` | embedded schema/raw JSON → validation result | `jsonschema::options().should_validate_formats(true).build` and `validate` remain behavior-critical. |
| Owning declared dependency | `work-spec/crates/wos-events/Cargo.toml:12` | jsonschema0.46, default-features=false → resolved0.46.8 | Version meets manifest semver range; metadata shows no jsonschema features enabled. |
| New schema node | CLI `Cargo.lock:630`, metadata package/node for jsonschema0.46.8 | resolver selection → regex/reference/format dependencies | Introduces referencing0.46.8, fancy-regex0.18 and regex1.13.1. Cache jsonschema0.46.8 Cargo.toml:151–152,178–179 declares those ranges. |
| WebAssembly family | CLI lock:619,1277 | js-sys0.3.106 → wasm-bindgen0.2.129 | Cached js-sys0.3.106 Cargo.toml:73–74 requires exactly0.2.129, explaining aligned macro/support/shared updates. Metadata records these through wasm-target getrandom0.3.4 edges; this is not host portability qualification. |

## 3. Data flow and graph invariants

Metadata contains158 packages and158 resolve nodes. Independently confirmed every edge names an existing package, every package matches a lock name/version/source identity, every lock dependency resolves to the same metadata dependency name/version, and every selected feature exists in its package feature declaration. No unresolved edge or dependency discrepancy was found. All local package manifests remain inside C; exactly one each of `integrity-verify`, `integrity-cbor`, `trellis-verify-wos` and `wos-events`. The declared report feature map exactly matches actual metadata nodes.

All79 added packages have the standard crates.io registry source. Independently hashed each cached `.crate` archive against its successor lock checksum: zero missing/mismatching archives. This establishes those retained archive identities; it does not audit every third-party implementation, guarantee pristine extracted source, build success or portable toolchain compatibility. Full node features include jsonschema[] (no default HTTP/file-resolution features), referencing[default], Integrity CBOR[default,json,std], getrandom0.3.4[wasm_js] alongside preserved0.2.17/0.4.3. No extra local dependency identity or replacement of crypto packages was found.

Five removed entries are js-sys0.3.105 and wasm-bindgen/macro/macro-support/shared0.2.128; corresponding additions are0.3.106/0.2.129. Other original CLI package versions remain selected. Two same-identity changes are: `wos-events` adds jsonschema; getrandom0.4.3 changes its lock dependency spelling from `r-efi` to `r-efi 6.0.0` because added0.3.4 also needs r-efi5.3.0. The latter is dependency disambiguation, not a replacement of the old random implementation. Metadata's target-specific edges support these distinctions.

Added-package inventory inspected in full (checksums/dependency arrays bound by the exact graph-delta and successor lock hashes above):

`ahash0.8.12`, `aho-corasick1.1.5`, `allocator-api2 0.2.21`, `autocfg1.5.1`, `bit-set0.8.0`, `bit-vec0.8.0`, `bitflags2.13.2`, `borrow-or-share0.2.4`, `bytecount0.6.9`, `data-encoding2.11.1`, `displaydoc0.2.7`, `email_address0.2.9`, `equivalent1.0.2`, `fancy-regex0.18.0`, `fluent-uri0.4.1`, `foldhash0.2.0`, `fraction0.15.4`, `getrandom0.3.4`, `hashbrown0.16.1`, `icu_collections2.3.0`, `icu_locale_core2.3.0`, `icu_normalizer2.3.0`, `icu_normalizer_data2.3.0`, `icu_properties2.3.0`, `icu_properties_data2.3.0`, `icu_provider2.3.1`, `idna1.1.0`, `idna_adapter1.2.2`, `js-sys0.3.106`, `jsonschema0.46.8`, `lazy_static1.5.1`, `litemap0.8.3`, `lock_api0.4.14`, `micromap0.3.0`, `num0.4.3`, `num-bigint0.4.8`, `num-cmp0.1.0`, `num-complex0.4.6`, `num-integer0.1.47`, `num-iter0.1.46`, `num-rational0.4.2`, `num-traits0.2.19`, `outref0.5.2`, `parking_lot0.12.5`, `parking_lot_core0.9.12`, `percent-encoding2.3.2`, `potential_utf0.1.6`, `r-efi5.3.0`, `redox_syscall0.5.18`, `ref-cast1.0.27`, `ref-cast-impl1.0.27`, `referencing0.46.8`, `regex1.13.1`, `regex-automata0.4.18`, `regex-syntax0.8.11`, `scopeguard1.2.0`, `smallvec1.16.2`, `stable_deref_trait1.2.1`, `synstructure0.14.0`, `tinystr0.8.4`, `unicode-general-category1.1.0`, `utf8_iter1.0.4`, `uuid-simd0.8.0`, `vsimd0.8.0`, `wasip2 1.0.4+wasi-0.2.12`, `wasm-bindgen0.2.129`, `wasm-bindgen-macro0.2.129`, `wasm-bindgen-macro-support0.2.129`, `wasm-bindgen-shared0.2.129`, `windows-link0.2.1`, `wit-bindgen0.57.1`, `writeable0.6.4`, `yoke0.8.3`, `yoke-derive0.8.4`, `zerofrom0.1.8`, `zerofrom-derive0.1.8`, `zerotrie0.2.5`, `zerovec0.11.8`, `zerovec-derive0.11.6`.

Of these,34 package records exactly match the qualified reference lock;42 added name/version/source identities are absent there. The remaining three identities exist there with different dependency qualification/version spelling. New schema selection satisfies the permissive manifest but is not automatically covered by prior0.46.1 execution.

## 4. Test behavior and edge cases

The existing20CLI tests remain unchanged and unexecuted on this graph. Prior BEFORE review traced all five subprocess integration tests and relevant unit assertions. Specifically:

- cli.rs:885 `matching_registry_does_not_bypass_native_export_verification` supplies an invalid registry-only archive and fails before an actual generic record reaches the native schema.
- cli.rs:913 `matching_registry_does_not_bypass_manifest_signature_failure` tampers fixture001 manifest signature; it does not reach schema validation.
- tests/verify_bundle.rs:120,165 verify fixture001 and registry equality/foreign refusal; no test constructs native `wos.provenance.recorded` records with the owning schema's acceptance/refusal variants.
- Prior owning native tests, separately retained, cover106 noncanonical kinds, timestamp formats, taskFailed/expired, raw field preservation, strict decoder and invalid schemas; they ran with the qualified0.46.1 dependency graph. Running only this CLI package does not run dependency crate unit tests.

Thus passing20tests would qualify CLI wiring/pin/refusal behavior but would not close the changed native schema implementation's positive/negative acceptance gap. No runtime defect is inferred from semver patch movement; the concrete issue is evidence coverage. Small remedy: retain this graph and add focused shared-helper and owning adapter tests under the same frozen versions/features, or make an owner-authorized Cargo-produced successor that preserves prior qualified schema/behavior-critical transitive selections where compatible. Pinning just the top-level schema version while allowing validation dependencies to change still requires explaining/qualifying remaining behavior changes. No full638-suite repeat is demanded by this finding.

## 5. Findings

FINDING1:

- Severity: BLOCKER to the proposed qualification progression; Category: test-coverage.
- Location: CLI lock:630,908; shared helper:70–78; CLI tests:885,913; integration tests:120,165.
- Description: The proposed twenty-test-only qualification reuses owning schema evidence from a different implementation graph. Current metadata selects jsonschema/referencing0.46.8 and changed regex/format dependencies; no planned test exercises the strict native schema behavior on this graph.
- Evidence chain: permissive events manifest→new resolver-selected validator→behavior-critical schema `build/validate`→CLI tests do not invoke that path with native records→prior qualified graph cannot establish current acceptance parity.
- Smallest remedy: amend the bounded qualification plan with focused native helper/adapter tests on this exact graph, or preserve the qualified behavior-critical dependency closure in a separately Cargo-produced, frozen and reviewed lock successor. Retain all setup evidence; no hand-merge or broad production change.

OBSERVATION2 — graph correctness. Exact delta, cached archive checksums, local identities, features and edges are internally consistent. Existing js-sys/wasm-bindgen shifts are a coupled version-family change with target-specific provenance; static review does not establish host or WebAssembly execution. No separate graph corruption finding.

## 6. Conclusion

VERDICT: REQUEST CHANGES before tests/build progression under the current qualification plan.

- Metadata setup successfully admits a coherent full graph and repairs the missing dependency edge; that limited claim is supported.
- Coverage: ADEQUATE for static identity/graph review; INSUFFICIENT for carrying forward prior strict native-schema qualification with only20CLI tests.
- Confidence: HIGH in the graph and concrete coverage mismatch; no claim of a jsonschema bug or guaranteed pin-back resolution.
- No eligible binary, actual D1 archive verification, complete D1, live deployment or adoption is approved. Root must choose and authorize the narrow remedy, freeze/review its successor and retain locked admission/test/build results.

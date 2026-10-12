# Final CLI pinback result: focused source and graph review

VERDICT: APPROVE the retained pinback result and the proposed narrow qualification path below. Residual validation-dependency drift still needs behavior evidence on the actual CLI feature graph. This is not eligible-binary or actual D1 approval.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-10. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`; relevant Rust guidance retained from preceding reviews. Static retained artifacts/source/documentation inspection only; no Cargo, metadata rerun, native/test/build, runner or HTTP execution. Only this report was written.

## 1. Summary and exact scope

Candidate `C`: `/private/tmp/integrity-final-cli-composition-v1-20261010`; attempt2 `A`: `C/setup/pinback-attempt2`. Independently recomputed:

| Input | SHA-256 |
| --- | --- |
| `A/receipt.json` | `c75a4b4eb882c168c882310360432f4d32622ba5778daf98c3693475c8a1c376` |
| `A/03.stdout` complete metadata | `7e1e7ad86ab95114505343c62ab9329fbf04a6f27de0b37ee1bfc94ab974de14` |
| `A/graph-delta.json`, refined review input | `510058c0913958b583fcf4fab5faf16ed867a34a61ee9be52fa71ea7d406ae1f` |
| `A/cargo-lock.after` and current CLI lock | `08752bd38d551e765565a938765976cf341509bc5cc59b93cd25827695cfab1b` |

The initial graph-delta hash in the assignment was superseded before review; this certificate covers the refined file with `presentInOriginalCliLock` distinctions. Receipt records two targeted pin commands and full metadata exit0/reaped/groupClear, the already-restored fancy-regex skip, wasm disabled, elapsed1.77s, and graph review pending. Source rehash against attempt1 frozen pins finds only the standalone CLI lock changed; production sources/manifests/helper/schema remain unchanged.

Exploration hypotheses: H1, pinback may refresh unrelated existing packages, refuted by three replacement identities only. H2,68 residual differences may all be newly introduced, refuted by original CLI lock comparison. H3, dependency package tests necessarily fail nonmember selection, refined: Cargo permits explicit package selection, but nonmembers needing dev-dependencies are refused; these two packages have none. H4, dependency-only selection proves CLI feature context, refined: select CLI root jointly and compare actual compiler artifacts.

## 2. Function and evidence trace

| Function / operation | Evidence location | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| Default pinback command sequence | `C/setup/run_pinback.py:70–90`; A receipt stages | attempt1 lock → exact downgraded schema/reference selections | jsonschema0.46.8→0.46.1 and referencing0.46.8→0.46.1; fancy-regex already0.17.0 skips under sole desired version rule. |
| Cleanup/result | runner:112–139; A receipt | commands → retained lock/log/group status | Owner records success/leader reaping/group clearance; no tests/build; this audit does not replay cleanup. |
| Complete graph capture | `A/03.stdout`,158packages/nodes | successor lock → full dependency graph | All local manifests internal; schemas/helpers actual dependency identities retained. |
| Shared schema use | `C/work-spec/crates/wos-events/src/native_provenance.rs:70–78` | raw schema/JSON → validation result | Maintained options/build/validate path remains behavior-critical; changed transitive format/regex implementations require evidence. |
| Adapter/helper integration | `C/trellis/crates/trellis-verify-wos/src/native_provenance.rs:10–35` | actual generic event bytes → owning constructor/findings | Unchanged maintained helper call; no custom verifier. |
| Helper tests | `C/work-spec/crates/wos-events/src/native_provenance/tests.rs:18–171` | original/malformed JSON and CBOR → assertions | Seven actual registry/parity/preservation/expiry/schema/numeric-depth/duplicate/tag tests, previously reviewed in full. |
| Adapter tests | `C/trellis/crates/trellis-verify-wos/src/native_provenance.rs:98–282` | actual validator/helper → findings/verdict | Six original-preservation, missing/malformed/canonical-bypass/strict-CBOR/mixed-event tests, previously reviewed in full. |

## 3. Graph invariants and residual drift

Independently compared attempt1/attempt2 locks: three additions (`jsonschema0.46.1`, `referencing0.46.1`, `fancy-regex0.17.0`), corresponding three removals, zero other changed package records/dependency arrays. All three newly selected cached crate archives match lock checksums. Metadata still has158packages/158nodes, no external local paths, and restored features jsonschema[], referencing[default], fancy-regex[default,perf,std,unicode,variable-lookbehinds]. Same-name/version nodes retain their attempt1 feature selections. Current CLI lock exactly equals retained attempt2 copy.

Against the broader historical qualified Trellis lock, the refined report lists68 differing version identities. Independent original CLI lock comparison confirms29 were already present in the CLI baseline and39 are newly introduced by schema closure/wasm-family selection. Do not label all68 a new upgrade. The39 include regex/ICU/format-related selections and platform-specific dependencies; full graph reachability includes conditional target edges, not proof each is active on the host. The prior lock-only0.46.8 coverage concern is partially remedied by restoring the three named versions, but residual validation dependency differences remain unexecuted.

A focused behavior run on this graph is a proportional alternative to repeatedly forcing all historical patch versions. Existing CLI tests alone still do not cover the native schema acceptance/refusal path. No full638-suite repeat or production change is necessary for this bounded remedy.

## 4. Cargo selection and prepared qualification path

Read local installed Cargo documentation at `/Users/mikewolfd/.rustup/toolchains/stable-aarch64-apple-darwin/share/doc/rust/html/cargo/commands/cargo-test.html:242–263`: `--package` tests specified packages; `--workspace` selects members. Documentation alone does not spell out the nonmember special case. Static inspection of the installed Cargo executable finds the specific refusal text for a package requiring dev-dependencies and not being a workspace member. Root also supplied the relevant Cargo0.91 primary-source condition at `src/cargo/ops/cargo_compile/mod.rs`; this reviewer did not browse/fetch that source. These observations support the selection path, but actual toolchain execution must confirm it.

Actual metadata states the CLI is the only workspace member. Nevertheless both `wos-events` and `trellis-verify-wos` are resolved local packages with a test-enabled library target and zero dev-dependencies; their complete manifests confirm this. Their maintained tests use normal dependencies. There is therefore no identified nonmember/dev-dependency refusal for their explicit selection. Do not claim a test ran merely because dependency code compiled.

Recommended owner-granted command after frozen-source/lock admission:

```text
cargo test --offline --locked -j1 --manifest-path <C>/integrity-stack/crates/integrity-verify-cli/Cargo.toml -p integrity-verify-cli -p wos-events -p trellis-verify-wos --message-format=json native_provenance::tests
```

Keep the CLI root jointly selected to retain its requested features/dev context; omit `--lib` because CLI has a binary target. Expect the seven named helper tests and six named adapter tests. CLI targets will be filtered by this name; zero CLI matches are not CLI behavior coverage. Refusal, zero helper/adapter matches or unexpected package/feature identity must stop, not silently qualify the graph.

Capture compiler-artifact packageID, features, target and profile for helper, schema/reference/regex and adapter, then compare relevant feature/package identities against the subsequent unchanged20CLI tests and retained CLI binary build. Target/profile distinctions for unit-test versus normal library compilation are expected; behavioral dependency selection/feature requests must be explained. Cargo JSON diagnostic/artifact lines coexist with libtest text, so preserve raw stdout/stderr and extract structured artifact lines without treating the entire stream as one JSON document. A full locked metadata receipt must also confirm the same lock/source/graph before progression. Freeze actual artifacts and fixture001 before/after hashes.

If the actual Cargo version refuses nonmember tests despite these static conditions, retain that refusal. A concrete fallback requires a separately reviewed private test workspace/manifest arrangement that selects the owning packages and reconciles the same dependency/features; it would need new graph proof. Do not switch silently to owning workspaces with their historical locks and call that the CLI graph. No custom verifier or production edit is recommended.

## 5. Findings

OBSERVATION1 — coverage, helper:70–78; CLI tests:885,913. Pinback restores qualified schema/reference/fancy-regex identities but leaves39 new version selections relative to original CLI baseline. Approve the focused7+6 maintained tests as the narrow next proof, not20CLI-only qualification. The prior coverage hold remains until their exact named results and artifact/graph continuity are reviewed.

OBSERVATION2 — execution readiness. Metadata/package selection supports the proposed joint command; it is not proof of test/build success. Root's grant, bounded operator, full locked admission and source/lock/artifact receipts remain required. No fallback or broad historical patch duplication is authorized here.

## 6. Conclusion

VERDICT: APPROVE pinback result and bounded next qualification path; actual qualification remains pending.

- Retained pinback is coherent, preserves attempt1 evidence, restores the three intended dependencies and changes only the private lock.
- Coverage: ADEQUATE static result/selection review; actual13 maintained test results plus20CLI tests/build remain missing.
- Confidence: HIGH in retained hashes, delta distinctions and package metadata; MEDIUM in nonmember command execution until the owner toolchain confirms it.
- No eligible executable, actual D1 archive verification, complete D1, portability, deployment or adoption claim follows.

## Narrow static acknowledgment of staged plan v4

Read phaseA, phaseB and operator controls of final frozen `final-cli-composition-plan-v4.json`; independently verified SHA-256 `69c3bc77b0b9e1c7a6bb15294a83a696834407015345f7a112c9d09b7a63d6c3`. The final refinement removes the mutable architecture-certificate entry from the plan input list; commands and controls remain as reviewed. Certificates are pinned by a separate handoff receipt. APPROVE the exact next phaseA commands as a qualification plan: full offline locked metadata on the standalone CLI manifest, then the joint CLI-root/helper/adapter filtered command above with `--message-format=json` and no `--lib`. This matches the recommended actual-CLI-feature-context approach. Actual installed Cargo identity and command feasibility remain retained-result gates.

PhaseA requires the13 named maintained tests,158-node graph/lock equality, compiler artifacts and unchanged source/fixture pins; CLI filtered-zero is explicitly excluded from coverage. PhaseB requires separate grant after independent result acknowledgment and selects the existing20CLI tests, then the exact binary build, retaining JSON artifacts for cross-phase identity/features comparison. The parent owns deadlines/log bounds/cleanup/target choice. No source/lock mutation or fallback workspace is permitted by the plan. No actual test/build or eligible-binary approval is implied by this static acknowledgment.

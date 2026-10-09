# Offline export trust: lock reconciliation code review

VERDICT: APPROVE the mechanical lockfile reconciliation. This static disposition does not qualify compilation or tests.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. Baseline HEAD: `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Scope: the additional `rand_core` dependency edge in `crates/integrity-verify-cli/Cargo.lock`, compared with the prior AFTER packet, and its owning current sibling manifest. Only this new certificate was written; previous certificates and all implementation files remain unchanged.

Procedure: applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, with relevant application/universal guidance already read in this review session. Read the exact lockfile diff and the entire owning `../stack-common/crates/stack-common-typeid/Cargo.toml`; traced the incoming dependency through current `wos-events` and the CLI lock graph. No builds, tests, Cargo commands or live calls executed by this reviewer.

## 1. Patch summary

The prior reviewed CLI lockfile had SHA-256 `c3549e67ad697f4cd03f9752a53d308b88ec469b5abf8c60eebd85d880ecec66`. The reconciled file has SHA-256 `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e`. Against HEAD the diff contains exactly two added dependency edges: the previously approved CLI → `integrity-cbor` edge and the newly reviewed `stack-common-typeid` → `rand_core` edge. No package versions, checksums, sources or Rust implementation change in this amendment.

The owning manifest already declares `rand_core = { version = "0.6", features = ["getrandom", "std"] }` (`../stack-common/crates/stack-common-typeid/Cargo.toml:8`). The lockfile already contains `rand_core` version `0.6.4` (`crates/integrity-verify-cli/Cargo.lock:420–428`). The added edge at `:550` therefore reconciles existing package declarations rather than introducing an unrelated dependency.

Exploration hypothesis H1: the missing edge is required by the current owning manifest, not by a new CLI source change. Confirmed by the manifest declaration and exact two-edge HEAD diff. H2: reconciliation changes another package resolution. Refuted by the diff: all existing version/source/checksum entries remain unchanged. No unresolved source question remains for this one-line amendment.

## 2. Function / dependency trace

No function is changed. The relevant dependency graph replaces the function trace for this lock-only amendment.

| Node / declaration | File:line | Input → output | Verified behavior |
| --- | --- | --- | --- |
| CLI package | `crates/integrity-verify-cli/Cargo.lock:333–345` | CLI dependencies → WOS verifier | Existing path includes `trellis-verify-wos`; prior new `integrity-cbor` edge retained. |
| WOS verifier | same lockfile `:631–638` | adapter → `wos-events` | Existing dependency reaches the owning event crate. |
| `wos-events` manifest | sibling `work-spec/crates/wos-events/Cargo.toml:16` | event crate → `stack-common-typeid` | Explicit maintained sibling path dependency. |
| `stack-common-typeid` manifest | sibling `stack-common/crates/stack-common-typeid/Cargo.toml:8` | type-ID crate → `rand_core` 0.6 | Existing declaration includes getrandom/std features. |
| Reconciled lock entry | `crates/integrity-verify-cli/Cargo.lock:547–552` | type-ID package → locked dependencies | Adds the previously absent `rand_core` edge alongside existing `uuid`. |
| Locked `rand_core` | same lockfile `:420–428` | constraint → version 0.6.4 | Existing compatible version/source/checksum and getrandom dependency retained. |

## 3. Data flow and invariants

This amendment changes dependency-graph metadata only. Cargo consumes the existing manifest constraint and the lockfile edge to resolve the already locked `rand_core` package. It introduces no new CLI argument, trust decision, digest input, archive mutation, private material or runtime result.

The four other reviewed code/test/documentation files were rehashed and exactly match the prior AFTER certificate: Cargo.toml `a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a`; cli.rs `ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9`; verify_bundle.rs `addf2343978168bb92439332db0af34ae0dbcfb19de6908580a854aa19bc2ea8`; offline-export-registry-pin.md `1ee7d1511a3b4d8cb2109a92df621d78c99ce575db6b2f87d450107d945548c2`. The prior source review and its trust limitations therefore still apply.

## 4. Test behavior and edge cases

No test assertion changes. The prepared parser, ZIP selection, mismatch, native-fixture and manifest-tamper assertions documented in `docs/offline-export-trust-after-code.md` remain unexecuted. The lock reconciliation removes an observed graph inconsistency; source inspection alone does not establish that compilation or tests will pass.

Owner-reported execution, not independently executed here: the granted native test attempt returned exit 101 because the lockfile needed updating and stopped before compilation; no retry occurred. Full offline metadata subsequently encountered unavailable non-host `js-sys` without downloading it. Host-filtered `aarch64-apple-darwin` metadata with `--offline --locked` reportedly returned exit 0. That result is dependency metadata evidence for that host only, not a test, build, cross-target or product qualification result. This review does not authorize a native retry or interfere with another owner's execution window.

## 5. Findings

**F1 — OBSERVATION / maintainability — `crates/integrity-verify-cli/Cargo.lock:550`.** The added dependency edge matches the current owning manifest (`stack-common-typeid/Cargo.toml:8`) and an already locked compatible package (`Cargo.lock:421–428`). Disposition: APPROVE; no additional code change needed.

**F2 — OBSERVATION / qualification — prior prepared Rust tests.** The interrupted attempt did not compile or run tests. The metadata receipt cannot replace that evidence. Disposition: preserve the pending compilation/test limitation; no execution approval is implied.

## 6. Conclusion

VERDICT: APPROVE.

The amendment correctly reconciles the current maintained manifest with the CLI lock graph while preserving the reviewed implementation. Coverage of the one-line metadata change: ADEQUATE for static review. Confidence: HIGH in dependency consistency; compilation and runtime qualification remain pending.

Exact pins:

```text
56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e  crates/integrity-verify-cli/Cargo.lock
f3a86cfb050d482b45610a0919e56feee18d1bcdf9669c2c4113a269d1e25692  ../stack-common/crates/stack-common-typeid/Cargo.toml
c647faf0747efb065bb9bbcb449d939393528315edfc947211e872607b7e6add  git diff --binary HEAD -- crates/integrity-verify-cli/Cargo.lock
```

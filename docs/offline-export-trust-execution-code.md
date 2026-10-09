# Offline export trust: execution evidence code audit

VERDICT: APPROVE the scoped local commit. The retained owner execution qualifies the reviewed native CLI tests: 15 unit tests and 5 integration tests passed. It does not qualify an actual D1 archive, deployment, installed service binary, agency identity or independently sourced production registry provenance.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium. Date: 2026-10-09. This is an evidence addendum to `offline-export-trust-after-code.md` and `offline-export-trust-lock-reconciliation-code.md`; it preserves those historical certificates. Only this certificate was written. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` with relevant guidance from the preceding source reviews. No native command, Cargo invocation, test rerun, live call or production edit was performed by this reviewer.

## 1. Patch and evidence summary

The audited implementation remains the exact registry-pin CLI and reconciled lockfile previously approved against HEAD `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Current hashes of Cargo.toml, Cargo.lock, cli.rs, verify_bundle.rs, registry-pin documentation and owning stack-common-typeid manifest match the reviewed packet and successful receipt. No intervening source change was found in those files.

Read in full: the successful receipt and matching log, frozen v2 handoff, and runner. Also read the original lock-refusal log and verified the original receipt hash. Retained evidence lives under the parent workspace directory `thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/offline-export-registry-pin/`.

Hypothesis H1: the successful log belongs to the exact reviewed v2 source packet. Confirmed by independently recomputed receipt/log/manifest/runner hashes, receipt source pins and current implementation hashes. H2: the prior exit 101 represented a behavioral test failure. Refuted: its log contains only the `--locked` admission refusal. H3: the retry qualifies actual operational export trust. Refuted by test inputs, command scope and receipt limits.

## 2. Function and evidence trace

| Function / stage | Source | Input → output | Audited behavior |
| --- | --- | --- | --- |
| Frozen packet validation | `docs/offline-export-registry-pin-runner.py:24–27` | fixed v2 digest + declared file pins → assertions | Requires exact v2 manifest and all declared artifact hashes before spawning Cargo. |
| `visit` | same file `:32–60` | CLI manifest → source-path set | Traverses direct path dependencies, includes discovered source files and enclosing manifests/locks. This is the runner's recorded source set, not a claim of arbitrary filesystem immutability. |
| Test process creation | same file `:65–82` | offline/locked/j1 CLI cargo test + isolated target → child process | Uses named CLI manifest and target directory, starts owned session, enforces 600-second cap. |
| Owned-group cleanup | same file `:88–110` | child/PGID → reaped child and remaining-group evidence | Polls/waits leader; checks owned group; records cleanup errors and final membership. |
| Receipt creation | same file `:111–127` | before/after pins, child status, log → JSON receipt | Records exact exit code, source comparisons, preserved-artifact comparison and log SHA-256. |
| CLI verification path | `crates/integrity-verify-cli/src/cli.rs:293–335` | ZIP and pin → report/error | Previously traced same-buffer pin check followed by unchanged maintained WOS checks; executed tests exercise success and refusal branches. |
| Unit execution | successful log `:58–77` | compiled CLI test harness → results | All 15 named unit tests passed, zero ignored/filtered. |
| Integration execution | successful log `:79–88` | native binary subprocess tests → results | All 5 named integration tests passed, zero ignored/filtered. |

## 3. Data flow and invariants

The v2 manifest is an immutable pre-run packet, correctly retaining its then-current `testsExecuted=false` and pending status. The later execution receipt supplies the newer result; do not rewrite the frozen packet to manufacture prior knowledge. Its hash is explicitly required by the runner and appears in the receipt source pins.

The successful receipt records `cargo test --offline --locked -j 1 --manifest-path <CLI Cargo.toml>`, target `/tmp/formspec-exact-source-composition-target-20261009-v1`, exit 0, no timeout/error, 22.348 seconds elapsed, PGID 90828, empty remaining group, no cleanup errors and cleanup confirmed. The log independently records actual compilation and execution, rather than only metadata resolution. Reusing a cache does not weaken the exact-source test result when Cargo and the source pins agree; this audit makes no clean-build or performance claim.

The receipt records unchanged source pins and no changed-source entries. Its preserved-artifact comparison is true; the sole recorded pre-existing artifact is `formspec-server` with digest `77f0983f6a82cf482d9265c663d39c35a8c90d19d537bd5637244e5749f90b83`. The runner's named preservation set includes the separate installed CLI path and service targets (`:63–64,112,121`), but the installed CLI path was absent from the baseline map. This is not evidence that all running binaries were pinned. These are bounded artifact checks and historical process evidence, not a fresh service-state survey. No installed-binary adoption or service deployment is established by the test command.

## 4. Test behavior and edge cases

The successful log names the reviewed assertions: strict/duplicate pin arguments, raw known-vector match and mismatch, missing/duplicate/nested/malformed members, matched pin with invalid native export, and matched pin with manifest signature failure (`:68–72`). These are the source tests analyzed at cli.rs:803,841,852,885,913 in the prior AFTER certificate. Their observed PASS results now replace the earlier pending-execution limitation for this source packet.

The integration log includes existing generic command checks, unpinned native fixture success and selected/foreign registry digest behavior (`:82–86`). In source, the latter requires successful matched-pin JSON evidence or failed exit with empty stdout and mismatch stderr (`tests/verify_bundle.rs:150–192`). Thus the run exercises genuine maintained archive verification and CLI subprocess behavior over synthetic native fixtures; it is not merely a mocked renderer test.

Fixture provenance limitation: the runner's recorded dependency source set does not include the external `trellis/fixtures/vectors/export/001-two-event-chain/expected-export.zip` opened by the tests. Consequently `sourcesUnchanged` is not a full-fixture pre/post assertion. Its current audit-time SHA-256 is `e0d6ef2bdc0756a5284e3cb66beb3d79c582b1f5e0231debbe44e41a162ba1fa`; that read is not a retroactive execution-time capture. The passing tests still establish their actual assertion behavior over the fixture they loaded, including the fixed expected registry pin. They do not establish immutable full-archive identity across the run. Future runner capture of explicit external fixture paths would close that provenance gap; it is not required to accept this bounded CLI source/test result, but would be required for a claim that a specific immutable original ZIP was executed.

The newly built target CLI currently hashes to `b9803346f60a8b308e40500962576313f4f5a9012ce951d19234252d9854c368`. This is an audit-time artifact observation, not an installed-binary or adoption claim.

Unchanged minor coverage gaps remain: dedicated text/both pin-output assertions, null observed digest when unselected, non-ASCII syntax and a nested decoy alongside a valid exact registry member. No dependency-crate test suites, complete workspace suite, cross-target build or actual D1 archive verification ran under this command. Those gaps do not block this bounded CLI commit.

The original attempt remains retained as exit 101, lock admission refusal before compilation. It is not counted among passing or failing behavioral tests and is not erased by the successful retry.

## 5. Findings

**F1 — OBSERVATION / qualification — successful log:57–88.** Native compilation and the exact reviewed CLI tests now have retained PASS evidence. Receipt exit/status, source pins and log hash agree. Disposition: the previous native CLI compilation/test limitation is resolved for this packet and host execution only.

**F2 — OBSERVATION / evidence boundary — v2 manifest status and receipt `limits`.** The manifest is historical pre-run evidence; the new receipt is additive execution proof. Neither qualifies actual D1 scope, installed-service activation, exporter identity, freshness or independent production pin provenance. Disposition: preserve these boundaries in the commit summary and operational handoff.

**F3 — OBSERVATION / provenance — runner `visit` at :32–60 and test fixture path at `tests/verify_bundle.rs:22`.** The external fixture ZIP is outside the recorded pre/post source set. Disposition: retain the behavioral PASS result but make no full-ZIP pre/post identity claim. Explicit fixture-path capture is a nonblocking runner improvement for future immutable-fixture qualification.

No blocking defect or evidence inconsistency found.

## 6. Conclusion and exact pins

VERDICT: APPROVE for the scoped local commit. Coverage: ADEQUATE for the bounded implementation and native CLI suite. Confidence: HIGH in the retained execution/source linkage. The owner executed the tests; this reviewer independently audited source, assertions and retained evidence without rerunning them. No further execution authorization is implied.

```text
d791774ba358ec4d7ab4628e687a64a6a5e9944226067c5d7d5b6eb607eff345  native-cli-tests-20261009T150655Z.json
841658cf23d6d9e261d9cbbc9fd828ec3a4c6547e203ae59a274a20eaae00467  native-cli-tests-20261009T150655Z.log
bda2e1408e1ec670410cd2ea07f7323941681cffbe51db3e29a1933d204159d8  native-cli-tests-20261009T150413Z.json
078c2774cc811f28721df3d32a9bd4e5c66a6a5808b583b3dd665a98c37eea77  docs/offline-export-registry-pin-handoff-v2.json
d691c559cee6d0bf213dc835a1b51db13f97dd37ca6b6e37d3f602b4e4a04f04  docs/offline-export-registry-pin-runner.py
a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a  crates/integrity-verify-cli/Cargo.toml
56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e  crates/integrity-verify-cli/Cargo.lock
ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9  crates/integrity-verify-cli/src/cli.rs
addf2343978168bb92439332db0af34ae0dbcfb19de6908580a854aa19bc2ea8  crates/integrity-verify-cli/tests/verify_bundle.rs
1ee7d1511a3b4d8cb2109a92df621d78c99ce575db6b2f87d450107d945548c2  docs/offline-export-registry-pin.md
f3a86cfb050d482b45610a0919e56feee18d1bcdf9669c2c4113a269d1e25692  ../stack-common/crates/stack-common-typeid/Cargo.toml
```

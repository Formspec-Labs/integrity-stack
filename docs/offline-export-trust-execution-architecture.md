# Offline export registry pin — execution architecture addendum

**VERDICT: APPROVE the bounded synthetic CLI qualification.** The retained owner execution log records 15 unit tests and 5 integration tests passing, with formal Cargo exit0. The reviewed source and dependency pins match the execution packet. This closes the earlier unexecuted-test limitation for this CLI change. It does not establish an actual D1 archive, independent registry custody, agency identity, registry freshness, disclosure authority, installation or shared adoption.

## 1. Artifact summary and review method

Independent reviewer: `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, with runtime model identity not independently exposed. Read **in full** and applied `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` for this addendum. All six phases appear below. This review read retained source, receipts and logs and recomputed file hashes; it did not execute Cargo, the runner, tests, a native binary, live calls, services or key operations. Only this certificate was written; other owners' work was preserved.

Category: proof infrastructure. The operator-facing outcome is evidence that the optional externally selected registry snapshot gate works with the existing native export verifier. The execution artifact is the owner-authorized v2 retry using `cargo test --offline --locked -j 1 --manifest-path /Users/mikewolfd/Work/formspec-stack/integrity-stack/crates/integrity-verify-cli/Cargo.toml` and retained target `/tmp/formspec-exact-source-composition-target-20261009-v1`. The receipt records exit0, elapsed22.348071749991504seconds, no timeout/error, process group90828 empty and cleanup confirmed. The runner waits/reaps its owned leader and records cleanup at `docs/offline-export-registry-pin-runner.py:78–118`. These are retained execution observations, not a fresh process-state audit.

Evidence paths below are relative to `/Users/mikewolfd/Work/formspec-stack`; `docs/` and `crates/` references are within `integrity-stack` unless stated otherwise. Receipt/log prefix is `thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/offline-export-registry-pin/`.

| Exact artifact | SHA-256 |
| --- | --- |
| Passing receipt `native-cli-tests-20261009T150655Z.json` | `d791774ba358ec4d7ab4628e687a64a6a5e9944226067c5d7d5b6eb607eff345` |
| Passing log `native-cli-tests-20261009T150655Z.log` | `841658cf23d6d9e261d9cbbc9fd828ec3a4c6547e203ae59a274a20eaae00467` |
| First refusal receipt `native-cli-tests-20261009T150413Z.json` | `bda2e1408e1ec670410cd2ea07f7323941681cffbe51db3e29a1933d204159d8` |
| First refusal log `native-cli-tests-20261009T150413Z.log` | `73c362bc51b6729c07c4d9a96c42e49ac46463e1da912b9717715225cbcdfdce` |
| `docs/offline-export-registry-pin-handoff-v2.json` | `078c2774cc811f28721df3d32a9bd4e5c66a6a5808b583b3dd665a98c37eea77` |
| `docs/offline-export-registry-pin-runner.py` | `d691c559cee6d0bf213dc835a1b51db13f97dd37ca6b6e37d3f602b4e4a04f04` |
| `crates/integrity-verify-cli/Cargo.lock` | `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e` |
| `crates/integrity-verify-cli/Cargo.toml` | `a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a` |
| `crates/integrity-verify-cli/src/cli.rs` | `ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9` |
| `crates/integrity-verify-cli/tests/verify_bundle.rs` | `addf2343978168bb92439332db0af34ae0dbcfb19de6908580a854aa19bc2ea8` |
| `docs/offline-export-registry-pin-qualification.md` | `cedcbc010fe94280aae6b4406b1f7c57cabfdf09f547b464fa0dac9ab94df1bb` |

The successful receipt has101 source pins. All101 current files independently match those recorded hashes; the receipt also records their before/after equality and no changed pins. Its preserved-artifact map contains exactly one file, the retained `formspec-server`, SHA-256 `77f0983f6a82cf482d9265c663d39c35a8c90d19d537bd5637244e5749f90b83`; current readback independently matches. This is not a claim that all binary artifacts were pinned.

## 2. Lineage and relationships

| Prior artifact | Relation | Evidence |
| --- | --- | --- |
| `docs/offline-export-trust-before-architecture.md` | Selected CLI-only snapshot gate; broader selected-exporter API deferred | Decision and invariants sections |
| `docs/offline-export-trust-after-architecture.md` | Static source approval; native tests then unexecuted | Findings/verdict; SHA `0aab473418ceb267712bdb88202b588af70962b3236012ddd60f4ca9417ea4f2` |
| `docs/offline-export-trust-lock-reconciliation-architecture.md` | Approved existing manifest/lock reconciliation before retry | Lineage and verdict; SHA `ea175da3e0677e8d499793238012c035c260d63dda40573cbc6265a3bce4bec6` |
| `trellis/specs/trellis-core.md:1738–1747` | Parent native verifier uses embedded signing registry | Core19 registry verification requirements |
| `trellis/specs/trellis-core.md:2486–2530` | Limits legal/trust conclusions | Native trust limitations |
| First attempt receipt and log | Retained failed attempt, not erased by success | Exit101; stale lock refusal at log:1–2; cleanupConfirmed=true |

| Component/seam | Owner | Dependency / consumer | Declared boundary |
| --- | --- | --- | --- |
| Exact-byte registry gate | Integrity CLI | Maintained ZIP reader and hash; operator selects digest | `src/cli.rs:293–370` |
| Native archive verification | Integrity/Trellis/WOS maintainers | CLI delegates unchanged verifier | `src/cli.rs:302,328–335`; `trellis/crates/trellis-verify-wos/src/lib.rs:46–47` |
| Bounded execution receipts | Root execution owner | Reviewer consumes retained output | Runner:24–27,62–67,111–127 |
| Real archive/custody qualification | Actual record and registry owners | Future operator verification | Usage/qualification documents' limits; not supplied by synthetic fixtures |

Hypothesis H1(high), the exact reviewed change now has native execution evidence: **CONFIRMED** by matching v2/source pins and passing log:56–88. H2(high), matching a selected registry bypasses native validity checks: **REFUTED** by CLI:301–302,328–335 and passing refusal regressions at log:71–72. H3(high), this proves actual D1 trust/custody: **REFUTED** by receipt `limits`, qualification document and absent actual archive. Enough evidence exists for this bounded addendum; no native rerun is needed or authorized.

## 3. Invariants and commitments

| Invariant | Status | Evidence and failure mode |
| --- | --- | --- |
| Pin check and verifier consume the same owned ZIP bytes | PRESERVED | CLI:294–302. Separate reads would permit input substitution. |
| Pin success cannot bypass native failures | PRESERVED | CLI:328–335; log:71–72. Otherwise equality would masquerade as archive validity. |
| Missing/ambiguous registry and invalid selection refuse | PRESERVED with executed synthetic evidence | CLI:341–369; log:68–70. Otherwise operator selection becomes ambiguous. |
| Legacy invocation remains explicit `not_requested` | PRESERVED | Integration:111–142; log:85. No-pin success must not imply independent trust selection. |
| Reviewed source identities remain bounded and reproducible | RELIED-UPON and corroborated | Receipt101 pins, runner:24–27,62,111–122, independent current hashes. Unpinned inputs remain outside this guarantee. |
| Execution proof remains separate from agency trust and adoption | PRESERVED | Receipt `limits`; qualification document final paragraph. Conflating these would create unsupported authority claims. |

The external fixture ZIP is **not** among the101 runner pre/post source pins. Its post-run SHA `e0d6ef2bdc0756a5284e3cb66beb3d79c582b1f5e0231debbe44e41a162ba1fa` is reported in the qualification document only as post-run readback. It cannot establish before/after fixture immutability. The compiled integration source fixes fixture001's expected registry digest at `tests/verify_bundle.rs:144–147` and exercises fixture001 with a matching digest and fixture005's foreign digest at150–189. It does not execute fixture005's archive. Unit tests supply additional synthetic negative evidence. This limitation does not invalidate the narrower recorded CLI behavior; it prevents expanding that evidence into fully frozen fixture provenance.

## 4. User value

The operator can now rely on executed synthetic evidence for exact snapshot acceptance/refusal, explicit no-pin behavior and continued native verification. The feature remains a thin CLI gate using maintained ZIP/hash/verifier components; this execution addendum adds no API or dependency. It pays down verification uncertainty without claiming runtime speed or resource improvement. The22.35seconds is receipt timing, not a benchmark.

The smaller alternative was static approval alone; that left compilation and executable behavior unqualified. Repeating execution now adds no identified architectural value. A broader exporter-key API remains a different capability with cross-owner changes. This qualification would fail its value test if operators still had to derive the supposedly independent digest from the archive itself or interpreted `matched` as fresh agency authorization.

## 5. Counterfactual and kill criteria

Kill criteria are source/packet hash disagreement, nonzero or incomplete test execution, native verification bypass, or representing these fixtures as an actual D1 record. None occurs in the retained scoped evidence. Removing this addendum leaves the earlier static approval intact but loses the precise execution qualification. Existing logs/receipts supply execution facts; this certificate contributes their bounded architectural interpretation rather than a duplicate verifier. A future reviewer should demand actual archive and independently retained registry provenance for a real operational claim; passing these tests cannot substitute for either.

## 6. Findings and dispositions

- **KEEP — OBSERVATION / intent-vs-shape:** retain the exact exit0 receipt and passing log as synthetic CLI qualification, with the v2/source pins. Evidence: passing log:60–88 and receipt fields.
- **KEEP — OBSERVATION / ownership:** retain the first exit101 lock refusal and lock reconciliation lineage. It remains a failed attempt; the later retry is separately identified.
- **RESHAPE — no required change:** existing qualification prose already states the fixture pre/post limitation and identifies only the preserved server binary. Do not broaden either claim.
- **REVERSE — OBSERVATION / scope:** reject any interpretation of `matched`, these tests or the test-built CLI as agency trust, fresh registry authority, actual D1 coverage or installed/shared adoption. Evidence: parent specification limits and qualification document.
- **DEFER — OBSERVATION / user-value:** real D1 verification requires a genuine authorized native archive, original evidence and independently retained registry provenance. No product fix, native rerun or live operation is authorized by this certificate.

## 7. Verdict

```text
VERDICT: APPROVE — bounded execution qualification/addendum
Intent vs. shape: MATCHES — exact-source synthetic CLI tests recorded.
User-value claim: SUPPORTED — previously unexecuted behavior now tested.
Commitment status: HONORED — native verification and authority boundaries preserved.
Conceptual debt delta: PAYS DOWN — execution uncertainty reduced; no new API.
Sibling subsumption: PARTIAL — receipts hold facts; certificate bounds their meaning.
Confidence: HIGH for retained log/receipt/source consistency; actual D1 and custody unqualified.
```

This is a static audit of retained owner execution, not independent reproduction. No native command, signing, key generation, provider mutation, service operation, browser/authentication action or live archive operation was performed by this reviewer.

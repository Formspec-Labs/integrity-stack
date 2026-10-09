# Native CLI qualification

The optional registry snapshot pin passed 15 unit tests and 5 CLI integration tests on the exact reviewed source. The formal Cargo exit was 0 after 22.35 seconds; the owned leader was reaped and process group90828 was empty. The 101 captured local dependency/source pins remained unchanged. The retained Formspec server binary hash remained unchanged. No services, keys, actual D1 records or shared adoption changed.

The native command was `cargo test --offline --locked -j 1 --manifest-path /Users/mikewolfd/Work/formspec-stack/integrity-stack/crates/integrity-verify-cli/Cargo.toml`, using the existing `/tmp/formspec-exact-source-composition-target-20261009-v1` cache. Cargo validated inputs and compiled the required CLI graph; no duplicate dependency cache was copied or deleted.

The tests cover valid snapshot acceptance, foreign snapshot refusal, legacy invocation with `not_requested`, malformed/duplicate selection, missing/ambiguous/nested registry members, malformed ZIP input, and registry matches that cannot bypass invalid native evidence or a changed manifest signature. The first attempt stopped at lock admission before compilation; its exit101 receipt remains retained. The lock amendment adds an existing `stack-common-typeid` dependency, `rand_core`, and both reviewers approved it.

Evidence:

- Passing receipt: `thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/offline-export-registry-pin/native-cli-tests-20261009T150655Z.json`, SHA-256 `d791774ba358ec4d7ab4628e687a64a6a5e9944226067c5d7d5b6eb607eff345`.
- Passing log SHA-256: `841658cf23d6d9e261d9cbbc9fd828ec3a4c6547e203ae59a274a20eaae00467`.
- Frozen amended packet: `docs/offline-export-registry-pin-handoff-v2.json`, SHA-256 `078c2774cc811f28721df3d32a9bd4e5c66a6a5808b583b3dd665a98c37eea77`.
- Test-built binary: `/tmp/formspec-exact-source-composition-target-20261009-v1/debug/integrity-verify`, SHA-256 `b9803346f60a8b308e40500962576313f4f5a9012ce951d19234252d9854c368`. This identifies a test artifact, not an installed or adopted service binary.
- Fixture001 archive post-run readback SHA-256: `e0d6ef2bdc0756a5284e3cb66beb3d79c582b1f5e0231debbe44e41a162ba1fa`. The external fixture ZIP was not included among the runner's101 pre/post source pins; do not represent that post-run hash as a recorded before/after comparison. Its exact registry digest is fixed by the compiled integration test.

This qualifies synthetic CLI behavior only. It does not qualify actual full D1 history, custody, archive coverage, agency identity, registry freshness or disclosure authority. The remaining real operation requires genuine authorized records, a qualified native archive with original evidence, and independently retained registry provenance before offline verification. The CLI pin establishes equality to that selected snapshot; the existing verifier still decides archive validity.

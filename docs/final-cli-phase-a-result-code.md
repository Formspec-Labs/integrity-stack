# Final CLI Phase A: independent result acknowledgment

VERDICT: APPROVE Phase A acknowledgment and readiness for separately granted Phase B20CLI tests/build. The13 maintained native tests passed on the actual CLI graph/host feature context. No final executable or actual D1 is qualified yet.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-10. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`; source assertions/traces remain from the preceding scoped reviews. This is proportional static retained-result acknowledgment only: no Cargo/native, rerun, test/build or HTTP execution. Only this report was written.

## 1. Scope and pins

Evidence `A`: `/private/tmp/integrity-final-cli-composition-v1-20261010/execution/phase-a-20261010-v1`; candidate `C` is its parent composition root. Independently recomputed:

| Artifact | SHA-256 |
| --- | --- |
| `receipt.json` | `9521ecc5d0a1e5335c7ce60f20986ce957f3e8a66ed8cdb8902610a84d596865` |
| `compiler-artifacts.json` | `ce2a67520d5af4bf50921be6d73981932b08787793e4a8e8388f8893beb962a2` |
| `owning-artifact-comparison.json` | `d4a7b787519e47412a0ff0f3bcd1aae8de76652463e34c1d4841b1243b55c5a0` |
| `host-artifact-comparison.json` | `4922299c58722dd238956cd7c2ba4e6bb415e88353f69deeee961f56af6935d9` |
| `host-feature-explanation.json` | `8035be61f7d6c5c22765f7e39b54d9ea3a004a0056f6b05913bd3806336fd24a` |
| `joint-native-tests.stdout` | `5a60eca30c67864e56838ef68d76ba776f008c9eba72f0d4ec925a166723b7d7` |
| `joint-native-tests.stderr` | `35bbe90ea02be4764983405f85ee6f0507b15c6c289837f142e9ddb23fb26bb6` |
| `locked-metadata.stdout` | `58e0ff66009f4899e080ee7d78d8f5d45fd9b3a0be4d6a80f0d8abd756245b5e` |

Receipt binds reviewed plan `69c3bc77…` and successor source pins `3e704e02…`. All8032 current source hashes match those successor pins; CLI lock stays `08752bd38d551e765565a938765976cf341509bc5cc59b93cd25827695cfab1b`. Independently compared locked metadata's complete packages/resolve to retained pinback metadata: exact equality,158packages/158nodes. Rehashed all retained stage logs against receipt: zero mismatch.

## 2. Trace and actual execution evidence

| Stage / behavior | Evidence | Verified result |
| --- | --- | --- |
| Full locked admission | receipt locked-metadata stage / retained stdout | Exact `cargo metadata --offline --locked --format-version1 --manifest-path CLI`; exit0; same complete graph, lock unchanged. |
| Joint root/helper/adapter tests | receipt joint-native-tests argv / stdout:181–211 | Exact reviewed three-package filtered command, no `--lib`; exit0; seven helper plus six adapter named results. |
| Owning strict path | C helper:70–78; adapter:10–35 | Unchanged maintained schema validation and byte-helper integration exercised by actual owning tests, not a replacement verifier. |
| Artifact extraction | raw stdout / compiler-artifacts.json | Independently extracted all JSON compiler-artifact lines; exact equality with retained156 records. |
| Completion/cleanup | receipt stages | All four recorded stage leaders reaped and groups clear; test command47.795s, overall50.253s. No independent process replay/check performed. |

Read retained rustc identity:1.89.0, host `aarch64-apple-darwin`. Runtime package-selection feasibility is now demonstrated by the actual test harness results, closing that static uncertainty. CLI unit/integration targets produced zero selected tests with15/5filtered; this is expected filtering, not execution of those20tests.

## 3. Graph, features and data invariants

Independently derived156artifacts representing130packages. Comparison to complete metadata produces exactly two differing artifact records: getrandom0.3.4 build-script and library have features[] while all-target metadata lists[wasm_js]. Inspected actual declared and resolved incoming edges: ahash requests getrandom unconditionally with[], while jsonschema/referencing request wasm_js only under `cfg(target_arch="wasm32")`. A zerovec declaration also requests wasm_js as a dev-dependency; zerovec's dependency-crate dev tests were not selected. No unaccounted active host edge requires that feature.

On the recorded Darwin host, the empty getrandom feature set is therefore an explained target-selection difference, not graph corruption. Preserve the raw mismatch report; Phase B must match actual Phase A host artifacts, not force metadata's all-target union. Relevant owning helper/schema/adapter features match the retained graph. Build/test target/profile distinctions remain explicit.

Independently cross-checked residual introduced-version inventory:32of39 appear in host compiler artifacts. Seven not observed are bitflags2.13.2, js-sys0.3.106, wasip2 and the four wasm-bindgen family packages. The full metadata retains platform/conditional edges leading to them (including unobserved parent chains); absence from this run is not cross-target qualification. No claim all158packages compiled or all39new versions executed is approved.

## 4. Actual tests and limits

Read the13 raw named results and checked their previously reviewed assertion paths:

- Adapter stdout:192–197, summary:199: missing-payload domain failure; strict malformed CBOR/duplicate-map refusal; all28canonical-route bypass refusals; mixed-event identification/privacy; original-record preservation; malformed wrapper/discriminator/field refusal. Six passed,57other tests filtered.
- Helper stdout:203–209, summary:211: duplicate-key rejection before conversion; bytes/tags/trailing rejection; original JSON and actual bare timestamp preservation; malformed/schema refusal; native TaskFailed expiry preservation with other-kind/unknown outcome refusal; JSON/CBOR numeric-depth parity; registry/known-route parity. Seven passed,25others filtered.

These results close the bounded native helper/adapter behavior gap identified for the composed host graph; they do not requalify every behavior of every dependency. Earlier qualification evidence remains separate. No complete native-window ZIP or actual D1 archive was supplied to this Phase A command.

## 5. Findings

OBSERVATION1 — expected feature distinction. Location: raw host comparison's getrandom records and locked metadata dependency entries. The only actual/artifact discrepancy is target-conditioned wasm_js. Explanation is supported by actual incoming edges and host identity. Phase B's artifact continuity remains required; this is not portable validation.

OBSERVATION2 — pending scope. Location: stdout:181–188 and receipt scope. Phase A filters all20CLI tests. They and final binary qualification remain unexecuted; even though the joint command produced a normal binary artifact for test compilation, that artifact is not yet the designated qualified final CLI.

No blocker to the separately granted Phase B plan. The prior qualification hold is satisfied only for the narrow native behavior evidence described above.

## 6. Conclusion

VERDICT: APPROVE Phase A acknowledgment and Phase B readiness under separate Root grant.

- Coverage: ADEQUATE for the13maintained native tests on the recorded actual CLI graph/host context, with locked/source/log continuity.
- Confidence: HIGH in retained artifact/result consistency; owner execution is audited evidence, not independent rerun.
- Next gate: existing20CLI tests, same frozen graph/host features, actual fixture001 pre/post continuity, retained binary build/hash and paired result acknowledgment. No new source or lock change is approved.
- No eligible binary designation, actual D1 verification, cross-target portability, live deployment, agency identity or adoption claim follows.

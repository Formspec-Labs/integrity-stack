# Pinback setup runner: focused static code review

VERDICT: APPROVE setup readiness for the default schema-only commands, subject to Root's separate serial grant and parent supervision. No graph, test/build progression or binary qualification is approved.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-10. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`. Static inspection only; no runner, Cargo, native, test/build or HTTP execution. Only this document was written.

## 1. Patch summary

Read all144 lines of `/private/tmp/integrity-final-cli-composition-v1-20261010/setup/run_pinback.py` (`R` below). Independently verified SHA-256 `0ab2812c59bc531d1cd3e0911de3e002b8ab153ac2bfbe4b2f7d038af5881d27`. Read the relevant plan commands/controls and verified `final-cli-composition-plan-v3.json` SHA-256 `05c28710ea6d92bbcee09f59dbd7189ff580665a45c1d94fcbcd32934f084945`, matching R:56. The caller is a future Root-authorized operator; none executed in this review.

The runner preserves attempt1 artifacts, attempts targeted offline lock pinback, captures complete metadata, and stops for independent graph review. Default commands are `cargo update --offline --manifest-path <exact CLI manifest> -p jsonschema@0.46.8 --precise 0.46.1`, then referencing0.46.8→0.46.1, then fancy-regex0.18.0→0.17.0, then full `cargo metadata --offline --format-version 1 --manifest-path <same manifest>`. There are no test/build commands and no `--no-deps`.

Exploration: H1, attempt1 could be overwritten, refuted by separate exclusive attempt2 directory. H2, each command might get a fresh120-second allowance, refuted by one shared deadline. H3, optional wasm pinback could run by default, refuted by false-by-default argparse flag. H4, successful setup could claim qualified graph, refuted by explicit pending-review result. No blocker found in the requested default scope.

## 2. Function trace

| Function / branch | R:line | Inputs → output | Verified behavior |
| --- | --- | --- | --- |
| `digest`, `write` | 24–28 | file / structured value → digest / receipt | Reads retained file bytes; writes structured JSON. |
| `main` preconditions | 52–66 | pinned plan/reviews/artifacts/source → admitted attempt2 | Checks exact plan/artifact/review/source identities and disk floor; exclusive new output directory; copies current lock before mutation. |
| Command selection | 67–73 | pinned plan / default-false flag → argv lists | Single shared command deadline; conditionals added only with `--include-wasm-pinback`; full metadata appended last. |
| Already-selected package branch | 79–90 | current lock versions / desired exact version → skip or refusal | Skips only if old ID absent and sole current version equals desired. Any other absence stops; records selected versions. |
| Command loop | 91–127 | argv list → process/receipt/log/lock evidence | `Popen` uses argument list without shell, fixed cwd, separate process session; enforces deadline, stage log cap and disk floor; nonzero exit or uncleared group stops; checks only lock changed. |
| `group_clear`, `reap` | 30–50 | process group/leader → cleanup observation | TERM, bounded wait, KILL escalation; checks group clearance; normal completion still cleans possible remaining descendants. |
| Stop/final capture | 128–141 | pass/error → retained final status | Catches BaseException inside operation, records stop reason, final lock/source hashes/time; returns nonzero on failure. Success says graph review pending. |

## 3. Data flow and invariants

Attempt1 files listed in plan `actualSetupArtifacts` are hash-checked but never written. Attempt2 uses a new `pinback-attempt2` directory (`R:65`); existing directory refuses before commands. The current lock is copied at :66, and each command retains a lock copy plus hashed stdout/stderr at :117–119. Partial successful mutations preceding refusal remain evidence; the runner does not silently roll back or reinterpret refusal as success.

One `time.monotonic()` deadline governs all commands (:67–68,91,104). This is a120-second command allowance, not a strict120-second wall-time guarantee for preflight hashing, source scans or cleanup. Polling has roughly0.1-second granularity; cleanup may add bounded waits. Log cap is32MiB aggregate stdout+stderr per stage, checked while running and after completion (:106,122). Disk floor is2GiB. These distinctions should remain visible in the owner receipt.

Default wasm commands are disabled (:54,71). Enabling the flag is not itself authorization: the help and plan require separate explicit grant/compatibility review. The runner does not independently evaluate that human review condition. This certificate approves only default schema-only setup; optional js-sys/wasm-bindgen pinback requires the owner gate first.

Cleanup covers errors raised within the command loop, including KeyboardInterrupt, via finally (:112–119). It does not install an external SIGTERM handler; forceful termination of the Python supervisor can bypass its finally block. Root's parent operator must retain/supervise recorded process groups and clean them if it interrupts the runner. No process race-free or adversarial filesystem immutability claim is made. Hash guards use Python assertions; invoke normal Python without `-O`/`PYTHONOPTIMIZE`, which would disable those checks.

## 4. Test behavior and edges

No behavioral tests or execution were performed. Concrete branches inspected: stale plan/artifact/source digest refuses before mutation; preexisting attempt2 directory refuses; already-desired sole package skips; ambiguous/absent selected package refuses; Cargo refusal stops before subsequent commands; deadline/log/disk failure triggers cleanup and nonzero return; normal process exit still reaps/cleans and records group state. Unforeseen OS cleanup errors can stop operation rather than authorize progression; parent supervision remains necessary.

Successful pinback/metadata still requires retained complete graph/lock review, successor freezing, full locked metadata admission and independent disposition of residual dependency drift. It does not resolve the preceding coverage finding by itself.

## 5. Findings

OBSERVATION1 — execution controls, R:56–64,112–119. Normal nonoptimized Python and parent cleanup of externally interrupted process groups are required operator conditions. These are limits of this runner, not graph qualification. No additional default setup command change is required under the described owner operator.

OBSERVATION2 — authority, R:54,71–73,128. Optional wasm commands are disabled by default and separately gated. Preserve that distinction; do not treat this certificate as permission to select the flag or start tests/build.

No blocking static finding for default bounded setup.

## 6. Conclusion

VERDICT: APPROVE default setup readiness only. Coverage of command selection, evidence preservation, stop branches and cleanup: ADEQUATE by static trace. Confidence: HIGH in inspected code; runtime cleanup and resolver outcomes remain unexecuted. Root's serial grant, actual setup receipt and successor graph review are still required. No tests, build, eligible binary, actual D1 or adoption approval.

# Actual D1 offline wrapper: focused static code review

VERDICT: APPROVE the thin wrapper and final v2 evidence checklist for preparation. They do not establish actual archive verification, input immutability, business coverage or execution authorization.

Reviewer: `/root/handoff_code_review`, independent non-author, GPT-6.1-sol / medium; 2026-10-09. Applied the fully read `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`; used the already fully read `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` for the narrow maintained CLI trace. Static inspection only: no wrapper invocation, shell syntax execution, native/build/test execution or live calls by this reviewer. Owner-reported `sh -n` pass is separate. Only this certificate was written; other owners' files remain unchanged.

## 1. Patch summary and exact scope

Evidence directory `E`: `/Users/mikewolfd/Work/formspec-stack/thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/final-d1-offline`. Read the complete shell script and v1 JSON checklist. Independently verified:

| Input | SHA-256 |
| --- | --- |
| `E/verify-actual-d1.sh` | `195f308a299b6a8b9141d8e050536ca9e85f87ffdfb4a2843222888ad8761cd1` |
| `E/actual-evidence-checklist-v1.json` | `7723561e53c56df6f952bcc7e864a85e62adb8b5cacb08468386bd69f8e07764` |
| `E/actual-evidence-checklist-v2.json` | `432d3bd05a2963c8640be6c4986dfc4e27b829c1ae163f736e9c09c275482aa9` |
| `E/candidate-local-demo-signing-key-registry.cbor` | `06516ab2228e2ff95fe247780a28436d01f0a77e028ef8f14997912dcaba51f2` |

The wrapper validates operator-supplied absolute executable/archive paths and expected digests, checks selected local registry/executable/archive hashes, then replaces itself with the maintained CLI. The eleven checklist rows identify pending actual source/case/filing/check/notice/clock/correction/decision/reopen/archive/verifier evidence. No actual archive or qualified final CLI is supplied (`v1 checklist:190–196`, unchanged null inputs in v2). Read v1 completely, then the complete v1→v2 delta. V2 adds owner-reported export/retrieval semantics and explicit input-race limits; shell bytes remain unchanged. Later versions are outside this certificate.

Exploration: H1, shell expansion could turn operator paths into commands, refuted by quoted argument use and absence of eval. H2, a hash-tool failure could proceed, refuted because missing/empty output cannot equal a validated expected digest. H3, prehashes atomically bind the bytes later used, refuted by separate pathname opens. H4, CLI success is presented as full D1 proof, refuted by explicit pending rows and coverage/identity limits (:198–204). Unresolved actual execution inputs are intentionally left pending.

## 2. Function and command trace

`I`: `/Users/mikewolfd/Work/formspec-stack/integrity-stack`.

| Function / command | Location | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| Required input checks | script:4–16 | four environment values → validated selection or exit | `set -eu`; rejects absent/empty variables, non-64-lowercase-hex hashes, relative paths, absent/nonexecutable CLI and absent/nonregular archive. |
| Local registry selection | script:17–19 | script path → sibling registry path and literal digest | Uses quoted dirname/cd, suppresses CDPATH influence on cd, pins exact candidate registry bytes independently rehashed above. |
| `hash_file` | script:20 | quoted path → SHA text | Invokes `shasum -a 256 --` and extracts first space-delimited field; expected digest checks at :21–23 fail before exec on mismatch. |
| CLI exec | script:26–27 | validated path, archive path, fixed option values → maintained verifier process | No eval, generated shell text, signing, writer or custom native parser. `exec` lets the parent supervise the verifier process and collect its result. |
| `verify_export_command` | `I/crates/integrity-verify-cli/src/cli.rs:293–337` | selected archive path → JSON/report or error | Reads archive once into owned bytes, checks registry pin on those bytes, calls owning WOS ZIP verifier, emits JSON; failures/false structure/false integrity return error. |
| `check_registry_pin` | same CLI:341–370 | same ZIP bytes / literal expected digest → match/error | Requires exactly one registry member relative after one root component, hashes raw member bytes, refuses missing/ambiguous/mismatched selection. |
| Registry status rendering | same CLI:373–378,603–614 | successful check selection → matched expected/observed fields | Match is emitted only after the prior gate succeeded; this is registry equality, not agency identity or business coverage. |

The maintained CLI/callee design was reviewed separately. A future executable must independently qualify that composition, including the current native WOS adapter and registry flag. The wrapper does not select or certify a binary by itself.

## 3. Data flow and invariants

Operator digests are admitted before file use and never interpreted as shell syntax. Paths remain quoted, and absolute paths prevent a filename beginning with `-` from becoming a CLI option. The registry digest is a fixed public selection, not derived from the archive it authenticates. The CLI hashes the archive's registry and verifies the same owned ZIP buffer (:294–302), preserving its internal no-second-read boundary.

The wrapper itself opens registry, executable and archive paths for prehashing and later executes/reopens paths separately. Symlinks and concurrent pathname/content replacement remain possible between checks and use. Before/after hashes cannot exclude transient replacement. It therefore proves neither atomic executable/archive binding nor no-swap behavior. The script explicitly disclaims no-swap proof (:25); the checklist separately requires immutable selection, actual checkpoint/member identity and parent receipts (:187,201). Root must use controlled retained inputs and qualify the actual run without making a stronger race-free claim.

The shell relies on the operator's normal `PATH` utilities/environment. It is not a sandbox or network isolation mechanism. `set -e` does not provide pipefail, but a failing `shasum` produces no matching valid digest; the enclosing equality check refuses. Exotic filenames that change shasum's printed format may refuse conservatively. No secret/private signing material appears in this scope.

## 4. Test behavior and edge cases

No new behavioral tests or execution receipts accompany this preparation. Owner reports syntax checking only; this review makes no phantom execution claim. Static branches inspected:

| Scenario | Static behavior / evidence |
| --- | --- |
| Missing input or invalid digest | Shell parameter guard or explicit exit2 (:5–12). |
| Relative/missing path | Explicit exit2 (:13–16). |
| Missing hash utility, unreadable input or changed digest | Equality fails rather than exec (:20–23); diagnostics may also come from the utility. |
| Spaces or shell metacharacters in absolute paths | Passed as quoted arguments; not evaluated (:15–23,26). |
| Qualified inputs all match | Exec maintained CLI with JSON and exact selected registry flag (:26–27); native result remains unknown. |
| Archive has another valid embedded registry | Maintained pin gate refuses before WOS verification/output (CLI:301,365–368). |
| Valid signature/archive but wrong case/history | Wrapper cannot distinguish; owner checklist requires actual cohort/checkpoint/original-member evidence (:141–145,198–202). |
| Timeout, runaway output or descendants | Wrapper has no built-in bounds; parent explicitly owns timeout/log capture/reaping and posthash receipts (script:24; checklist:159,187). |

Coverage is adequate for a deliberately thin static operator wrapper. Actual positive verification, refusal/timeout receipts and unchanged post-run inputs remain pending under Root's operator. Broad fixture-suite repetition is unnecessary for this preparation and was not performed.

## 5. Findings

OBSERVATION 1 — correctness / input race limit. Location: script:21–27. Hash checks precede separate executable/archive pathname use. This is a precondition check, not atomic custody or immutable byte proof. Existing disclaimers and parent responsibilities accurately bound the claim; no blocking change is required. Do not report race freedom after an ordinary successful run.

OBSERVATION 2 — evidence authority. Location: v1 checklist:150–164,190–204; v2 appended `ownerConfirmedExportSemantics`. The checklist keeps actual evidence pending and states that registry equality/CLI success do not prove scenario completeness, current authorization, identity, delivery, clocks or custody. V2 distinguishes case/process/checkpoint/bundle/rawZIP identities, semantic WOS export from sealed ZIP, and pinned retrieval from potentially publishing head retrieval. It explicitly says the Trellis CLI alone lacks the independently selected registry gate and no final binary is supplied. These are owner-reported context, not independently live-verified route, commit or deployment facts in this audit. V2's no-atomic-snapshot/no-swap limit correctly states the shell's actual behavior; no stronger claim is approved.

No blocking static finding.

## 6. Conclusion

VERDICT: APPROVE for preparation only.

- The wrapper safely passes quoted selected inputs to the maintained verifier and preserves separate registry verification and business-evidence responsibilities.
- Coverage of changed shell branches and stated claims: ADEQUATE for static review; actual execution is pending.
- Confidence: HIGH for inspected shell/CLI data flow and exact hashes. No actual D1 archive, final CLI, race-free binding, native execution, live state, full D1 or adoption is qualified.

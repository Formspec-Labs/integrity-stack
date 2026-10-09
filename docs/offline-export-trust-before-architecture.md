# Offline export registry pin — BEFORE architecture review

**VERDICT: APPROVE the narrow optional CLI registry-snapshot digest gate.** Prefer this to adding a manifest-public-key API across Integrity, Trellis WOS and Python for the present operator workflow. It qualifies exact independently selected registry bytes, not agency identity, individual human signers, freshness or legal sufficiency. Keep the maintained native verifier and archive format unchanged. No required architectural RESHAPE remains if the conditions below are implemented.

## 1. Frame and reviewer

Independent non-author `/root/handoff_before_review`, parent-requested gpt-6.1-sol/medium; runtime model identity not independently exposed. Read in full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` and applied all six phases in this continuous investigation. Static BEFORE decision review; only this certificate written. No Rust/code changes, builds, tests, live calls or private material. Existing unrelated Integrity docs and Trellis Cargo.lock edits preserved.

Current inspected Integrity HEAD `d2dd4827cd294aaecc470e6a49dd8954a48880cf`; Trellis HEAD `ea8f547367e4d41d09395001230ccf14705af8c9`. No concrete proposed implementation diff exists yet. Paths below are relative to `/Users/mikewolfd/Work/formspec-stack`.

Problem: current `integrity-verify verify-export ZIP --format json` proves native embedded-registry signature consistency but cannot accept an independently chosen expected registry identity. Proposed additive CLI option `--trusted-signing-key-registry-sha256` supplies the expected SHA-256 of exact retained registry member bytes before native verification. Category: proof infrastructure/operator tool. Beneficiary: an offline operator with an independently acquired registry snapshot and provenance, checking whether a native archive uses that exact snapshot.

## 2. Lineage and relationships

| Artifact | Relation / observation | Evidence |
| --- | --- | --- |
| Trellis Core §19 | Normative parent requires manifest kid resolution through embedded030 registry | `trellis/specs/trellis-core.md:1738–1747` |
| Trellis Core §§18,20 | Native ZIP authority and honest trust/legal limits | Core:1325–1343,2486–2530 |
| Current CLI | Native ZIP path/format only; existing output format and status | `integrity-stack/crates/integrity-verify-cli/src/cli.rs:56–66,145–176,266–309,494–552` |
| Rust native verifier | Embedded registry parse → protected manifest kid resolution → manifest signature | `integrity-stack/crates/integrity-verify/src/trellis/export.rs:153–245` |
| WOS/Python counterparts | No external exporter key/registry argument; retained unchanged for chosen CLI-only scope | `trellis/crates/trellis-verify-wos/src/lib.rs:46–47`; `trellis/trellis-py/src/trellis_py/verify.py:4596–4654`; `verify_wos.py:229–246` |
| Existing single-event key API | Sibling does not subsume archive verification; unsuitable workaround | `integrity-stack/crates/integrity-verify/src/trellis/mod.rs:243–274` |
| Maintained bundle reader | Existing raw ZIP entry reader/path/bytes API already a CLI dependency | `integrity-stack/crates/integrity-bundle/src/lib.rs:24–49,91`; CLI Cargo.toml:dependencies |
| Complete D1 target | User need for offline completeness, signer association and limits exceeds this gate | `thoughts/plans/benefits-scenarios/artifact/01-appendix-requirements.md:45,53,99` |

| Seam | Owner | Input → output / consumer |
| --- | --- | --- |
| Independently selected registry digest | Operator/root | Trusted provenance and exact retained bytes → expected digest argument |
| Local CLI admission | Integrity CLI | Same ZIP buffer + digest → matched/mismatch/not-requested evidence |
| Native signature/archive verification | Existing Integrity/Trellis WOS | Same ZIP buffer → unchanged owning structural/integrity/domain report |
| Actual case archive/history | Root/WOS/Trellis | Real records and native export → later operation input |
| Agency/signer/legal authority | Owning deployment/bindings | Independent provenance/association/policy, not inferred by this CLI |

The option adds a local caller constraint above the existing algorithm. It neither replaces Core kid resolution nor changes Trellis wire bytes. Therefore no Trellis-owned WOS/Python signature change is necessary. A later reusable library consumer needing external-key admission would need its own coordinated design.

## 3. Invariants and implementation conditions

**I1 — One candidate byte snapshot: PRESERVED.** Read ZIP once into owned bytes. Apply maintained `read_stored_zip` to those bytes and find exactly one entry whose path equals `030-signing-key-registry.cbor`. Reject duplicate/missing member or parse failure for the requested gate. Do not choose first/last duplicate, read the archive again, use a JSON reserialization, or trust a hash merely claimed inside manifest. Invoke existing WOS verifier on the same byte buffer. Reader API gives exact `BundleEntry.bytes()`; no custom ZIP parser required.

**I2 — Native verifier remains necessary: PRESERVED.** Matching digest is only an input constraint, never a verified archive. Existing verifier still parses registry, resolves protected manifest kid, verifies manifest, binds member digests and checks events/checkpoints/proofs/WOS semantics. Failed native verification remains failure even when gate matches. Keep current failure behavior and report evidence. A pin mismatch must fail the overall invocation even if native bytes are internally valid.

**I3 — Caller selects expected value independently: RELIED-UPON.** Validate exactly64hex digits and deterministic casing representation; reject malformed/missing flag values and repeated flag occurrences rather than silently overriding. Do not derive expected digest from the input archive or a sidecar inside it. A user who copies the observed archive hash into the argument has performed no independent selection; tooling cannot manufacture provenance. A malicious internally consistent archive with a different registry must fail against the retained external pin.

**I4 — Snapshot trust differs from exporter-only trust: NEWLY INTRODUCED constraint, explicitly narrower.** An entire registry pin fixes all included key rows, rotation history, metadata and ordering. Native verifier may accept a manifest signed by any applicable key in that selected snapshot; this gate is not a single expected exporter-key check. It accommodates historical keys already present without requiring every event/checkpoint key equal one key. If an operator must authorize only one exporter within an otherwise shared registry, this shape is insufficient: use a separately reviewed manifest-kid/public-key admission seam. No claim that the two mechanisms are equivalent.

**I5 — Clear output and exit meaning: PRESERVED / additive.** Text/JSON must explicitly distinguish requested-and-matched from not-requested, and expose expected/observed digest where available. Failed gate exits nonzero; malformed flag is usage failure. Absence of option preserves existing verification capability and exit semantics but states no independent registry pin was checked. Do not silently set agency trust, identity, freshness, authorized export, completeness beyond native coverage or legal admissibility. Keep native verification report meanings intact; gate evidence is CLI-owned observation, not a forged Trellis VerificationReceipt/profile. Existing JSON `verified` is native validity; any added overall/gate result must avoid ambiguity about native-valid versus invocation-refused.

**I6 — Maintained cryptographic primitive and dependency direction: PRESERVED.** Reuse maintained SHA-256, declare the direct crate dependency actually used. The suggested `integrity_verify::trellis::sha256_bytes` is not currently publicly exported: mod.rs imports/reexports do not provide it; native export uses the maintained Trellis types helper internally. Do not implement SHA-256 or expose an unrelated API solely to avoid declaring a dependency. Bundle reader is already directly declared. Cross-owner libraries remain untouched.

**I7 — Static source and real record proof remain separate: PRESERVED.** There is currently no actual full D1 archive in this review. That is an acquisition/history dependency, not evidence that the generic verifier lacks native verification. Conversely, an available archive does not create the missing external selection argument. Later actual proof needs exact archive/binary pins, independently acquired registry/provenance, actual event coverage, original signed text/permitted document bytes, signer association and retention/clock/notice findings. Synthetic tests cannot supply those records.

## 4. User value and smaller shape

This adds a concrete offline check against a registry snapshot already selected outside the archive. It removes an otherwise manual, easy-to-omit equality step without duplicating signature or archive logic. No speed/resource advantage claimed: the CLI may parse/copy entries in addition to native verification. Complexity/resource cost should remain bounded by reuse; avoid a performance claim without measurement.

Compared with the prior proposed manifest-key API, registry pinning needs fewer changed owners and directly matches an exact-snapshot operator workflow. It is chosen because that narrower outcome suffices here, not because it gives stronger single-exporter authorization. A shell precheck is smaller code but leaves output/status integration and consistent same-buffer checking to each operator. A new trust profile/runtime format adds no useful capability.

Six-month falsifier: users cannot tell no-pin verification from independent snapshot admission, mismatched registry still succeeds, or this tool's match is presented as authenticated agency/human identity.

## 5. Hypotheses and counterfactuals

H1(high): maintained exports already accept trusted external selection — **REFUTED** across CLI/Rust/Python. H2(high): CLI digest admission necessarily changes normative native verifier — **REFUTED**, it composes an additional operator constraint. H3(high): whole-registry pin equals a single exporter pin — **REFUTED**, authority is to the selected snapshot. H4(high): no archive means no generic change can be justified — **REFUTED**, missing input and missing boundary are separate. H5(high): proposed public hash helper exists — **REFUTED**, use maintained declared primitive.

Kill criteria: mismatched pin accepted, gate and verifier use different ZIP reads, ambiguous duplicate030 selection, no-pin presented as external trust, or native failures suppressed. Counter-decision: add selected manifest key across three owned APIs; valid when exporter-only authorization is required but unnecessary here. Removal probe: native integrity remains, external exact-registry check disappears. Sibling subsumption partial: native reader/hash/verifier already supply mechanics; CLI admission/output is the missing composition. Future critic should inspect explicit gate evidence and key provenance rather than equate match with legal origin.

## 6. Findings and dispositions

**F1 — OBSERVATION / named-seam / KEEP CLI-only snapshot selection.** Adopt optional externally supplied exact registry digest; preserve maintained verifier and native format. No required RESHAPE if conditions I1–I7 hold.

**F2 — OBSERVATION / sibling-conflict / DEFER exporter-key library API.** Needed only for independently authorizing one manifest signer rather than a whole registry snapshot, or reusable non-CLI consumers. Do not change WOS/Python API ownership speculatively.

**F3 — OBSERVATION / trust / REVERSE authority overclaims.** Registry hash match is selected-byte identity plus existing native signature consistency. No new trust profile, synthetic signer, D1 wrapper or legal claim.

**F4 — OBSERVATION / verification / KEEP meaningful acceptance checks.** Require actual valid native fixture + correct external pin success, wrong pin nonzero, internally valid replacement-registry archive refusal under original pin, malformed/repeated option refusal, missing/duplicate registry refusal, matched pin with native tamper failure, and explicit no-pin output preserving current native results. Rust implementation requires owning Rust discipline and independent AFTER code/architecture gates; this certificate performs no execution.

## 7. Verdict

```text
VERDICT: APPROVE
Intent vs. shape: MATCHES — narrow external registry-snapshot admission at CLI boundary.
User-value claim: SUPPORTED — integrated offline selected-registry equality evidence.
Commitment status: HONORED — native algorithm unchanged, trust limits explicit.
Conceptual debt delta: PAYS DOWN — manual composition made reviewable without cross-owner API churn.
Sibling subsumption: PARTIAL — maintained primitives reused.
Confidence: HIGH for static architecture; implementation/execution/real archive not reviewed.
```

Only this BEFORE certificate added. Current spec/source/report boundaries traced, no code edited, native builds/live calls/tests or key operations. Final implementation must receive exact-diff independent AFTER review; actual-record operation proof remains separate.

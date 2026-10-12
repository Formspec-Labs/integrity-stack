# Native provenance offline adapter — AFTER preparation architecture review

**VERDICT: APPROVE the exact private adapter and test preparation.** The adapter checks only `wos.provenance.recorded`, delegates original payload bytes to the shared WOS helper, and reports invalid or unavailable payloads as domain failures with fixed messages. Existing canonical routes and cryptographic verification remain separate. This is static preparation approval: the shared helper is absent, and no compilation, execution, integration, actual history or adoption is qualified.

## 1. Artifact summary and method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime model identity not independently exposed. Applied `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full during this continuous native-provenance review. All six phases are covered below. Read the complete patch and the bodies of both revised design documents, traced existing verdict classification and dependencies, and independently recomputed identities. No Cargo, native command, test, live call, service change or implementation edit executed. Only this certificate written; all other owners' files preserved.

Category: proof infrastructure serving native provenance custody and offline review. Private candidate root: `/private/tmp/integrity-native-provenance-v1-20261009/candidate/trellis/crates/trellis-verify-wos`. The three-file patch declares one private module, adds one validator invocation and supplies the thin adapter plus narrow tests. It makes no manifest/public-export changes. Production adapter is `src/native_provenance.rs:6–35`; remaining lines are prepared tests.

| Exact artifact | SHA-256 |
| --- | --- |
| `/private/tmp/integrity-native-provenance-v1-20261009/native-provenance-offline.patch` | `bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97` |
| Candidate `src/lib.rs` | `b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9` |
| Candidate `src/validator.rs` | `e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0` |
| Candidate `src/native_provenance.rs` | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |
| `trellis/examples/d1-export/native-provenance-routing-proposal-v2.md` | `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` |
| `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md` | `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82` |

Paths below are workspace-relative unless labeled candidate. Candidate line references use the private root above.

## 2. Lineage and relationships

| Artifact | Relationship | Evidence |
| --- | --- | --- |
| `integrity-stack/docs/native-provenance-before-architecture.md` | Parent approval and private preparation addendum | Agreed API addendum; strict shared ownership and separate schema requirements |
| Joint routing proposal v2 | Declares generic wire shape, canonical separation, owners and gates | Decision and exact wire shape; Shared owning API and decoder; Owners and implementation seams; Verification gates |
| Core API supplement v3 | Declares owner helper and source-specific timestamp policy | Shared API and ownership; Exact CBOR subset |
| `trellis/specs/wos-trellis-verification.md:3–29,31–43` | Normative parent: Core proof separate from offline domain semantics | Core-derived evidence, no live runtime dependencies, blocking domain verdict |
| Existing WOS validator and verdict | Maintained consumer mechanism | `trellis/crates/trellis-verify-wos/src/validator.rs:17–36`; findings.rs:26–35 |

| Component/seam | Owner | Dependency and consumer | Boundary |
| --- | --- | --- | --- |
| Generic record decoding/schema/classification | WOS `wos-events` | Shared `NativeProvenanceEvent` consumed by adapter | Core supplement v3 API; actual implementation pending |
| Offline adapter | Trellis WOS verifier, privately prepared under lent Integrity ownership | Existing WOS dependency and Integrity domain types | Candidate native_provenance.rs:6–35 |
| Core evidence and verdict | Generic Integrity | `DomainEvent` supplies original optional payload/hash; findings classified by maintained verdict | integrity-stack/crates/integrity-verify/src/trellis/validator.rs:90–109,134–148,190–196 |
| Registry/client/admission | Trellis owner | Same WOS helper, separate integration patch | Joint proposal Owners section; outside this three-file patch |

Both existing admission and offline WOS crates already depend on `wos-events` in their Cargo.toml files. The new adapter uses that direction without adding WOS-specific interpretation to generic Integrity. Its private module does not create a new public API. The original shared-checkout helper path `work-spec/crates/wos-events/src/native_provenance.rs` is absent at review time; no shared implementation is certified by this preparation.

Hypothesis H1(high), the patch duplicates strict decoding policy: **REFUTED** by direct shared-helper delegation at candidate native_provenance.rs:20. H2(high), it weakens canonical checks: **REFUTED** for this patch; exact generic-literal filtering skips every other event and the existing validator calls remain. H3(high), new failures correctly block domain admissibility: **CONFIRMED statically** by Severity::Failure and maintained non-projection classification. H4(high), this proves the shared strict rules execute correctly: **REFUTED**; helper implementation and execution remain pending. No more source exploration is needed to qualify the private preparation.

## 3. Invariants and commitments

| Invariant | Status | Evidence / failure mode |
| --- | --- | --- |
| Only the generic route uses this check | PRESERVED | Candidate native_provenance.rs:12–14; mixed-route and canonical-exclusion tests. Matching a nested application key cannot select specialized semantics. |
| Original readable payload reaches one owning validator | PRESERVED in adapter shape | Candidate:16–24 passes borrowed bytes directly. Local JSON inspection could erase ambiguous CBOR evidence; none is added. |
| No payload means no domain admissibility claim | PRESERVED | Candidate:17–19,28–33 emits hash-associated Failure. Prepared unavailable-payload test checks crypto Pass/domain Fail/relying-party Invalid independently. |
| Invalid generic shape remains a domain failure | PRESERVED | Candidate:20–23,28–33; maintained verdict.rs location is `integrity-stack/crates/integrity-verify/src/trellis/validator.rs:100–109,134–148`. It is not a projection advisory or a cryptographic mutation. |
| Reports avoid original facts and schema diagnostics | NEWLY INTRODUCED / preserved by code | Candidate:17–23,26–33 uses fixed kind/message and event hash only; helper error is discarded. No original id, actor, data or error text is interpolated. This bounds this adapter's reports, not every report elsewhere. |
| Canonical and timestamp source policies remain distinct | RELIED-UPON | Core supplement v3 Exact CBOR subset: bare original timestamp tag0 is permitted at one path; wrapped payload permits no tags. Adapter correctly calls wrapped `from_dcbor_slice`, not bare-record entry. |
| Offline semantics remain independent of live state | PRESERVED | Candidate:10–35 depends only on DomainEvent bytes; normative WOS verification boundary:17–29. |

The prepared tests cover OnEntry/NoticeSent original-value preservation, no mutation of DomainEvent inputs, missing payload, malformed wrapper/required fields/kinds, canonical28 bypass refusal, malformed and trailing CBOR, duplicate keys at wrapper/record/data, unsupported tags/bytes/nontext keys, wrapped timestamp-tag rejection, depth refusal and mixed-route isolation. These are test intentions read from candidate native_provenance.rs:37–284, not passing execution results. Full shared-helper numeric/enum/schema coverage and genuine runtime-window evidence remain owner gates in the joint proposal. The adapter need not duplicate the owner's entire test suite.

## 4. User-value analysis

The preparation supplies a small maintained-domain hook so offline review can refuse unreadable or invalid generic provenance while retaining established specialized checks. It adds one bounded scan and shared-helper call per matching event; no performance/resource benefit is claimed or measured. The conceptual benefit is one source of record validity rather than copied kind/field/decoder rules.

Leaving generic records unchecked would preserve byte integrity but omit their domain-shape refusal. Copying a parser into this adapter would add divergent semantics and dependency debt. Generic Integrity cannot subsume WOS-specific interpretation without breaking the existing consumer-validator boundary. Value is falsified if ingress and offline helper decisions diverge, canonical-kind bypass succeeds or a valid generic record is rewritten. These claims require the future helper/integration evidence; preparation alone cannot resolve them.

## 5. Counterfactual analysis

Kill criteria: local fallback acceptance, duplicated record policy, canonical event promotion, sensitive report interpolation or an unavailable-payload advisory replacing failure. None appears in this exact patch. Removing it leaves the current WOS offline validator blind to the new generic route's shape. Opposite design would accept generic bytes solely on Core integrity, which proves custody but not this declared WOS domain boundary. Shared WOS helper subsumption is intentional: it owns all actual strict validation; the adapter owns traversal, finding placement and privacy. A six-month reviewer should first inspect owner helper/schema drift and whether the private patch actually reached the maintained router/verifier, not infer adoption from this certificate.

## 6. Findings and dispositions

- **KEEP — OBSERVATION / named-seam:** direct wrapped-byte delegation and generic-literal filtering; candidate native_provenance.rs:6–24. No required reshape.
- **KEEP — OBSERVATION / commitment:** fixed, hash-associated domain Failure findings for invalid/unavailable payload; candidate:17–33 and maintained verdict classification. This preserves cryptographic/domain separation and avoids leaking original facts through new messages.
- **KEEP — OBSERVATION / ownership:** preserve private patch handoff and existing WOS dependency; no shared-checkout edit or generic Integrity dependency inversion.
- **REVERSE — OBSERVATION / intent-vs-shape:** reject any statement that prepared tests passed or that the absent shared helper's strict semantics were qualified. Actual code and execution receipts are prerequisites.
- **DEFER — OBSERVATION / scope:** actual helper/schema AFTER review, coordinated compilation, full runtime window, admission/offline parity, archive mutations and owner adoption. These are explicit joint gates, not work performed here.

## 7. Verdict

```text
VERDICT: APPROVE private adapter/test preparation only
Intent vs. shape: MATCHES — thin shared-owner validation hook.
User-value claim: SUPPORTED — offline domain refusal for the new generic route.
Commitment status: HONORED — canonical, crypto/domain, privacy and ownership separation.
Conceptual debt delta: PAYS DOWN — reused validation; no copied allowlist/decoder.
Sibling subsumption: PARTIAL and intentional — WOS helper owns strict rules.
Confidence: HIGH for static adapter shape; helper behavior/execution unqualified.
```

No build/test PASS, source integration, transport success, original-record round-trip in production, actual D1 archive, trust decision, live operation or adoption follows from this verdict.

# Native provenance shared source — AFTER architecture review

**VERDICT: APPROVE the exact shared-helper/schema source and its offline adapter alignment.** The helper validates original raw values, retains the complete record, refuses canonical-kind bypass, and checks ambiguous CBOR before conversion can discard evidence. The bare custody timestamp exception is path-specific; the offline wrapped payload remains tag-free. No architecture reshape is required in this bounded scope. Compilation, execution, mutable lock/private dependency closure, integration/adoption and actual D1 qualification remain unqualified.

## 1. Artifact summary and method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime model identity not independently exposed. Applied the full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full during this continuous review. All six phases appear below. Read the actual helper, complete schema and helper tests; traced the maintained CBOR functions, producer selection/consumer boundary and previously reviewed exact offline patch. Recomputed all12 manifest pins, compared schema fields to the actual serializer and its remaining-kind enum to the owner registry. These are static source checks, not test execution. No Cargo/build/native/live commands or source edits. Only this certificate written; other owners' files preserved.

Category: product capability and proof infrastructure for complete native custody and later offline interpretation. Core private root: `/private/tmp/core-native-provenance-v1-20261009/work-spec`; Core base `22296385f4ef179ad330f55d80592194f8b3af6b`. References to helper/schema/tests below are relative to that root. Workspace references are explicitly labeled.

| Exact artifact | SHA-256 |
| --- | --- |
| Workspace `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-source-v1.json` | `d2ff5275a96069351e1984ca750f636f5741b5f30c51979555ac6bc285d649b3` |
| `crates/wos-events/src/native_provenance.rs` | `09423218a6ff828275c3c319939b6079dc92632403d5ab25befe84c8c1f3940d` |
| `schemas/wos-native-provenance-event.schema.json` | `c0de3586a1880ead199c8aa12b8543e8e62c422c674f00e53f576226daf2cd54` |
| `crates/wos-events/src/native_provenance/tests.rs` | `c078ca577dcde0e4da7fe35d26071843086b842d47c60797c73dc554a7189e14` |
| Previously reviewed `/private/tmp/integrity-native-provenance-v1-20261009/native-provenance-offline.patch` | `bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97` |

All12 manifest-listed current files match. This certifies those source identities, not a portable or executable dependency graph. The manifest explicitly records private absolute dependency paths and pending portable source closure. Its `Cargo.lock` pin identifies current bytes without proving locked resolution succeeds.

## 2. Lineage and relationship trace

| Artifact | Relation | Evidence |
| --- | --- | --- |
| Workspace `integrity-stack/docs/native-provenance-before-architecture.md` | Parent constraints and shared API agreement | Agreed API addendum; separate schema, original values, no copied allowlist |
| Workspace `integrity-stack/docs/native-provenance-after-architecture-preparation.md` | Exact thin offline adapter review | Invariants and verdict; fixed domain failures and wrapped helper |
| Workspace `trellis/examples/d1-export/native-provenance-routing-proposal-v2.md` | Joint wire/ownership decision | Decision, shared decoder and verification gates; SHA `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` |
| Workspace `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md` | Source-specific CBOR policy and owner API | Exact CBOR subset; SHA `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82` |
| Workspace `trellis/specs/wos-trellis-verification.md:3–29,31–43` | Normative proof/domain boundary | Core-derived offline evidence; cryptographic integrity separate from domain admissibility |

| Component/seam | Owner | Depends on / consumer | Source |
| --- | --- | --- | --- |
| Strict raw record/schema/classification | WOS events | Maintained enum, type-ID helper, embedded cached jsonschema validator | helper:57–79; schema properties.record |
| Original custody decoding/production | WOS runtime/events | Bare entry point, original id and existing context | custody_trellis.rs:97–115; custody.rs:264–309 |
| Offline domain check | Trellis WOS verifier | Wrapped helper and existing DomainFinding interface | Previously pinned patch native_provenance.rs:6–35 |
| Cryptographic proof and generic domain interface | Integrity | Maintained CBOR primitive; consumer-owned WOS validator | Workspace integrity-cbor/lib.rs:140–203,297–338; generic validator interface |

WOS owns the business vocabulary and schema; Integrity provides generic byte primitives; Trellis WOS adapter composes them. The helper adds `jsonschema` to WOS events with cached initialization (`OnceLock`), not to generic Integrity. Private `Cargo.toml` uses absolute sibling paths as declared setup; restoring portable paths/freezing those dependencies remains a release prerequisite. The owner reports private adapter integration; this review does not independently qualify that larger integration graph.

H1(high), unknown facts can disappear through typed parsing: **REFUTED for this helper**. It inspects raw values, parses only the discriminator for classification, validates closed structural shape, and stores a clone of the original value (helper:57–79). H2(high), duplicate CBOR keys disappear before refusal: **REFUTED** by ordering at148–156 and maintained map checks before conversion. H3(high), bare timestamp support relaxes wrapped archives: **REFUTED** by distinct entry points and exact bare root path guard at165–168. H4(high), static implementation proves runtime behavior: **REFUTED**; prepared tests and actual execution remain separate.

## 3. Invariants and commitments

| Invariant | Status | Evidence / failure mode |
| --- | --- | --- |
| Exact wrapper and native structural fields; original arbitrary data retained | PRESERVED | Schema closes wrapper/record, `data: {}`; helper clones original payload:79. Static comparison finds exactly20 serializer fields, no field differences. Unknown structural fields cannot silently disappear. |
| Explicit recognized remaining kind; no canonical bypass | PRESERVED | helper:61–65 and schema recordKind enum; static registry comparison matches106 remaining entries. Existing canonical28 keep their separate routing at custody.rs:271–278. |
| Required persisted id/time/tier/version | PRESERVED | Schema required list; timestamp date-time format with format assertion enabled at helper:70–78; native type-ID check:67–69. Defaults and inferred fields are not inserted. |
| Complete original record and triggering event survive | PRESERVED at value boundary | helper:79,114–126; producer uses original bare bytes:100 then native.payload():113, verifies id:102. No event substitution/defaulting or timestamp restamp occurs here. |
| One CBOR value, no ambiguous maps before JSON conversion | PRESERVED | helper:148–156; workspace integrity-cbor/lib.rs:140–149,166–198. Sorted clone discarded; original decoded value converted only after validation. |
| Wrapped and bare tag policies differ only at original root timestamp | PRESERVED | helper:96–109,151,165–168; custody.rs:312–313. Bare tag0 requires text; shared schema then validates date-time. Every wrapped tag, byte string and nontext key refuses. |
| JSON/CBOR accepted numeric/depth domains align | PRESERVED statically | helper:129–156,159–189; signed64 conversion in workspace CBOR/lib.rs:304–312. Bare traversal begins at depth1 to account for subsequently added wrapper. Negative zero/nonfinite numbers refuse. |
| Offline invalid/unavailable payload is domain Failure, with fixed report messages | PRESERVED by exact adapter | Pinned adapter:16–33; generic verdict at workspace integrity-verify/trellis/validator.rs:100–109,134–148. Helper errors are discarded, preserving report privacy. |
| No WOS-specific dependency enters generic Integrity | PRESERVED | WOS helper consumes generic integrity-cbor; Trellis WOS adapter consumes WOS helper. Existing consumer-validator direction remains. |

The helper's JSON-side schema error contains an instance path (`helper:75–77`), so it is not a universal guarantee that every caller diagnostic excludes user-controlled property names. The offline adapter emits only fixed messages plus the already supplied canonical event hash; its narrower report-privacy claim remains supported. No broad diagnostic privacy claim is approved.

Depth128 is an accepted-value/traversal rule after maintained decoding, not a measured preallocation or byte-size resource bound. The helper clones validated values and the maintained canonicalizer clones a sorted tree for validation; this is the explicit preservation/simplicity tradeoff. No speed or memory claim is made. JSON Value entry points cannot recover duplicate raw HTTP JSON keys already collapsed by upstream parsing, as documented in the approved proposal.

## 4. Tests and user value

Read tests prepare registry parity/every-known-route and canonical exclusions, complete original JSON/tagged timestamp preservation, original byte nonmutation, required/unknown/malformed fields, JSON/CBOR numeric/depth boundaries, duplicates before conversion, tags/bytes/trailing refusal. Test names reside in `crates/wos-events/src/native_provenance/tests.rs`; their assertions match these invariants. The separately prepared offline suite exercises unavailable payload, fixed Failure findings, wrapped-tag refusal and mixed-route isolation. Neither suite has been executed by this reviewer; this certificate claims no PASS.

The user-visible improvement is eligibility for custody and offline shape checks of known native records that lack specialized mappings. Reusing maintained CBOR, schema and enum components avoids106 copied mappings or an independent serializer. The original-value ownership pays down loss and interpretation drift at the cost of bounded tree traversal/cloning. It does not certify richer kind-specific business assertions, real history completeness, signer identity, archive coverage, retention or agency trust.

## 5. Counterfactual and kill criteria

Reject the shape if a canonical kind enters generic custody, a duplicate key is accepted after collapse, an original record field is dropped/normalized, producer/offline value domains diverge or generic Integrity acquires WOS record semantics. None appears in the reviewed source. Removing the helper restores divergent producer/admission/offline interpretation; adding local typed parse/reserialization would reintroduce omission/default risks. Existing canonical schemas cannot subsume this generic full-record shape because their `recordKind` policy differs. A future reviewer should first demand actual coordinated tests, full-window original/receipt/ZIP identity evidence and a portable frozen dependency graph; this source review does not supply them.

## 6. Findings and dispositions

- **KEEP — OBSERVATION / commitment:** separate strict generic schema and raw-value ownership; retain existing canonical mappings unchanged. Evidence: helper57–79, schema structural properties, custody271–309.
- **KEEP — OBSERVATION / named-seam:** shared maintained decoder/canonicalizer with pre-conversion duplicate refusal and source-specific timestamp policy; retain the wrapped adapter entry point. Evidence: helper96–109,148–189.
- **KEEP — OBSERVATION / ownership/privacy:** WOS owns rules; Trellis offline composes them; fixed adapter messages avoid exposing helper diagnostics. No required architecture RESHAPE found.
- **REVERSE — OBSERVATION / scope:** reject claims of original source-byte equality across tagged-bare to untagged-wrapped conversion, raw HTTP duplicate detection, resource bounds beyond the stated traversal rule, or universal diagnostic privacy.
- **DEFER — OBSERVATION / scope:** execution, lock/private path closure, actual admission/client/router integration, portable patch/adoption, and full D1 proof. These remain explicit owner gates; no native retry follows from this certificate.

## 7. Verdict

```text
VERDICT: APPROVE static shared source and offline alignment
Intent vs. shape: MATCHES — strict original-value custody boundary with shared owner rules.
User-value claim: SUPPORTED — closes interpretation gap for remaining known native kinds.
Commitment status: HONORED — canonical separation, source validity and domain ownership preserved.
Conceptual debt delta: PAYS DOWN — maintained schema/enum/CBOR reuse replaces drift-prone fallback.
Sibling subsumption: PARTIAL — canonical routes remain specialized; shared helper subsumes generic rule copies.
Confidence: HIGH on static shape and exact identities; execution/integration/adoption unqualified.
```

Broader Core producer/runtime reviews remain separate. This bounded verdict does not certify buildability, full native custody success, a genuine archive, operational authority or any live system result.

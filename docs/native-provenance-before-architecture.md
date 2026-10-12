# Native provenance custody — BEFORE architecture review

**VERDICT: APPROVE the refined shape; DEFER implementation until the shared WOS API and generic record schema are frozen by their owners.** Use `wos.provenance.recorded` for known provenance kinds without a canonical event literal. Preserve all28 existing canonical mappings and their existing payloads. The generic payload is exactly `{ "record": <original serialized ProvenanceRecord with explicit recordKind> }`. A shared WOS-owned raw-value validator must enforce this boundary at production, admission and offline interpretation. This approval does not authorize source edits, builds or live operations.

The earlier proposed `wos.kernel.provenance_recorded` is superseded by the lead's joint conferral. A neutral `wos.provenance` family accurately describes custody of the original record without attributing all recorded actions to the kernel.

## 1. Decision frame and method

Independent reviewer `/root/handoff_before_review`; parent-requested gpt-6.1-sol/medium, runtime model identity not independently exposed. Read **in full** `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` and applied all six phases. Static review only: no builds, tests, native/live calls or implementation changes. Only this certificate written; other owners' work preserved.

Category: product capability with proof infrastructure. Beneficiaries are workflow operators and later offline reviewers who need custody of the full native provenance history. The lead reports a134-kind inventory with106 known kinds lacking canonical mappings and an initial OnEntry refusal before transport. That incident/count is owner-supplied context, not independently reproduced here. The code confirms the generic gap: WOS synthesizes an event tail for kinds without canonical mapping (`work-spec/crates/wos-events/src/custody.rs:263–290`), but Trellis routes only registered literals and its WOS adapter admits only kinds resolved from canonical literals (`trellis/crates/trellis-server/src/composition.rs:199–225`; `trellis/crates/trellis-admission-wos/src/lib.rs:125–132`). This review qualifies the shape that closes that mismatch, not actual D1 completion.

All paths are relative to `/Users/mikewolfd/Work/formspec-stack`.

## 2. Lineage and relationship trace

| Prior artifact | Relation | Evidence |
| --- | --- | --- |
| WOS native enum and canonical vocabulary | Single source of kind classification and existing28 mappings | `work-spec/crates/wos-events/src/provenance/kind.rs:5–8,472–520` |
| Current custody serializer | Preserves authored record except intentional canonical `recordKind` omission | `work-spec/crates/wos-events/src/custody.rs:293–318` |
| Current canonical Facts-tier schema | Requires event dispatch; forbids `recordKind` | `work-spec/schemas/wos-workflow.schema.json:4409–4425` |
| Native log schema | Post-append export shape, not unstamped constructor shape | `work-spec/schemas/wos-provenance-log.schema.json:5` |
| WOS-Trellis verification specification | Core cryptography first; offline WOS semantics use Core-derived evidence only | `trellis/specs/wos-trellis-verification.md:3–29,31–43` |
| Joint owner conferral | Refines proposal to neutral literal and WOS-owned `NativeProvenanceEvent` helper | Lead's current task messages; API/schema freeze still pending |

| Component/seam | Owner | Depends on / used by | Named boundary |
| --- | --- | --- | --- |
| Enum, classification, original record validation and event production | WOS | Shared `NativeProvenanceEvent` helper, existing enum | Proposed owner API; exact signature/schema pending |
| Registry and admission | Trellis WOS adapter/composition | WOS helper; neutral registry metadata | Existing `wos-events://` schema reference and ServiceOnly policy, admission lib:25–31,62–87,101–117 |
| Offline WOS interpretation | Trellis `trellis-verify-wos` | WOS helper; Integrity's consumer-validator interface | `trellis/crates/trellis-verify-wos/src/lib.rs:41–47`; validator.rs:17–36 |
| Generic cryptographic verification | Integrity | Trellis Core evidence; consumer-supplied domain validator | `integrity-stack/crates/integrity-verify/src/trellis/validator.rs:190–196`; WOS verification spec:6–29 |

Both WOS admission and offline crates already depend on `wos-events` (their Cargo.toml dependency sections). Reusing its validator preserves direction. Adding WOS record knowledge to generic Integrity would reverse that separation. Lent editing ownership is limited to a private Trellis WOS-validator candidate/module declaration/narrow tests, then patch handoff to the owner; it does not transfer semantic ownership or authorize edits in the original shared checkout.

H1(high), a transport event per every kind is required: **REFUTED**. Existing enum classification plus a single separate generic event can preserve the record without106 copied literals. H2(high), typed parsing alone proves full original fidelity: **REFUTED**. `ProvenanceRecord::Deserialize` defaults many fields, infers missing `recordKind` from canonical event and has no unknown-field refusal (`record.rs:636–715`). H3(high), current canonical schema accepts the proposed full original: **REFUTED** by its explicit `not: required recordKind`. Next action must therefore freeze a separate generic-record schema and the shared validator behavior before implementation.

## 3. Invariants and commitments

| Invariant | Status required | Evidence / failure mode |
| --- | --- | --- |
| Existing28 canonical mappings and payloads remain exact | PRESERVED | Kind table:472–500; custody.rs:270–277,299–315. Generic fallback must not weaken signature, clock, intake or other canonical semantics. |
| Generic literal is not itself a `ProvenanceKind` mapping | NEWLY INTRODUCED | Separate transport classification; canonical table remains unchanged. Otherwise reverse lookup falsely equates many record kinds. |
| Generic path admits only explicit known enum kinds with `canonical_event_literal() == None` | NEWLY INTRODUCED | Shared enum lookup:506–519. Unknown kinds and canonical-kind generic bypass must refuse deterministically. |
| Full original serialized record survives validation | RELIED-UPON / strengthened | Typed parser defaults/unknown handling at record.rs:641–692 cannot establish this. Validate raw fields and retain original value; do not replace it with a parsed-and-reserialized approximation. |
| Identity, timestamp and original event are preserved | PRESERVED | Metadata takes record.id at custody.rs:44–60; persisted timestamp meaning at record.rs:530–546. No new id, time, canonical event substitution, dropped/null/defaulted field or inferred kind may silently rewrite evidence. |
| Domain validation follows Core proof, without live runtime dependence | PRESERVED | WOS verification spec:13–29. Generic event presence does not imply cryptographic verification or full history coverage. |
| One owner supplies validation/classification | PRESERVED | Existing dependencies on wos-events; no copied106-kind allowlist in Trellis/Integrity. Otherwise future kinds drift across producer/admission/offline. |

Raw validation must check the exact wrapper member set, object record root, explicit `recordKind`, required field presence/types, and unknown top-level record members according to the frozen WOS-owned schema. Reject unsupported fields rather than silently discard them. Keep intentionally arbitrary `data` JSON and any explicitly allowed extension namespace distinct from structural unknown fields; recursively closing all `data` objects would invent a new restriction. A comparison against typed reserialization alone is insufficient because defaults, optional omission and serde handling change accepted input shape. The shared helper may parse to classify/check types while retaining the original raw record for transport and interpretation.

"Original" here means the original serialized JSON value carried through the existing maintained JSON-to-dCBOR path. It does not assert preservation of source whitespace, property order, numeric lexical spelling or original signed text bytes. Those require their own byte evidence. Validate the persisted timestamp without restamping it; determine exact required-field rules in the owner schema rather than relying on constructor defaults. Preserve the original inner `event`, which can be the workflow trigger; the outer transport literal must not overwrite it. Keep record identity bound to existing metadata/idempotency identity. Existing metadata validation alone only checks its own fields (`custody.rs:81–102`), so a public construction path accepting separate metadata must not silently admit a conflicting record id or transport kind.

## 4. User-value analysis

The proposal makes otherwise known native provenance eligible for maintained custody, addressing a concrete producer/admission mismatch. One neutral literal plus one shared validator adds less conceptual debt than106 transport mappings and duplicate allowlists. It retains specialized canonical events where independent semantics already exist. It does not itself establish a complete real archive, actual signer association, retention policy or agency trust.

The smaller alternatives fail the stated outcome: retaining refusal prevents full native custody; accepting arbitrary generic JSON loses classification and bypass protection. A broader enum-to-canonical expansion changes106 event semantics and registry commitments unnecessarily. Value is falsified if a known noncanonical record still cannot traverse the maintained path, if the returned record differs from its original, or if offline interpretation accepts a record admission refuses.

## 5. Counterfactual check

Kill criteria: a canonical kind succeeds through generic dispatch; an unknown kind/structural field is silently accepted and discarded; producer and offline classification differ; a full record is normalized; or generic Integrity acquires WOS-specific dependencies. Opposite decision would preserve today's explicit rejection but leave the full-history outcome unavailable. Removing the new event breaks the first known noncanonical custody append before admission. Existing canonical28 subsume specialized semantics only; they do not subsume custody of other known records. A future reviewer will most likely question schema/validator drift and whether generic custody was wrongly presented as validation of every kind-specific business rule. The owner API must distinguish structural/classification admissibility from richer semantic assertions.

## 6. Findings and dispositions

**F1 — CONCERN / named-seam / RESHAPE before code.** Freeze a separately named generic full-record schema and exact WOS-owned helper input/output/error behavior. Do not reuse or relax canonical `FactsTierRecord`: it explicitly forbids `recordKind` (`wos-workflow.schema.json:4420–4425`). The generic schema must declare which record fields and extension policy it admits. The API remains WOS-neutral with respect to Trellis types and returns/retains the original record value. This is the remaining prerequisite; the lead reports owner agreement on location, not a completed API/schema freeze.

**F2 — OBSERVATION / commitment / KEEP.** Preserve canonical28 exactly; generic wrapper supports only known remaining kinds and rejects canonical bypass. Use enum classification, not a106-entry copied list. Cite kind.rs:472–520 and current custody.rs:270–318.

**F3 — OBSERVATION / ownership / KEEP.** Admission, client producer and offline WOS interpretation reuse the same WOS helper. Update registry specs and composition together so advertised support matches actual routing; current specs and routing use the canonical slice (admission lib:62–87; composition.rs:214–226). Keep ServiceOnly and existing budget/schema metadata discipline for the new event.

**F4 — OBSERVATION / scope / REVERSE.** Reject any claim that typed `ProvenanceRecord` deserialization alone checks lossless original shape, or that generic custody equals specialized semantic validation/full D1 proof. Cite record.rs:641–715 and WOS verification spec:13–43.

**F5 — OBSERVATION / scope / DEFER.** Implementation awaits the owner API/schema freeze; then review a private owner-coordinated patch with targeted preservation, unknown-field/kind, canonical-bypass, malformed timestamp/id and admission/offline parity cases. No native execution or live operation follows from this BEFORE review.

## 7. Verdict

```text
VERDICT: APPROVE refined decision shape; implementation deferred pending F1
Intent vs. shape: MATCHES — one neutral custody event preserves known original records.
User-value claim: SUPPORTED — closes verified producer/admission vocabulary mismatch.
Commitment status: HONORED if separate generic schema and shared validator are frozen.
Conceptual debt delta: PAYS DOWN — one maintained rule replaces divergent fallback vocabulary.
Sibling subsumption: PARTIAL — canonical events retain their specialized semantics.
Confidence: HIGH on inspected boundaries; MEDIUM on unimplemented API/schema details.
```

No implementation, execution, transport success, completed history, private material or real-record result is certified here. The actual OnEntry incident and134/106 inventory remain owner-reported context; static source confirms the underlying mismatch independently.

## Agreed API addendum — private adapter preparation

The lead subsequently confirmed owner agreement on `WOS_NATIVE_PROVENANCE_EVENT_LITERAL = "wos.provenance.recorded"` and `NativeProvenanceEvent::from_dcbor_slice(&[u8]) -> Result<Self, ...>`. The shared decoder/validator owns exact wrapper and record fields, required id/kind/timestamp/auditLayer/definitionVersion, RFC3339 timestamp validation, bounded open JSON data, and the rule that the explicit known kind has no canonical mapping. The generic schema is separate from canonical FactsTierRecord. This resolves F1 sufficiently for thin private adapter preparation; no additional user approval is required.

**APPROVE private source preparation now:** the Trellis WOS offline adapter compares only the shared literal and delegates readable payload bytes to the shared `from_dcbor_slice` helper, reporting its errors through the existing domain-finding mechanism. No local record parser, field list,106-kind list, JSON normalization or fallback acceptance belongs in that adapter. Private candidate path: `/private/tmp/integrity-native-provenance-v1-20261009/candidate/trellis/crates/trellis-verify-wos`. Original shared-checkout files remain untouched. Narrow negative test preparation is in scope; builds remain outside this grant.

Actual shared-helper qualification remains pending independent AFTER inspection. In particular, inspect that all supported serialized record fields are covered by the frozen field list; duplicate CBOR map keys are refused before any JSON-map conversion can erase them; unsupported tags/bytes/nontext keys and depth violations refuse; and the original decoded JSON value, not a canonicalized replacement, reaches strict validation. Maintained canonicalization may validate a discarded clone, but cannot recover duplicate evidence already lost in an earlier lossy conversion. The parent reports a decode/JSON-subset/maintained-validation/original-view plan; its exact ordering and limits require source evidence before any execution or preservation claim.

This addendum updates the earlier implementation deferral: owner-coordinated thin private adapter source/test preparation is approved, while helper correctness, runtime qualification, builds and live use remain unqualified. The shape verdict remains APPROVE.

# Section signing v1: byte design awaiting repeat-identity handoff

Status: proposed preimplementation shape for integrity-stack-T7, not an enabled profile or valid vector set. Formspec producer pin: `1952ce8e5d5a3085398885e915765f66b1b4a852`. Whole-response signing remains unchanged.

## Existing scope and proposed bytes

Authority: Formspec Core §2.1.6 Section-Signature Scope and §4.8.5, accepted D-003. One party signs only its explicit Field values. Covered paths are a set of canonical dot paths relative to Response.data. Paths must resolve to Fields under the pinned Definition and retained signed Response revision. Attachments are complete field values; signed file references do not prove retained binary contents.

Proposed bytes reuse `integrity_canonical::domain_separated_canonical_bytes` and `compute_digest`:

`UTF8("formspec.response.section-signed-payload.v1") || 0x00 || JCS(payload)`

Proposed payload properties:

- `responseId`, `definitionUrl`, `definitionVersion`: strings copied from the retained signed Response; signature pins must agree exactly.
- `partyRole`: the signature's declared role; semantic validator must confirm role, signer authority and coverage policy.
- `signedAt`, `signingIntent`: exact signature signedPayload strings; the top-level signature signingIntent must agree.
- `coveredPaths`: unique nonempty canonical paths sorted by ASCII order (accepted grammar is ASCII). Input order is immaterial; duplicates are errors.
- `values`: object keyed by each covered path, whose value is lowercase SHA-256 hex of JCS of the complete resolved field value. Null is a value; missing is an error. No entire-Response hash or unrelated field value is included.
- `consentAccepted`, `consentTextRef`, `consentVersion`, `affirmationText`, `documentId`, `documentHash`, `documentHashAlgorithm`: exact existing signature evidence fields; binding them prevents replacement of the declared consent, affirmation or surface after signing. Referenced text/binary retention still needs separate integrity checks.
- `repeatBindings`: proposed object keyed by each covered path's indexed repeat ancestor (for example `parents[0]`), whose value is that logical instance's stable identifier. Include every ancestor for nested repeats. Nonrepeat signatures use an empty object. **Cannot finalize this property until Formspec supplies a portable source for stable instance identity.**

Outer digest is SHA-256 of the framed bytes. Values use existing JCS and SHA-256 libraries; no new signature algorithm or method URI is introduced. COSE signing remains the maintained method-registry operation and is outside this byte-only output. No signatureValue, digest, receipt, mutable collection of signatures or whole-Response revision digest enters this payload.

Signing revision retention and replacements remain host obligations. Retaining an immutable snapshot permits original signature reconstruction; stable identity also prevents accepting that original signature against a current response where a different instance occupies its covered index.

The API should accept retained signed Response and signature inputs, return the existing `SignedPayload` result type, and compare current section inputs to original inputs to report changed paths. Definition-aware checks stay with Formspec. An error or changed scope must never be interpreted as a valid signature.

## Producer gap and concrete handoff recommendation

The accepted Response schema stores repeated groups as arrays and paths as indexes. It has no stable repeat-instance identifiers or signature-bound revision identifier. The metadata shape is closed; an undocumented new metadata member is not a conformant solution. Two different parents with identical income/family-size values can be reordered without changing a path/value-only digest. Retention alone cannot distinguish the logical people when the current wire data and signed selected values are equal. Hashing the whole row/Response to infer identity incorrectly binds unrelated section data and still cannot distinguish fully equal rows.

Recommendation for Formspec owner review through the lead:

1. Add an optional explicit top-level `Response.repeatMemberIds` map from each concrete repeat-member path (e.g. `parents[0]`, `parents[0].children[0]`) to a nonempty opaque stable identifier. IDs must be unique within the Response and preserved with the logical instance on insertion/deletion/reorder; deleted identifiers must not be reused. Every covered indexed ancestor needs a binding in both signed and current revisions. Missing/malformed identity for a covered repeat fails closed. Other members need not affect that section's bytes.
2. State that a signature's indexed path binds the ancestor IDs from the retained signed Response revision and must match those at the same resolved paths in the current Response. Do not reuse an ID for a new logical instance. The host must preserve these maps in signed revisions and exports and enforce attribution/atomic acceptance.
3. Integrity copies only selected ancestor bindings into `repeatBindings`. An insert before a signed row or reorder changes its ancestor binding, requiring a new signature for the revised covered path even if selected values coincide. An unrelated nonrepeat edit or appending an unrelated row does not change selected bindings.
4. Clarify normative binding of the existing consent/affirmation and signing-surface fields listed above; their schema shapes already exist. Add positive/negative schema and semantic fixtures for stable IDs, duplicate/missing maps, nested repeats, equal-valued row reorder and replacement-history preservation; regenerate derived outputs through Formspec owner.

This is a recommendation, not a landed schema change. The lead must route it to the Formspec producer before byte format finalization; this session must not edit sibling schemas/specs.

## Prior art and independent reference

- RFC 8785 JCS defines deterministic JSON serialization, Unicode preservation, UTF-16 property ordering and interoperable number constraints: https://www.rfc-editor.org/rfc/rfc8785 . Reuse integrity-canonical's canonical JSON writer (RFC 8785 with exact decimal numbers) and SHA-2 0.10; avoid another serializer/crypto implementation.
- Installed independent Python reference `rfc8785` 0.1.4 (Trail of Bits: https://github.com/trailofbits/rfc8785.py) plus standard-library hashlib. Existing Python `jcs` 0.2.1 supplies an additional oracle when needed. No installation ran. They do not import Rust or read expected vector bytes to derive payloads.
- RFC 9535 JSONPath: https://www.rfc-editor.org/rfc/rfc9535 . General query expressions are intentionally not used: accepted Formspec paths are a closed concrete-path grammar, not queries/wildcards. A small grammar/parser is project-owned glue, while canonical serialization/hashing use maintained packages.
- No maintained crypto package can infer logical identity from equal JSON values. This is a producer representation issue, not a missing cryptographic primitive.

After producer resolution, vectors should independently compare canonical JSON, framed bytes, value digests and outer SHA-256. Negatives: covered changes/missing values; role/scope/pins/time/intent mismatch; empty/duplicate/noncanonical paths; whole attachment changes; equal-valued repeat retargeting; nested repeats. Positives: unrelated sections, equivalent scope order, re-signing, Unicode/numeric JCS edges and unchanged whole-response vectors. Illustration digests from Formspec fixtures are never promoted as expected bytes.

## Independent preimplementation review

Reviewer `t7_scope_review` (gpt-6.1-sol, medium) returned RECONSIDER on the initial path/value-only proposal: repeat retargeting is a blocker and unsigned consent/surface evidence is a concern. This draft now incorporates its narrow `repeatMemberIds` and evidence-binding recommendation. Producer review/landing remains required; no byte implementation or valid vectors have shipped. Evidence: Core :880-899, response schema :418 and :529, ADR 0155 :179-186.

Follow-up independent review: APPROVE for the revised proposed shape, conditional on an accepted Formspec producer commit before code/vector freezing. No unresolved design finding remains; producer lifecycle and runtime checks remain required. Reviewer inspected experiment outputs statically and ran no tests.

# @formspec-org/integrity-canonical

Produces the full-Response intake handoff bytes defined by Rust `integrity-canonical::canonical_response_handoff_bytes`. It preserves every JSON member, including `authoredSignatures`. `canonicalResponseSignedPayloadBytes` produces the distinct whole-response signing preimage by omitting only the entire top-level `authoredSignatures` member. Section signing remains outside this package.

```ts
import { canonicalResponseHandoffBytes } from '@formspec-org/integrity-canonical';

const bytes = canonicalResponseHandoffBytes(canonicalResponse);
if (!globalThis.crypto?.subtle) throw new Error('SHA-256 is unavailable');
const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes);
const responseHash = 'sha256:' + Array.from(new Uint8Array(hash),
  byte => byte.toString(16).padStart(2, '0')).join('');
```

Both exported functions accept `unknown` and return `Uint8Array<ArrayBuffer>`. Inputs must be actual JSON objects: plain or null-prototype objects containing strings, finite numbers, `JSON.rawJSON` numbers, booleans, null, ordinary dense arrays and other plain objects. It refuses cycles, undefined/functions/symbols/BigInt, accessors or inherited serialization hooks, class/boxed objects, nonenumerable/symbol properties, sparse/extended arrays and malformed Unicode. It does not validate the Formspec Response schema. The caller must parse untrusted wire JSON with a duplicate-member refusal policy before calling this object API; parsing may otherwise discard duplicates before byte generation sees them.

Bytes are UTF-8 of `formspec.response.handoff.v1`, one NUL byte, then `integrity-canonical-json-v1` of the complete object: RFC 8785 JCS, except that a number is written as its exact decimal value in `Number::toString` layout rather than first rounded to a double. A JS number therefore serializes exactly as RFC 8785 says, because its text is the shortest decimal that round-trips to it. Longer text differs: `JSON.rawJSON('1152921504606846976')` (2^60 written out) stays as written, while RFC 8785 writes 1152921504606847000. A Formspec decimal with more digits than a double holds (Core §3.4.1 requires at least 18) survives only as a `JSON.rawJSON` number. `parseJsonExact(text)` parses wire JSON that way, keeping a number as a JS number when its text is that number's own text. A nonzero number that binary64 round-to-nearest-even takes to zero (magnitude ≤ 2^−1075) or to infinity (magnitude ≥ 2^1024 − 2^970) is refused, as RFC 8785 refuses non-finite values. The decision reads the digits alone, never `Number()`, so Rust, TypeScript and Python agree (`tests/fixtures/canonical-numbers`). Strings are escaped by `JSON.stringify` and member names ordered by the default UTF-16 sort, both as RFC 8785 specifies. No cryptographic primitive is included. SHA-256 belongs to the caller's genuine crypto provider; never use a fallback hash labeled SHA-256.

Runtime requirements: Node 22 or a browser with `TextEncoder` and `String.prototype.isWellFormed`; `parseJsonExact` and raw numbers also need JSON.parse source text access (`JSON.rawJSON`). Browser WebCrypto availability is a separate caller requirement for hashing. The package has no runtime dependencies.

Build, tests and typecheck use the repository's installed npm workspace tools:

```sh
npm run build -w packages/integrity-canonical
npm run test -w packages/integrity-canonical
npm run typecheck -w packages/integrity-canonical
```

Byte fixtures shared with the Rust authority live at `tests/fixtures/response-handoff/vectors.json`. Both runtimes read each input as text: TypeScript through `parseJsonExact`, Rust through `canonical_response_handoff_bytes_from_json`. Rust parity runs with `cargo test --offline --locked -p integrity-canonical --test response_handoff_vectors`. Python fixture reproduction, input scope and oracle provenance are documented beside those fixtures.

For `signedPayload.digest`, use the signing export and genuine SHA-256. The digest is lowercase hex without the handoff's `sha256:` prefix:

```ts
import { canonicalResponseSignedPayloadBytes } from '@formspec-org/integrity-canonical';
const bytes = canonicalResponseSignedPayloadBytes(fullResponse);
if (!globalThis.crypto?.subtle) throw new Error('SHA-256 is unavailable');
const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes);
const digest = Array.from(new Uint8Array(hash),
  byte => byte.toString(16).padStart(2, '0')).join('');
```

Signing bytes match Rust `canonical_response_signed_payload_bytes_from_json` / `build_signed_payload_from_json`: UTF-8 `formspec.response.signed-payload.v1`, one NUL byte, then the canonical JSON of the Response with only top-level `authoredSignatures` omitted. Every other member remains, including nested members of that name. Both APIs snapshot validated own data descriptors recursively before serialization or omission, including malformed Unicode within omitted signatures; neither mutates the input. The serializer receives only the admitted snapshot, preventing later Proxy value reads or serialization hooks from replacing checked data. Descriptor inspection can itself execute Proxy traps; this API is not an isolation boundary for executable JavaScript. Byte production performs no hashing, signing, verification or Response schema validation. The caller supplies all required signing metadata pins separately.

Shared independent signing vectors live at `tests/fixtures/response-signing/vectors.json`. Rust parity uses `cargo test --offline --locked -p integrity-canonical --test response_signing_vectors`.

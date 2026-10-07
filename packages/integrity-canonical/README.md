# @formspec-org/integrity-canonical

Produces the full-Response intake handoff bytes defined by Rust `integrity-canonical::canonical_response_handoff_bytes`. It preserves every JSON member, including `authoredSignatures`. It does not produce the distinct whole-response signing preimage or section-signing bytes.

```ts
import { canonicalResponseHandoffBytes } from '@formspec-org/integrity-canonical';

const bytes = canonicalResponseHandoffBytes(canonicalResponse);
if (!globalThis.crypto?.subtle) throw new Error('SHA-256 is unavailable');
const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes);
const responseHash = 'sha256:' + Array.from(new Uint8Array(hash),
  byte => byte.toString(16).padStart(2, '0')).join('');
```

The single exported function accepts `unknown` and returns `Uint8Array<ArrayBuffer>`. Inputs must be actual JSON objects: plain or null-prototype objects containing strings, finite numbers, booleans, null, ordinary dense arrays and other plain objects. It refuses cycles, undefined/functions/symbols/BigInt, accessors or inherited serialization hooks, class/boxed objects, nonenumerable/symbol properties, sparse/extended arrays and malformed Unicode. It does not validate the Formspec Response schema. The caller must parse untrusted wire JSON with a duplicate-member refusal policy before calling this object API; parsing may otherwise discard duplicates before byte generation sees them.

Bytes are UTF-8 of `formspec.response.handoff.v1`, one NUL byte, then RFC 8785 JCS of the complete object. Serialization uses exact `canonicalize@5.1.0`; the input guard prevents its JSON.stringify-compatible omission, coercion and `toJSON` behavior from silently changing non-JSON runtime data. No custom sorter or cryptographic primitive is included. SHA-256 belongs to the caller's genuine crypto provider; never use a fallback hash labeled SHA-256.

Runtime requirements: Node 22 or a browser with `TextEncoder` and `String.prototype.isWellFormed`. Browser WebCrypto availability is a separate caller requirement for hashing. Consumers vendoring this package must honor its exact dependency and resolve `canonicalize@5.1.0` through the package manifest; an older application dependency cannot substitute for it.

Build, tests and typecheck use the repository's installed npm workspace tools:

```sh
npm run build -w packages/integrity-canonical
npm run test -w packages/integrity-canonical
npm run typecheck -w packages/integrity-canonical
```

Byte fixtures shared with the Rust authority live at `tests/fixtures/response-handoff/vectors.json`. Rust parity runs with `cargo test --offline --locked -p integrity-canonical --test response_handoff_vectors`. Python fixture reproduction, input scope and oracle provenance are documented beside those fixtures.

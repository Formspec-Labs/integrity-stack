# Whole-Response signing parity fixtures

`vectors.json` is shared by TypeScript and existing Rust signing-byte authority. `generate.py` independently derives complete preimages and SHA-256 with `rfc8785` 0.1.4 and Python hashlib; it imports no Rust/TypeScript implementation and reads no expected output to derive bytes. Reproduce with a Python interpreter containing that reference package.

Vectors pin the existing Rust example, signature omission across absent/null/object/array/co-signature inputs, preservation of metadata/extensions/locale/issuer/IDs/time/nested signature names and unusual JSON keys, UTF-16 key ordering and number formatting. Wire negatives cover root shape, invalid JSON and malformed Unicode, including malformed strings/keys inside omitted signatures. Constructed runtime negatives are checked separately in TypeScript. Object APIs require caller duplicate-wire-member refusal before parsing.

Synthetic signature members prove omission and stability only; these fixtures establish no signing act, signature verification, or schema validity. Signing bytes are `formspec.response.signed-payload.v1 || NUL || JCS(response without top-level authoredSignatures)`; handoff uses its separate domain and retains the entire Response.

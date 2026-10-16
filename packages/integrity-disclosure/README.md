# `@formspec-org/integrity-disclosure`

RFC 9901 SD-JWT selective disclosure over generic JSON claims: issue, present an allowlisted subset, and verify offline against a pinned `(iss, kid, key)`. Byte-identical to the `integrity-disclosure` Rust crate (shared vectors in `tests/fixtures/selective-disclosure`).

```sh
npm install @formspec-org/integrity-disclosure
```

- Wire: `application/sd-jwt`, `<issuer-jwt>~<disclosure>~...~`. Flat object-property disclosures only; no key binding.
- Issuer JWT: Ed25519 (`EdDSA`) over `b64(header).b64(payload)`, header and payload as JCS.
- Disclosure: `base64url(JCS([salt, path, value]))`, salt = 128 bits of CSPRNG output.
- `_sd` is sorted and padded with decoy digests to a power of two.
- Numbers are IEEE doubles, as in JCS; show `valueJcs`, never a re-serialized number.

Part of [integrity-stack](https://github.com/Formspec-Labs/integrity-stack). Apache-2.0.

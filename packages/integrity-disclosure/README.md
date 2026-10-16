# `@formspec-org/integrity-disclosure`

RFC 9901 SD-JWT selective disclosure over generic JSON claims: verify offline against a pinned `(iss, kid, key)`. Issuing and presenting are the `integrity-disclosure` Rust crate's job; this package agrees with it byte for byte (shared vectors in `tests/fixtures/selective-disclosure`, which a test-only TS issuer reproduces).

```sh
npm install @formspec-org/integrity-disclosure
```

- Wire: `application/sd-jwt`, `<issuer-jwt>~<disclosure>~...~`. Flat object-property disclosures only; no key binding.
- Issuer JWT: Ed25519 (`EdDSA`) over `b64(header).b64(payload)`, header and payload as JCS.
- Disclosure: `base64url(JCS([salt, path, value]))`, salt = 128 bits of CSPRNG output.
- Use `encoding: 'pinned'` for presentations this stack issued (the viewer and CLI do). `'rfc9901'` accepts other issuers' encodings and normalises values.
- Claim paths in `REFUSED_CLAIM_NAMES` (RFC 7519 names, `cnf`, `vct`, `status`, `Object.prototype` members, SD-JWT structure names) are refused.
- `_sd` is sorted and padded with decoy digests to a power of two.
- Numbers are IEEE doubles, as in JCS; show `valueJcs`, never a re-serialized number.

Part of [integrity-stack](https://github.com/Formspec-Labs/integrity-stack). Apache-2.0.

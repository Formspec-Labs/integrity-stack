# Integrity Stack

Shared integrity primitives for the Formspec stack: canonical encoding and hashing, COSE signing and
verification, HPKE, bundle IO, and the verification tools that let anyone check a signed artifact
without contacting its publisher. Consumed by [Formspec](https://github.com/Formspec-Labs/formspec),
Trellis and the Workflow Orchestration Standard; the rest of the stack is indexed from
[formspec-stack](https://github.com/Formspec-Labs/formspec-stack).

## Packages

npm, published from this repository (`@integrity-stack/*`):

| Package | What it is |
|---|---|
| [`@integrity-stack/signature-port`](packages/integrity-signature-port) | The signature verifier port and the verification receipt types every adapter returns. |
| [`@integrity-stack/cose`](packages/integrity-cose) | COSE_Sign1 byte helpers and method dispatch enforcement. |
| [`@integrity-stack/signature-adapter-webcrypto`](packages/integrity-signature-adapter-webcrypto) | The port implemented on WebCrypto, for browsers and Node. |

Rust crates live under [`crates/`](crates/) (`integrity-*`; see `Cargo.toml` for the workspace members) and
are consumed by sibling path from the stack checkout.

## Build and test

```sh
npm install && npm test          # builds the packages, then runs every workspace's suite
cargo nextest run --workspace    # the crates
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

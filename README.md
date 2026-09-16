# Integrity Stack

Shared integrity primitives for the Formspec stack: canonical encoding and hashing, COSE signing and
verification, HPKE, bundle IO, and the verification tools that let anyone check a signed artifact
without contacting its publisher. Consumed by [Formspec](https://github.com/Formspec-Labs/formspec),
Trellis and the Workflow Orchestration Standard; the rest of the stack is indexed from
[formspec-stack](https://github.com/Formspec-Labs/formspec-stack).

## Packages

npm, published from this repository under the stack's `@formspec-org` scope:

| Package | What it is |
|---|---|
| [`@formspec-org/integrity-signature-port`](packages/integrity-signature-port) | The signature verifier port and the verification receipt types every adapter returns. |
| [`@formspec-org/integrity-cose`](packages/integrity-cose) | COSE_Sign1 byte helpers and method dispatch enforcement. |
| [`@formspec-org/integrity-signature-adapter-webcrypto`](packages/integrity-signature-adapter-webcrypto) | The port implemented on WebCrypto, for browsers and Node. |

Rust crates live under [`crates/`](crates/) (`integrity-*`; see `Cargo.toml` for the workspace members) and
are consumed by sibling path from the stack checkout. The three `integrity-verify*` crates reach the
`trellis` and `stack-common` siblings by path, so they sit outside the default workspace and build where
those siblings are checked out (`cargo nextest run --manifest-path crates/<crate>/Cargo.toml`).

## Build and test

```sh
npm install && npm test          # builds the packages, then runs every workspace's suite
cargo nextest run --workspace    # the crates
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

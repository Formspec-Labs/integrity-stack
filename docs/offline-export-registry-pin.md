# Offline export registry selection

The optional `verify-export --trusted-signing-key-registry-sha256 <64 lowercase hex>` check binds verification to the exact signing-key registry snapshot selected independently by the operator. It does not establish agency authority, signer identity, registry freshness or authorization to disclose the archive. A digest copied from the archive itself supplies no independent origin evidence.

The CLI reads the archive once. It uses the maintained STORED ZIP reader to locate exactly one member whose relative name after the export root is `030-signing-key-registry.cbor`, hashes its unchanged bytes with maintained SHA-256, and refuses a missing, duplicate or mismatching registry before reporting success. It then runs the unchanged `trellis_verify_wos::verify_export_zip` on the same ZIP bytes. The registry may contain historical rotated keys. Every existing manifest, event, checkpoint, inclusion, consistency and WOS-domain check remains required.

Text and JSON results distinguish `matched` from `not_requested`, and show the expected and observed registry digest when selected. Existing `verified` continues to describe the maintained archive verification; a mismatch causes nonzero exit before a success report. Invalid digest syntax and duplicate selection flags are errors. This adds no archive format, deployment trust profile or library API.

## Runnable operations and evidence dependencies

The existing command is `integrity-verify verify-export <actual.zip> --format json`. After this private source change is compiled and qualified in a coordinated native-build window, the pinned form adds `--trusted-signing-key-registry-sha256 <independent snapshot digest>`. Do not pass this flag to the old installed binary or represent prepared tests as executed.

Runtime must first create genuine records for correction, replacement, decision, checks, clocks, notices and original signed evidence under the permitted current case scope. A coordinated native Trellis head request can publish an archive; its actual checkpoint then selects the pinned bundle retrieval. Preserve exact ZIP bytes and independently selected registry provenance before the offline run. An empty scope supplies no archive, and a successful synthetic fixture cannot establish real D1 coverage.

Current boundaries: Trellis owns service evidence-member composition; WOS owns current output grants and native custody producers. This CLI change creates neither missing events nor member bytes and does not change service configuration, keys or accepted originals. Python/Rust library entry points retain their existing embedded-registry semantics; this explicit operator gate is a CLI-only capability.

## Verification scope

Prepared Rust unit and integration cases cover strict argument parsing, exact member selection, wrong and foreign snapshots, omitted selection, missing/duplicate/malformed members, and matching registry bytes with an invalid archive. Native compilation and execution remain pending coordination. Static independent code and architecture reviews must identify that limitation explicitly.

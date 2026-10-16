#!/usr/bin/env bash
# Runs the crypto-ownership fence (deny.toml) over the default workspace and over the three
# excluded verification crates, which reach the trellis and work-spec siblings by path and so only
# exist where those siblings are checked out. In a lone checkout only the workspace is checked.
set -euo pipefail
cd "$(dirname "$0")/.."

manifests=(Cargo.toml)
if [ -d ../trellis ] && [ -d ../work-spec ]; then
  manifests+=(crates/integrity-verify/Cargo.toml crates/integrity-verify-cli/Cargo.toml crates/integrity-verify-parity/Cargo.toml)
else
  echo "deny-bans: trellis/work-spec siblings absent; checking the default workspace only" >&2
fi

for manifest in "${manifests[@]}"; do
  echo "deny-bans: $manifest"
  cargo deny --manifest-path "$manifest" check --config deny.toml bans
done

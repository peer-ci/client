#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo build -q

BIN="./target/debug/peer-ci"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Force required failure by ensuring firecracker/jailer are not found.
if XDG_CACHE_HOME="$tmp" PATH="/nonexistent" "$BIN" doctor >/dev/null 2>&1; then
  echo "expected 'peer-ci doctor' to fail, but it exited 0" >&2
  exit 1
fi

echo "ok"

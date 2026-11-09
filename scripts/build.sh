#!/usr/bin/env bash
# Build one binary: no cgo, no local paths, -mod=readonly, version embedded, commit stamped by Go.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-dist/debuff}
mkdir -p "$(dirname "$out")"
CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -trimpath -ldflags "-s -w" -o "$out" ./cmd/debuff
echo "$out"

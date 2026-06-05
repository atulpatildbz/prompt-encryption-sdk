#!/usr/bin/env bash
# Build the WASM filter and start Envoy (Docker, arm64 native on M4).
set -euo pipefail
cd "$(dirname "$0")"

WASM_TARGET="${WASM_TARGET:-wasm32-wasip1}"
# Pin this to your TARGET Envoy tag — version skew is OPEN #2.
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.34-latest}"
# Prefer podman, fall back to docker. Override with CONTAINER_RUNTIME.
RUNTIME="${CONTAINER_RUNTIME:-$(command -v podman || command -v docker)}"

# Use the rustup toolchain explicitly (Homebrew's rustc may be broken).
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> Building WASM filter ($WASM_TARGET)"
rustup target add "$WASM_TARGET" >/dev/null 2>&1 || true
cargo build --release --target "$WASM_TARGET"

WASM_FILE="target/$WASM_TARGET/release/attest_filter.wasm"
[ -f "$WASM_FILE" ] || { echo "ERROR: wasm not built at $WASM_FILE"; exit 1; }
echo "==> Built $WASM_FILE"

echo "==> Starting Envoy via $RUNTIME ($ENVOY_IMAGE): :10000 (write) / :10001 (no-write) / :9901 (admin)"
echo "    Watch for [L4]/[L7] 'wasm log' lines below."
exec "$RUNTIME" run --rm -it \
  --entrypoint /usr/local/bin/envoy \
  -v "$PWD/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  -v "$PWD/$WASM_FILE:/etc/envoy/attest_filter.wasm:ro" \
  -p 10000:10000 -p 10001:10001 -p 9901:9901 \
  "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --log-level info

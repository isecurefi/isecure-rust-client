#!/bin/sh
set -eu

cargo fmt --all --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --no-default-features --target wasm32-wasip2 -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
cargo build --locked --release
cargo build --locked --release --no-default-features --target wasm32-wasip2 --lib
cargo audit --no-fetch --ignore RUSTSEC-2023-0071
scripts/generate-sbom.sh
git diff --exit-code -- sbom.cdx.json

if [ -n "${WASMTIME_BIN:-}" ] && [ -n "${WASM_TOOLS_BIN:-}" ]; then
    scripts/test-wasm.sh
else
    echo "WASMTIME_BIN and WASM_TOOLS_BIN are required for the real Wasm gate" >&2
    exit 2
fi

#!/bin/sh
set -eu

wasmtime_bin=${WASMTIME_BIN:-}
if [ -z "$wasmtime_bin" ]; then
    wasmtime_bin=$(command -v wasmtime || true)
fi
if [ -z "$wasmtime_bin" ] || [ ! -x "$wasmtime_bin" ]; then
    echo "WASMTIME_BIN must name an executable Wasmtime binary" >&2
    exit 2
fi

cargo build --locked --release --target wasm32-wasip2 --example wasm_contract
"$wasmtime_bin" run -C cache=n target/wasm32-wasip2/release/examples/wasm_contract.wasm

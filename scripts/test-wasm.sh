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
wasm_tools_bin=${WASM_TOOLS_BIN:-}
if [ -z "$wasm_tools_bin" ] || [ ! -x "$wasm_tools_bin" ]; then
    echo "WASM_TOOLS_BIN must name an executable wasm-tools binary" >&2
    exit 2
fi

artifact=$(WASM_TOOLS_BIN="$wasm_tools_bin" scripts/audit-wasm.sh)
"$wasmtime_bin" run -C cache=n "$artifact"

#!/bin/sh
set -eu

wasm_tools_bin=${WASM_TOOLS_BIN:-}
if [ -z "$wasm_tools_bin" ] || [ ! -x "$wasm_tools_bin" ]; then
    echo "WASM_TOOLS_BIN must name an executable wasm-tools binary" >&2
    exit 2
fi

artifact=target/wasm32-wasip2/release/examples/wasm_contract.wasm
maximum_bytes=${MAX_WASM_CONTRACT_BYTES:-400000}
case "$maximum_bytes" in
    ''|*[!0-9]*)
        echo "MAX_WASM_CONTRACT_BYTES must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "$maximum_bytes" -eq 0 ]; then
    echo "MAX_WASM_CONTRACT_BYTES must be a positive integer" >&2
    exit 2
fi

cargo build --locked --release --target wasm32-wasip2 --example wasm_contract
"$wasm_tools_bin" validate "$artifact"

actual_bytes=$(wc -c < "$artifact" | tr -d ' ')
if [ "$actual_bytes" -gt "$maximum_bytes" ]; then
    echo "Wasm contract is $actual_bytes bytes; budget is $maximum_bytes" >&2
    exit 1
fi

temporary=$(mktemp "${TMPDIR:-/tmp}/isecure-wasm-imports.XXXXXX")
cleanup() {
    rm -f -- "$temporary"
}
trap cleanup EXIT HUP INT TERM
"$wasm_tools_bin" component wit "$artifact" \
    | sed -n 's/^  import \([^;]*\);$/\1/p' \
    | LC_ALL=C sort > "$temporary"
diff -u contracts/wasm-contract-imports.txt "$temporary"

if grep -Eq '^wasi:(clocks|filesystem|http|random|sockets)/' "$temporary"; then
    echo "Wasm contract gained a forbidden ambient capability" >&2
    exit 1
fi

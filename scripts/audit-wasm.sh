#!/bin/sh
set -eu

example=${1:-wasm_contract}
case "$example" in
    wasm_contract|wasm_auth_rejections) ;;
    *) echo "unsupported contract example" >&2; exit 2 ;;
esac

wasm_tools_bin=${WASM_TOOLS_BIN:-}
if [ -z "$wasm_tools_bin" ] || [ ! -x "$wasm_tools_bin" ]; then
    echo "WASM_TOOLS_BIN must name an executable wasm-tools binary" >&2
    exit 2
fi

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

messages=$(mktemp "${TMPDIR:-/tmp}/isecure-wasm-messages.XXXXXX")
imports=$(mktemp "${TMPDIR:-/tmp}/isecure-wasm-imports.XXXXXX")
cleanup() {
    rm -f -- "$messages" "$imports"
}
trap cleanup EXIT HUP INT TERM

cargo build --locked --release --target wasm32-wasip2 --example "$example" \
    --message-format=json-render-diagnostics > "$messages"
artifact=$(jq -r --arg example "$example" '
    select(.reason == "compiler-artifact")
    | select(.target.name == $example)
    | select(.target.kind | index("example"))
    | .filenames[]
    | select(endswith(".wasm"))
' "$messages" | tail -n 1)
if [ -z "$artifact" ] || [ ! -f "$artifact" ]; then
    echo "Cargo did not report the Wasm contract artifact" >&2
    exit 1
fi
"$wasm_tools_bin" validate "$artifact"

actual_bytes=$(wc -c < "$artifact" | tr -d ' ')
if [ "$actual_bytes" -gt "$maximum_bytes" ]; then
    echo "Wasm contract is $actual_bytes bytes; budget is $maximum_bytes" >&2
    exit 1
fi

"$wasm_tools_bin" component wit "$artifact" \
    | sed -n 's/^  import \([^;]*\);$/\1/p' \
    | LC_ALL=C sort > "$imports"
diff -u contracts/wasm-contract-imports.txt "$imports" >&2

if grep -Eq '^wasi:(clocks|filesystem|http|random|sockets)/' "$imports"; then
    echo "Wasm contract gained a forbidden ambient capability" >&2
    exit 1
fi

printf 'Verified %s: %s bytes; exact import allowlist.\n' "$example" "$actual_bytes" >&2
printf '%s\n' "$artifact"

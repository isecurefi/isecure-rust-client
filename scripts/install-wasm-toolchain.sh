#!/bin/sh
set -eu

destination=${1:?"usage: scripts/install-wasm-toolchain.sh DESTINATION"}
case "$destination" in
    /*) ;;
    *)
        echo "destination must be an absolute path" >&2
        exit 2
        ;;
esac
if [ -L "$destination" ]; then
    echo "destination must not be a symbolic link" >&2
    exit 2
fi
for executable in "$destination/wasmtime" "$destination/wasm-tools"; do
    if [ -e "$executable" ] || [ -L "$executable" ]; then
        echo "refusing to overwrite existing path: $executable" >&2
        exit 2
    fi
done

os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
    Darwin/arm64)
        wasmtime_asset=wasmtime-v48.0.0-aarch64-macos.tar.xz
        wasmtime_sha=b62f687c7b19dd7c04b44ba5d6170a92a2c99bfc190887348aee9323e3703e60
        wasm_tools_asset=wasm-tools-1.257.1-aarch64-macos.tar.gz
        wasm_tools_sha=1d1ced29aa8320733a7e27452434e66f9bcb61ce39a00ee63229594d71f8544d
        ;;
    Linux/x86_64)
        wasmtime_asset=wasmtime-v48.0.0-x86_64-linux.tar.xz
        wasmtime_sha=1d23a692da51a4f825698f3f999da71f28bad19a96df5395fadc8d07f162dac3
        wasm_tools_asset=wasm-tools-1.257.1-x86_64-linux.tar.gz
        wasm_tools_sha=acea0a6f71b15f3b2d394f97453398f29099cec52df93bb25741a22561639b24
        ;;
    *)
        echo "unsupported Wasm tool host: $os/$arch" >&2
        exit 2
        ;;
esac

temporary=$(mktemp -d "${TMPDIR:-/tmp}/isecure-wasm-tools.XXXXXX")
case "$temporary" in
    "${TMPDIR:-/tmp}"/isecure-wasm-tools.*) ;;
    *)
        echo "unexpected temporary directory" >&2
        exit 2
        ;;
esac
cleanup() {
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

wasmtime_archive="$temporary/$wasmtime_asset"
wasm_tools_archive="$temporary/$wasm_tools_asset"
curl --fail --silent --show-error --location \
    --output "$wasmtime_archive" \
    "https://github.com/bytecodealliance/wasmtime/releases/download/v48.0.0/$wasmtime_asset"
curl --fail --silent --show-error --location \
    --output "$wasm_tools_archive" \
    "https://github.com/bytecodealliance/wasm-tools/releases/download/v1.257.1/$wasm_tools_asset"

verify_sha256() {
    expected=$1
    file=$2
    if command -v shasum >/dev/null 2>&1; then
        printf '%s  %s\n' "$expected" "$file" | shasum -a 256 --check
    else
        printf '%s  %s\n' "$expected" "$file" | sha256sum --check
    fi
}
verify_sha256 "$wasmtime_sha" "$wasmtime_archive"
verify_sha256 "$wasm_tools_sha" "$wasm_tools_archive"

mkdir -p "$destination"
tar -xf "$wasmtime_archive" -C "$temporary"
tar -xf "$wasm_tools_archive" -C "$temporary"
cp "$temporary/${wasmtime_asset%.tar.xz}/wasmtime" "$destination/wasmtime"
cp "$temporary/${wasm_tools_asset%.tar.gz}/wasm-tools" "$destination/wasm-tools"
chmod 0755 "$destination/wasmtime" "$destination/wasm-tools"

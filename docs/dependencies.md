# Dependency review

Reviewed 2026-08-22. `Cargo.lock` pins every direct and transitive version. Direct requirements in
`Cargo.toml` use exact versions. Default features are removed from `rsa`; only PEM parsing and its
standard-library support are enabled.

`sbom.cdx.json` is the committed deterministic CycloneDX 1.6 inventory for the complete locked
native/test dependency graph. Regenerate it with `scripts/generate-sbom.sh`; verification rejects
drift.

## Production dependencies

| Crate | Exact version | Licence | Reason |
| --- | ---: | --- | --- |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | Encode RSA ciphertext and exact bank-file bytes for the REST wire. |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 | Define the caller-injected cryptographic RNG contract. It does not select an OS RNG. |
| `rsa` | 0.9.10 | MIT OR Apache-2.0 | Parse SPKI/PKCS#1 public keys and perform RSA-OAEP. |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Exact typed JSON models. |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 | Encode requests and strictly decode responses. |
| `sha1` | 0.10.7 | MIT OR Apache-2.0 | Required only by the provider's legacy RSA-OAEP SHA-1 protocol. It is not used for signatures or new hashes. |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT | Best-effort clearing of owned secret buffers. |

There is no production HTTP, TLS, filesystem, async-runtime, logging or AWS dependency. Native and
Wasm hosts supply those capabilities.

## Test-only dependencies

| Crate | Exact version | Licence | Reason |
| --- | ---: | --- | --- |
| `futures-executor` | 0.3.34 | MIT OR Apache-2.0 | Drive deterministic immediately-ready test futures. |
| `rand_chacha` | 0.3.1 | MIT OR Apache-2.0 | Reproducible RSA tests and securely seeded live-test RNG. |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | Verify pinned contract bytes and test RSA keys. |

All resolved licences are permissive (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`,
`Unicode-3.0`, `Unlicense`, or compatible combinations). The full resolved inventory is reproducible
with:

```sh
cargo metadata --locked --format-version 1 |
  jq -r '.packages | sort_by(.name)[] | select(.source != null) | [.name,.version,.license] | @tsv'
cargo tree --locked --edges normal
cargo audit --ignore RUSTSEC-2023-0071
```

Dependency changes require the same functional, security and simplicity reviews as source changes.

## Verification tools

The mandatory Wasm gate downloads only digest-pinned official archives:

- Wasmtime 48.0.0 for real `wasm32-wasip2` execution; and
- wasm-tools 1.257.1 for component validation and exact import inspection.

`scripts/install-wasm-toolchain.sh` records the admitted Apple ARM64 and Linux x86-64 archive
digests. These are verification tools, not crate dependencies or runtime capabilities.

## Reviewed advisory exception

`cargo audit` reports `RUSTSEC-2023-0071` for `rsa` 0.9.10 and says no fixed upgrade is available.
The Marvin timing attack concerns RSA private-key decryption. This SDK only parses a public key and
performs public-key OAEP encryption; it has no private-key or decryption API. The advisory is
therefore not reachable through this crate's use of `rsa`. The verification command names the exact
exception so any different advisory still fails. Recheck this decision whenever `rsa`, challenge
crypto or provider protocol behavior changes.

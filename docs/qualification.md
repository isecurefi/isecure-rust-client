# Qualification evidence

Status: SDK implementation evidence, not production-bank qualification or crate publication.

On 2026-08-22 the following passed locally on Apple ARM64 with Rust 1.94.1:

- exact pinned Swagger digest, 26-operation and 35-schema inventory checks;
- native formatting, strict warning-free Clippy, unit/integration/doc tests and release build;
- RSA-OAEP SHA-1 interoperability for both SPKI and PKCS#1 public keys;
- `wasm32-wasip2` release builds and real execution under official Wasmtime 48.0.0
  (`wasmtime-v48.0.0-aarch64-macos.tar.xz`, SHA-256
  `b62f687c7b19dd7c04b44ba5d6170a92a2c99bfc190887348aee9323e3703e60`);
- identical Wasm classifications for success, logical failure, HTTP failure, malformed response,
  cancellation and timeout; and
- an authorized privacy-safe `gpgtest` run in AWS account `589434896614`, `eu-west-1`, using one
  retained synthetic identity set: Admin RSA/TOTP authentication, Data RSA authentication, key
  listing and certificate listing passed without manual SMS or email verification.

The live run retained no customer values, tokens, codes, API keys, filenames, payloads, payload
hashes or provider response text as evidence. Its private mode-0600 fixture remains under ignored
`.live/` and is not qualification evidence by itself.

The deployed API returned `ExpiresIn` as a JSON number although the pinned Swagger declares a
string. The compatibility behavior is recorded in `contracts/observed-extensions.json`; the SDK
accepts only a non-negative integer in either JSON form.

The live check proves the current synthetic test endpoint only. It does not prove a real bank,
production availability, settlement, certification, customer credential custody or Connector/WASI
host qualification.

## Wasm-first hardening follow-up

Also on 2026-08-22, the SDK added and passed:

- typed URL, request, response, exact-file, signature and collection limits, including exact-boundary
  and maximum-plus-one cases;
- bounded request serialization and zeroization of complete and rejected temporary bodies;
- exact-byte upload and download with Base64 confined to the provider wire;
- one shared native/`wasm32-wasip2` runner for real RSA challenge encryption, authentication,
  upload/download, error classes, cancellation, timeout, host-owned retry and secret-safe debug;
- 10,000 deterministic response mutations and 4,000 URL/auth-transition mutations without a panic
  or permissive drift result;
- real Wasmtime 48.0.0 execution, wasm-tools 1.257.1 validation, the exact retained WASI command
  import allowlist, rejection of network/filesystem/HTTP/clock/random imports, and a measured
  355,567-byte artifact under the 400,000-byte budget; and
- the guarded synthetic `gpgtest` Admin-TOTP/Data authentication, key-list and certificate-list
  journey after the changes.

The repository now has a digest-pinned GitHub Actions gate for the same checks plus Rust 1.85.1
native and Wasm compilation. This records the workflow source; it does not claim a hosted run until
GitHub executes the commit. The command-component allowlist is test scaffolding, not the final
generated WIT Connector world or signed-plugin qualification.

The resolved three-pass findings are recorded in `docs/reviews.md`.

## Brokered Component facade follow-up

On 2026-08-25, the SDK added the brokered facade for the first ISECure registration,
authentication/MFA and parent connection-test package while retaining the direct native client.
The compatibility lock pins platform WIT source revision
`de7a15feb02b324d5f1c3d709ddddb722ad71b4c`, package
`isecure:connector-runtime@2.0.0` and exact WIT SHA-256
`60f02b20ce4a79a9fb4d4b3153ef3b603ad97d34f1cd5db36bf592db0343e2f2`.

Focused and full local checks prove:

- exact secret-free business plans and closed privileged preparation/capture mechanics;
- direct/brokered auth, verification, typed response and stable error parity;
- deterministic rejection of missing, extra, reordered, duplicate, wrong-operation, already-used and
  unavailable bindings or values before unauthorized work;
- no raw-secret or privileged-broker API in the business source and no transport/client capability in
  the privileged source;
- unchanged dependency graph and no SDK `unsafe` code; and
- `wasm32-wasip2` library compilation plus real Wasmtime 48.0.0 execution of the shared brokered
  contract runner. wasm-tools 1.257.1 validated the 352,201-byte Component under the 400,000-byte
  budget with the exact retained `wasi:cli`/`wasi:io` command-harness allowlist and no clock,
  filesystem, HTTP, random or socket import.

The command harness proves SDK Wasm code generation, execution and import stability. It is not the
generated production business/security WIT adapter, a signed package, host qualification or live
provider qualification; those remain platform and application tasks.

## Managed security Component follow-up

On 2026-08-27, the brokered core was made available as `no_std` plus `alloc` while the direct native
client remained the default `std` API. Strict Clippy and release builds passed for
`wasm32-wasip2` with default features disabled. The platform's real ISECure security Component then
wrapped `SecurityFacade` behind the generated managed security world. Exact Component inspection
reported one import, `isecure:connector-runtime/security-broker@2.0.0`, and one export,
`isecure:connector-runtime/connector-security@2.0.0`; no WASI command, I/O, socket, filesystem,
clock, random or ambient HTTP import was present.

The host still owns entropy, transient-secret release, response inspection, capture, durable
custody, authority and transport. This evidence qualifies the SDK boundary and deterministic build
path only. Signed-package admission, application deployment and live provider qualification remain
platform tasks.

## Account/certificate compatibility integration — 8 November 2026

The full local gate and both native/Wasm minimum-version checks passed for
implementation `10d4bf6`. The [integration review](reviews/2026-11-08-account-certificate-compatibility.md)
records the three review angles, exact counts and current live-test limit. The
retained synthetic Admin/TOTP login and key read passed; its Data identity lacks
the current server's required mode flag, so the combined live suite did not pass.
This fixture issue is not reported as successful end-to-end qualification.

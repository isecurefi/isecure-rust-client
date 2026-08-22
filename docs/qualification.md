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

The resolved three-pass findings are recorded in `docs/reviews.md`.

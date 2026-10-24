# Changelog

## 0.1.0 - Unreleased

- Accept existing optional login `Account` metadata and expose it on completed direct-client
  sessions, preserving entitlement omission, strict decoding and collection limits.

- Initial transport-neutral ISECure REST API v2 Rust SDK.
- Admin/Data authentication, verification and session state machine.
- Account, certificate, OpenPGP key and file operations.
- Exact pinned OpenAPI verification, native and real Wasm tests, and guarded synthetic `gpgtest`
  qualification.
- Typed SDK resource limits for Wasm memory safety.
- Exact-byte file upload and download with Base64 confined to the REST wire.
- One shared native/WASI contract suite, deterministic mutation tests, pinned Wasm tools, import and
  size auditing, and mandatory CI verification.
- Secret-free business planning and a narrow injected privileged broker facade for the signed
  two-Component ISECure registration/authentication/connection-check seam, while preserving the
  direct native client and shared protocol/authentication core.
- A `no_std` plus `alloc` brokered core for managed WebAssembly security Components, with the native
  direct client retained behind the default `std` feature and a strict no-default-feature Wasm gate.

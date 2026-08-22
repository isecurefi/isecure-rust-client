# Changelog

## 0.1.0 - Unreleased

- Initial transport-neutral ISECure REST API v2 Rust SDK.
- Admin/Data authentication, verification and session state machine.
- Account, certificate, OpenPGP key and file operations.
- Exact pinned OpenAPI verification, native and real Wasm tests, and guarded synthetic `gpgtest`
  qualification.
- Typed SDK resource limits for Wasm memory safety.
- Exact-byte file upload and download with Base64 confined to the REST wire.
- One shared native/WASI contract suite, deterministic mutation tests, pinned Wasm tools, import and
  size auditing, and mandatory CI verification.

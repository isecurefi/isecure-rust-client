# Three-pass review record

Reviewed 2026-08-22. Each finding below was fixed and covered by a focused test before the final
gate. No unresolved finding remains in these three scopes.

## 1. Functional and cross-SDK correctness

- Compared all 26 Swagger operations with `isecure-ts-client` 2.1.0 for method, path, body, query,
  authentication and expected success status.
- Added exact pinned-contract, schema-inventory and observed-extension checks.
- Fixed the deployed `ExpiresIn` number/string difference found by the live test and recorded it as
  an observed deviation.
- Added fail-closed handling for unknown MFA names, malformed response codes, expiry values and
  partial TOTP enrollment responses.
- Added API-key security-domain matching, session replacement on reauthentication and the
  logout-only expired-session exception.
- Proved native and Wasm success, logical/HTTP/malformed failures, cancellation, timeout, explicit
  retry ownership and RSA interoperability.

## 2. Credential, privacy and security

- Replaced request/response debug output that could expose URL identity values or status wording.
- Zeroized secret wrappers and temporary parsed token, API-key, challenge, file and encrypted-key
  fields where owned memory permits it.
- Limited errors to validated structural fields and rejected free-form transport codes.
- Removed duplicate configured API-key storage and changed adapter recovery to drop all client-held
  configuration/session secrets.
- Fixed permissive loopback prefix matching so `localhost.evil` and equivalent authorities are
  rejected.
- Guarded live preparation and execution by exact profile, region, AWS account, non-root identity,
  synthetic domain and mode-0600 fixture. Live evidence contains counts/outcomes only.

## 3. KISS, idiomatic Rust, dependencies and parity

- Kept one generic client and one injected transport contract; added no HTTP client, TLS stack,
  async runtime, filesystem or AWS dependency to production code.
- Removed an unused registration model and avoided a second high-level workflow engine; typed
  `AuthState` remains the single caller-visible state machine.
- Pinned seven direct production dependencies and three test dependencies, generated a locked
  CycloneDX SBOM and documented every direct role/licence.
- Reviewed the only RustSec finding as unreachable because this crate performs public-key RSA
  encryption only, never private-key decryption; any other advisory still fails verification.
- Used the same core request, response, auth and error code for native and `wasm32-wasip2`; the Wasm
  proof is a real Wasmtime execution, not a compile-only check.

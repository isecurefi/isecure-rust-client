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

## Wasm-first hardening follow-up

Reviewed 2026-08-22 after adding resource limits, exact-byte files, shared parity cases, mutation
testing and automated Wasm gates.

### 1. Functional and Wasm parity

- Replaced caller-supplied Base64 file text with exact upload/download bytes and retained the exact
  provider JSON wire shape.
- Added exact-boundary and maximum-plus-one coverage for URLs, request/response bodies, files,
  signatures and collections.
- Made native and WASI execution consume one runner and one versioned failure-case file; added real
  RSA-OAEP challenge execution, raw-byte upload/download and host-owned retry to that runner.
- Moved the MFA collection bound ahead of every authentication branch after review found that an
  unexpected `MfaOptions` field could otherwise bypass the item-count check.

### 2. Credential, privacy and security

- Bounded request serialization before allocation growth and documented that the host must cap a
  response before copying it across WIT.
- Added zeroization for partially serialized rejected requests and oversized decoded file buffers
  after review found those temporary values were not wrapped on every error path.
- Pinned official Wasmtime and wasm-tools archives by host-specific digest, validated the component,
  fixed its exact command-harness imports and explicitly denied network, filesystem, HTTP, clock and
  randomness imports.
- Made the tool installer refuse symlink destinations and existing binary targets rather than
  overwriting them.

### 3. KISS, DRY and supply chain

- Added no production dependency, feature flag, runtime, WIT model or second client. One six-field
  `ResourceLimits` value and one typed `LimitError` cover all resource failures.
- Shared the existing synthetic RSA public key and the complete native/WASI runner instead of
  copying test logic.
- Kept fuzz-style testing deterministic and dependency-free: 14,000 bounded mutations run in the
  ordinary suite.
- Added one pinned CI job and fixed a review-discovered invalid `cargo audit fetch` command before
  completion. Strict Clippy, MSRV, native/Wasm builds, live synthetic compatibility, SBOM drift and
  the full gate pass with no SDK `unsafe` code.

## Brokered Component facade follow-up

Reviewed 2026-08-25 for `ISECURERUSTBROKER-001`. Findings were resolved before the final gate.

### 1. Functional correctness and provider-authoring usability

- Compared the closed operation plans and mutation fields with the direct client's exact registration,
  password-recovery, login, MFA, verification and authenticated-header wire shapes. An initial MFA
  implementation always emitted `ChallengeName`; review found the direct contract can omit it, so the
  brokered input now preserves that optional state.
- Review found the first draft lacked the verification-accepted transition. Extracted one shared
  verification classifier and proved direct/brokered phone-verification parity.
- Review found that a later business Component would otherwise need to duplicate account, certificate
  and key-list decoding. Extracted the direct JSON decoder and logical/collection checks for exact
  reuse by the three brokered parent-connection checks.
- Added authenticated, MFA-selection, malformed partial-TOTP, HTTP-error and verification parity
  fixtures, plus exact operation/stage/binding and generated-world lock tests.

### 2. Authority, credential isolation, privacy and failure semantics

- Kept the business source free of raw-secret wrappers, transient-secret access, request mutations,
  capture broker access and the privileged facade. Opaque-reference canaries remain absent from debug
  output and business results.
- Validated operation/input shape and complete binding cardinality before reading a one-use value;
  validated every capture kind and duplicate before the first broker call. Missing, extra, reordered,
  wrong-operation, duplicate, unavailable and already-used cases fail closed with stable errors.
- Made prior auth context derivable only from opaque host bindings. Captured values remain opaque and
  can reach custody only through `CaptureBroker`; request outputs remain zeroizing and redacted.
- Documented the mandatory host checks that the SDK cannot own: signed stage authority, atomic whole-
  stage capture, existing API-key-domain equality, buffer disposal and fresh-instance destruction.

### 3. KISS, DRY, Wasm and generated-contract drift

- Preserved the direct `Client` and one protocol core. Direct and brokered paths now share typed models,
  errors, limits, JSON decoding, logical checks and auth/verification classification; no second HTTP
  client or workflow engine was introduced.
- Split the 974-line mixed draft into one secret-free business module and one privileged security
  module. This is an audit boundary inside the same crate, not a new public service, trait hierarchy,
  feature flag or dependency.
- Kept the facade limited to the first ISECure registration/authentication/parent-test package. It does
  not introduce OAuth2, mTLS, discovery, tenant wiring or a general security-plugin framework.
- Pinned the exact generated business/security WIT worlds and digest. The shared native/WASI runner now
  executes brokered planning and preparation without changing its exact import allowlist.
- Fixed the Wasm audit script to consume Cargo's reported artifact path, so repository-local and
  direnv-managed external build caches use one portable gate without hardcoded cache paths.

No finding remains in these three scopes. This review qualifies SDK implementation only; generated
WIT adapters, the signed two-Component package, host coordinator, application integration and live
Connector qualification remain separate tasks.

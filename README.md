# ISECure Rust client

`isecure-rust-client` is the transport-neutral Rust SDK for ISECure REST API v2. It covers the same
File Exchange protocol as `isecure-ts-client` 2.1.0, with Rust types and explicit state transitions.
The crate is not published yet (`publish = false`).

The client supports:

- Admin and Data registration and RSA-assisted login;
- SMS and TOTP MFA, email and phone verification, password recovery, logout, session expiry and API
  key-domain checks;
- account, certificate, certificate-sharing, enrollment and import/export operations;
- OpenPGP public-key administration; and
- file upload, listing, download and deletion.

File methods use exact bytes at the Rust boundary. The SDK performs and validates the REST API's
Base64 wire encoding, so Connector code does not maintain a second encoding path.

The SDK owns only the provider protocol. It does not own HTTP sockets, credential storage, retries,
financial rules, approvals, bank signing keys, application configuration or plugin authority.

It offers two protocol front ends over the same models, limits, errors and authentication
classifier:

- `Client` is the existing direct client for a trusted native caller. It owns zeroizing credentials
  and session values in process memory and uses an injected `Transport`.
- `BusinessFacade` and `SecurityFacade` are the brokered Component seam. The business side receives
  only safe data and opaque host resources. The privileged side can read an exact one-use value,
  place it in an admitted ISECure field, or ask the host broker to seal an exact response value. It
  owns no durable state and opens no connection.

## Design

Create a `Client<T, E>` with three caller-owned capabilities:

- `T: Transport` sends one HTTP-shaped request. A native application, Wasmtime host or test supplies
  it.
- `E: ChallengeEncryptor` performs the exact RSA-OAEP SHA-1 challenge operation. The supplied
  `RsaChallengeEncryptor` takes caller-provided cryptographic randomness.
- An optional `Clock` makes expiry behavior deterministic in tests.

`ResourceLimits` bounds resolved URLs, JSON requests and responses, decoded files, signatures and
provider collections. Defaults are defensive SDK limits rather than provider claims. A signed
Connector profile may supply explicit non-zero limits; the Wasm host must still cap response bytes
before copying them into guest memory.

The core crate opens no sockets or files, starts no runtime and depends on neither Tokio nor an HTTP
library. Native callers use the default `std` feature. A managed security Component disables default
features and receives only the broker capabilities supplied by its generated WIT world; the shared
brokered protocol core then builds for `wasm32-wasip2` without importing WASI command, I/O, socket,
filesystem, clock, random or ambient HTTP capabilities.

```rust
use isecure_rust_client::{ClientConfig, Mode, SecretString};

let config = ClientConfig::builder(
    "https://ws-api.test.isecure.fi/v2",
    "synthetic@example.invalid",
    Mode::Admin,
)
.phone("+358400000000")
.company("Synthetic Company")
.name("Synthetic User")
.password(SecretString::new("read-from-a-protected-host-slot"))
.public_key_pem("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")
.bank("simulator")
.api_key(SecretString::new("read-from-a-protected-host-slot"))
.build()?;

# let _ = config;
# Ok::<(), isecure_rust_client::Error>(())
```

Call `login()`, inspect `AuthState`, and invoke only the indicated next transition. The client retains
tokens in memory, rejects a returned API key that differs from the configured security domain and
refuses authenticated work after local expiry. `logout()` is the sole operation allowed to use a
locally expired session.

## Brokered Component facade

The brokered facade is intentionally narrower than the direct client. It covers the first signed
ISECure package: Admin/Data registration, password recovery, authentication and MFA, plus
authenticated account/key/certificate-list connection checks. Later file and certificate workflows
continue to use the shared protocol core but are not admitted through this security facade yet.

`BusinessFacade::plan` checks the exact ordered protected-value kinds and emits a short typed stage
list. A `ProtectedBinding` borrows a generated WIT `protected-reference`; it has no method that
reveals the host resource or credential bytes. `complete_authentication` consumes only sanitized
provider fields and structural capture evidence, then uses the same auth classifier as `Client`.

`SecurityFacade::prepare` accepts only closed ISECure operations and inputs. It reads each injected
`TransientSecret` once into a zeroizing buffer and emits only the exact `ChResp`, `Encrypted`, MFA,
verification, `Authorization` or `x-api-key` mutation required by that operation.
`SecurityFacade::capture` never reads a provider credential: it passes an opaque protected response
resource to the injected `CaptureBroker`. The host must enforce signed package, Component, tenant,
legal-entity, environment, operation, stage, slot, purpose, destination, generation and use-count
authority, including API-key equality when a security domain already exists.

The facades do not implement WIT bindings. The generated platform adapter maps the signed
`connector-business-plugin` and `connector-security-plugin` worlds to these Rust types. The exact
compatible WIT revision and digest are pinned in
`contracts/brokered-component-profile.lock.json`. Components still never call one another; the host
invokes and mediates every stage. OAuth2, mTLS, generic security-plugin discovery and tenant-defined
wiring remain outside this SDK and this first ISECure seam.

## Build and test

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
cargo clippy --locked --no-default-features --target wasm32-wasip2 -- -D warnings
cargo build --locked --release --no-default-features --target wasm32-wasip2 --lib
scripts/install-wasm-toolchain.sh /absolute/private/tool-directory
WASMTIME_BIN=/path/to/wasmtime WASM_TOOLS_BIN=/path/to/wasm-tools scripts/test-wasm.sh
```

The Wasm script builds and executes `examples/wasm_contract.rs` as real WASI code. The identical
runner and versioned `contracts/component-contract-cases.json` execute natively too. They cover
authentication, raw-byte upload/download, logical and HTTP failure, malformed JSON, cancellation,
timeout, host-owned retry and secret-safe debug output. The gate also validates the component,
checks its exact import allowlist and enforces a 400,000-byte regression budget. The native suite
additionally covers exact operations, resource-limit boundaries, URL encoding, API-key
substitution, expiry, RSA interoperability and deterministic mutation fuzzing.

The command example deliberately keeps its small WASI command harness. Production managed
Components use `default-features = false`; platform qualification inspects the finished Component
and rejects every import outside its exact generated broker contract.

The pinned Swagger bytes, source revision, digest and observed deviations live under `contracts/`.
`tests/openapi_contract.rs` rejects contract, operation or schema inventory drift.

## Live test

The ignored test in `tests/live_gpgtest.rs` is only for the synthetic `gpgtest` AWS account. It checks
the exact `default` profile, account `589434896614`, region `eu-west-1`, non-root identity, endpoint
and mode-0600 fixture before making calls. The one-time preparation test administratively creates
verified synthetic users and TOTP, so no SMS or email code is needed.

Run preparation once, only in the admitted account:

```sh
AWS_PROFILE=default AWS_REGION=eu-west-1 ISECURE_GPGTEST_PREPARE=1 \
  cargo test --test live_gpgtest administratively_prepare_synthetic_gpgtest_fixture \
  -- --ignored --exact
```

Then run the read-only black-box test:

```sh
AWS_PROFILE=default AWS_REGION=eu-west-1 ISECURE_GPGTEST_LIVE=1 \
  ISECURE_GPGTEST_FIXTURE_FILE="$PWD/.live/gpgtest-fixture.json" \
  cargo test --test live_gpgtest authorized_synthetic_gpgtest_auth_and_read_operations \
  -- --ignored --exact
```

`.live/` is ignored. Never copy its contents into Git, logs, test output or issue text.

See [dependency review](docs/dependencies.md), [qualification evidence](docs/qualification.md) and
[security guidance](SECURITY.md).

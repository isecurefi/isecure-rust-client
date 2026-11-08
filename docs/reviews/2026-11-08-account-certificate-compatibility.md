# Account and retired-certificate compatibility integration

Reviewed 2026-11-08. Integrates `6365fac` and `10d4bf6` onto the existing main
line, preserving the prior authentication-diagnosis fixes.

## Review 1: behavior and compatibility

Completed login responses now accept optional typed `Account` metadata. Older
responses still work; unavailable entitlements remain distinct from an empty
list. Intermediate MFA/verification responses do not create or retain a completed
session. Certificate listings accept optional `Retired` summaries separately
from usable certificates and connections. Focused before/after tests reproduce
both original failures and pass with these changes.

## Review 2: security and evidence

Unknown/malformed fields still fail. Existing byte and collection limits apply;
metadata never grants authorization, and retired certificates never become
usable connections. Session/account debug output does not reveal preview or
subscription values. Both direct and brokered certificate readers enforce the
same bounds. No crypto, credential storage, provider mutations or retry policy
changed in the production library.

## Review 3: architecture and simplicity

Reuse the existing shared models, decoders and collection checks. The direct
session projection is additive; brokered custody stays with the existing host.
Record observed response extensions alongside the frozen upstream OpenAPI
snapshot rather than silently changing its provenance. No new dependencies,
transport, persistent state or authentication stack were added.

## Qualification

Exact implementation revision: `10d4bf600a24ffafba0ce31591cfba029dfd8dcd`.
The complete `scripts/verify.sh` gate passes with Rust 1.94.1: formatting,
all-target checks, strict native/no-std Wasm Clippy, 50 native tests and one doc
test, release builds, dependency audit with the existing documented RSA
private-decryption advisory exception, and unchanged SBOM. Both real Wasmtime
48.0.0 harnesses pass exact import checks at 362136 and 205448 bytes, below their
400000-byte budgets. Rust 1.85.1 native and wasm32-wasip2 checks also pass.
Generated/local tests had networking denied; live tests were not mixed into them.

The current test-domain mapping was verified against ordinary gpgtest in account
589434896614, eu-west-1. At the check, Login alias stage_gpgtest served version 21
and Userdata served version 19; body tracing was disabled. The retained synthetic
fixture completed Admin/TOTP login and key listing. Data login was correctly
denied because the old fixture lacks `data_enabled`; a read-only account check
confirmed the absent field. No fixture repair was performed as part of this
initial integration. That initial result is superseded by the follow-up below.

This integration does not implement the planned SHA-256 tenant authentication
profile, publish to crates.io, or change GitHub repository visibility.

## Authorized fixture repair and discovery follow-up

The owner authorized setting `data_enabled=true` only while absent on the retained
synthetic gpgtest account. The conditional update verified the exact account,
tenant key, existing Admin mode and absence of deletion markers. Read-back proved
all other attributes unchanged; no production account changed. Future fixture
provisioning now explicitly enables the Data identity it already creates.

The next live run exposed the current server's `FileTransferCapabilities` array.
A typed optional projection now accepts that discovery metadata in both direct
and brokered readers. The metadata grants no authority and does not implement
large-file transfers. The pinned OpenAPI snapshot remains unchanged.

Three inline follow-up reviews:

1. Compatibility: absent and empty metadata preserve old responses; populated
   discovery metadata is preserved. Both frontends return identical models.
2. Security/privacy/evidence: malformed values and unexpected nested fields fail;
   outer and nested collections retain resource limits. No transfer request,
   network target, credential or authorization derives from discovery. Temporary
   field-name/type diagnostics were removed; no auth response was logged.
3. Architecture/reuse: reuse the shared response model and existing limits. No
   dependency, transport, backend change or negotiation framework is introduced.
   Fixture provisioning adds only the missing mode flag.

The complete network-denied local gate passes with 51 native tests and one doc
test, strict Clippy, release builds, the existing scoped audit exception and
unchanged SBOM. Actual Wasmtime harnesses pass at 362355 and 205652 bytes with
exact import allowlists. Rust 1.85.1 native/Wasm checks pass. The bounded live
Admin/TOTP login, key listing, Data login, certificate listing and completed
session metadata assertions all pass against ordinary gpgtest. This is the
bounded authentication/read suite, not real-bank or all-provider qualification.
GitHub CI for the earlier merge `88723b0` passed (run `42481766914`).

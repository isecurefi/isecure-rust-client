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
initial integration. Full live qualification remains pending that repair.

This integration does not implement the planned SHA-256 tenant authentication
profile, publish to crates.io, or change GitHub repository visibility.

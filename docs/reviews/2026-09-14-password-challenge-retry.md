# Password challenge rejection — 2026-09-14

## Review 1: functional correctness

A failed registration has no API key. The security facade previously rejected its empty capture
set before the business facade could classify the provider response. The retained RED reproduces
`Protocol(MissingValue)` at that boundary. Capture now validates and seals only supplied fields;
successful registration still requires the API key in business completion. The additive registration
step result recognizes only HTTP 400, response code `01` and the provider's exact password-check
failure. The same classifier supplies direct/brokered login parity. Unknown or contradictory
responses do not become retryable; 429 and 5xx retain their error classification.

## Review 2: security, privacy and evidence

The classification denotes password/challenge validation before registration/authentication. It
does not claim the nonce definitely expired: the same provider rejection covers invalid challenge
or password decryption. A plugin may explicitly request a fresh challenge and new input; the SDK
never repeats requests, retains passwords or grants host authority. A response containing a captured
credential cannot also be classified as this registration rejection. Missing successful credentials,
duplicate captures, unsupported fields and broker refusal remain covered. All fixtures are synthetic;
provider error vocabulary is a protocol constant, with no customer response or identifier retained.

## Review 3: KISS and contract control

One provider-owned predicate is shared by registration and authentication. Existing strict
registration completion remains available; the additive typed step result leaves policy and state
transitions to the caller. No transport, clock, retry loop, state library, WIT or application contract
was added. Consumers opt into the new git-pinned SDK revision and must handle the new authentication
diagnosis. Unchanged consumers retain their pinned revision.

## Verification

Focused RED/GREEN passes, including the empty-capture reproduction, successful registration without
a key refusal, confirmed password-check rejection and unknown/contradictory envelope mutations.
All 42 native tests pass; two live cases remain explicitly ignored. Native and WASI strict Clippy
and the `wasm32-wasip2` release library build pass. No provider request is made by this qualification.

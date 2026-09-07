# Authentication HTTP rejection classification — 7 September 2026

Scope: SDK foundation for platform `CONNECTSTATE-002-CLASSIFY`, based on
`c8cfffdf0b4c1789a777b1870b0c6bcc9f60232e`. Plugin projection and installed package delivery are
separate remaining gates in the platform ledger. No retry policy is added to the SDK.

## Functional correctness review

The executed regression reproduces the exact failure class: an HTTP 400 with the bounded invalid-code
envelope returns `Http` before reaching the existing shared authentication classifier. Only login,
MFA selection/submission and email/phone/TOTP verification select the new decoder. Recognized 400
rejections and narrowly recognized 429 attempt limits reach the existing typed failure states;
registration, password recovery and generic API operations retain strict status checks.

The direct and brokered matrix covers invalid/expired/new-code, already-verified and rate-limit
responses; all three verification purposes and login; success-coded and malformed rejection
envelopes; unknown wording, 401/500 and inconsistent 429; malformed JSON and unexpected token fields.
Explicit repeated email/MFA submissions demonstrate retained existing continuation custody, not an
SDK retry. Their transport supplies exactly one response per explicit call. Existing operation,
resource-limit, expiry, domain-key substitution and brokered protocol tests also pass.

## Security, privacy and evidence review

Review identified misleading broad wording in the predecessor best-effort classifier. An additional
executed RED rejects `Too many accounts`, an already-sent confirmation code, and an expired access
token that mentions a new code. The new HTTP admission guard requires code context and excludes
password/token/session ambiguity, recognizes verified/confirmed phrases, and requires request/attempt/
rate context for limits. Unknown HTTP outcomes remain errors. The existing HTTP-200 classifier is
unchanged. Classification never establishes continuation usability or permission to replay.

A rejected authentication envelope cannot introduce token captures or challenge metadata. Direct
rejection parsing requires the exact two-field API envelope; unexpected fields, including a request
ID, remain HTTP errors. Brokered metadata is already structurally sanitized and bounded by its
existing limits. Raw provider text stays out of Debug output; a synthetic canary test verifies this.
No real account, credential, provider payload, network authentication or persisted answer is used.

## KISS, ownership and generated drift review

The SDK retains one protocol classifier and one shared transport preparation path. A private HTTP
admission guard selects existing typed states without new public enum variants, dependencies,
contracts, persistence, retry timers or app/provider workflow logic. The brokered no-std target keeps
its capability boundary; the direct-only decoder is feature-gated.

Adding every regression to the old monolithic Wasm harness exceeded its 400,000-byte budget. A
separate focused harness runs the same new source as the native test, using the existing audit script
with a closed two-example inventory. Both retain the unchanged size budget and exact import list.
An initial default-clock fixture caused the import check to fail; the fixture now injects a fixed
clock, so no ambient clock capability was allowed. Audit failures now reach stderr even when the
caller captures the artifact path. No generated wire artifact changes.

## Focused evidence and limits

- `/tmp/isecure-auth-classification-sdk-red.log`: invalid-code HTTP 400 regression fails before fix.
- `/tmp/isecure-auth-classification-sdk-review-red.log`: ambiguous wording regression fails before guard refinement.
- `/tmp/isecure-auth-classification-sdk-green.log`: 25 tests pass across rejection parity, brokered
  facade, client contract and retained transport parity targets.
- `/tmp/isecure-auth-classification-sdk-clippy.log`: strict native library, affected tests and both examples pass.
- `/tmp/isecure-auth-classification-sdk-wasm-clippy.log`: strict release no-default-feature Wasm lint passes.
- `/tmp/isecure-auth-classification-sdk-wasm.log`: both real Wasmtime 48.0.0 executions pass, with
  validated exact imports; retained harness 353887 bytes and focused harness 197464 bytes.
- `/tmp/isecure-auth-classification-sdk-wasm-build.log`: release no-default-feature Wasm library builds.
- `/tmp/isecure-auth-classification-sdk-contract.log`: both exact WIT/operation pin and business custody checks pass.
- SDK tooling installed through the repository's digest-pinned script. Shell syntax, rustfmt and
  changed Markdown formatting are checked before commit. No full platform/app aggregate is claimed.

All three reviews pass for this SDK slice. The platform must consume the exact committed SDK revision,
project these reasons to plugin-owned messages, and qualify its changed host/package path before the
parent task is complete. Existing installed packages have not changed.

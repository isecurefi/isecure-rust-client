# Logical authentication rejection guards — 7 September 2026

Follow-up to the HTTP rejection slice `0c646c9`. Platform classification review found that the
pre-existing HTTP-200 logical failure path bypassed the new ambiguity guards.

## Functional review

An executed regression shows an invalid-password response becoming `InvalidCode` in both direct
and brokered login. Five cases now return `Unknown` for password/session ambiguity, unrelated limits
and already-sent confirmation wording. Recognized code/verification/attempt-limit cases still use the
same typed reasons on both HTTP paths. No successful authentication transition or continuation
handling changes; no request is retried.

## Security, privacy and evidence review

Reviewed status/envelope gating, reason precedence and token/session ambiguity. Unknown causes remain
unknown instead of producing a misleading code instruction. HTTP 400/429 admission still accepts
only its bounded existing reason set; registration and other operations are unchanged. The SDK never
turns a reason into retry permission. All inputs are synthetic and provider text remains redacted.

## KISS and ownership review

Move wording guards into the existing shared classifier and remove duplicate wording checks from
HTTP admission. No new enum, interface, dependency, policy in the plugin/app, generated artifact or
lint exception. HTTP admission now checks only status, logical response code and classified reason.

## Focused evidence

- `/tmp/isecure-auth-logical-classification-red.log`: executed password-as-code regression.
- `/tmp/isecure-auth-logical-classification-green.log`: all 25 affected native tests pass.
- `/tmp/isecure-auth-logical-classification-clippy.log`: strict native library and affected harness pass.
- `/tmp/isecure-auth-logical-classification-wasm-clippy.log`: strict no-std release Wasm lint passes.
- `/tmp/isecure-auth-logical-classification-wasm.log`: both real Wasmtime executions pass the same
  exact import allowlist and unchanged 400,000-byte bounds (353645 / 197632 bytes).
- No-std release build, rustfmt and changed Markdown formatting are checked before commit.

All three reviews pass for this follow-up. Platform SDK pins and Component/host qualification must
advance to the committed successor; this SDK change alone does not deliver an installed plugin.

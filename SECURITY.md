# Security

Report vulnerabilities privately to the ISECure maintainers. Do not open a public issue containing
credentials, tokens, customer data, provider response bodies or exploitable details.

## Credential boundary

- `SecretString` and `SecretBytes` redact `Debug`, cannot be cloned or serialized, and zeroize their
  owned allocation on drop.
- Passwords, API keys, tokens, MFA codes, TOTP enrollment data, file bytes, signatures and encrypted
  private keys use those wrappers at public boundaries.
- Parsed temporary credentials are moved promptly into zeroizing wrappers and remaining temporary
  fields are zeroized on drop.
- Request debug output omits URLs because paths contain identities and file references. Secret
  headers and all bodies are redacted.
- Errors retain only a closed category, validated value-free code, HTTP status, two-digit provider
  code and a bounded safe request ID. They do not retain response text or raw bodies.

The caller still owns secure input, storage, screen rendering, clipboard policy, process memory,
HTTP/TLS, DNS, proxy, redirect and certificate policy. WebAssembly hosts should release credentials
through a bounded capability and destroy the instance after use. The SDK is not a vault.

## WebAssembly resource boundary

`ResourceLimits` provides SDK-side defense in depth for URLs, JSON bodies, decoded files,
signatures and collections. A host must enforce the response-byte limit before crossing WIT and
allocating guest memory; the SDK check occurs after the injected transport returns. The retained
WASI command harness has one exact import allowlist and rejects filesystem, sockets, HTTP, clocks
and randomness. That command scaffolding is not the production Connector world: the signed plugin
package must separately admit only its generated WIT capabilities.

## Transport and retries

The core sends exactly once per method call. It does not retry automatically because several REST
operations mutate provider state and the API exposes no universal idempotency key. A transport may
retry only when it can prove the first attempt was not sent. An indeterminate outcome must be
reconciled before a caller chooses another mutation.

Use HTTPS except for the SDK's explicit loopback allowance in local tests. Production hosts must
also enforce the signed package's fixed endpoint policy; do not accept customer-entered base URLs.

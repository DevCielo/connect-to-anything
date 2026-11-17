# Threat model

## Protected assets

Provider access/refresh tokens, API keys, tenant identity, end-user binding, allowed scopes, callback integrity, and upstream data returned through the proxy.

## Defenses in this MVP

| Threat | Control |
| --- | --- |
| Connect-link theft/replay | 256-bit random token, hashed storage, ten-minute expiry, single consumption |
| OAuth CSRF/code injection | independent one-use state bound to the server-side tenant/user transaction plus transaction-specific PKCE S256 verifier; browser-cookie binding remains future hardening |
| Callback mix-up | provider-specific callback path checked against stored session provider |
| Cross-tenant access | API key resolves tenant server-side; all connection operations include tenant predicate |
| Database disclosure | AES-256-GCM authenticated encryption for tokens, API keys and PKCE verifiers |
| Token disclosure to clients | list API exposes metadata only; proxy injects credentials server-side |
| Open proxy/SSRF | operator-configured OAuth-provider origin; user-supplied API-key origins get relative-path, HTTPS and DNS/IP private-range checks |
| Clickjacking/cache leakage | CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `no-store` |

## Required before production

- Put envelope-encryption keys in KMS/HSM, add key IDs and rotation. Never place a raw master key beside the database.
- Replace shared static API keys with hashed, rotatable service credentials or signed workload identity.
- Store allowed return URLs per tenant and compare exact normalized URLs.
- Add rate limits to session creation, callbacks and proxy calls; cap upstream response sizes and timeouts.
- Enforce an egress firewall or resolving proxy. Application DNS checks alone do not eliminate DNS rebinding/TOCTOU.
- Add immutable, redacted audit events and alerts. Never log authorization codes, state, cookies or tokens.
- Implement provider revocation and webhook-driven invalidation. Local credential deletion alone does not revoke grants.
- Add per-provider allowed methods/path patterns/scopes instead of exposing an unrestricted provider-origin proxy.
- Use production-grade storage with migrations, backups, transaction isolation and availability controls.
- Add CSRF tokens to API-key form POSTs if the hosted connect page gains ambient browser authentication or cookies.

## Explicit non-goals

This MVP does not bypass anti-bot controls, automate MFA, capture passwords, defeat provider access policies, or claim compliance certification. Operators are responsible for provider terms, user consent, data-processing agreements and least-privilege configuration.

## Warranty and operator responsibility

The software is provided as-is without warranty. A workflow can perform destructive writes if you define destructive requests. The operator must review imported captures and generated definitions, restrict server API keys, isolate outbound network access, test against non-production data, obtain every required authorization, and provide their own rollback and incident response procedures.

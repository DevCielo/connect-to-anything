# Architecture

## Current boundary

```text
customer backend --server API key--> connection broker --OAuth/API key--> provider
       |                                  |
       | creates one-use URL              | encrypted SQLite credentials
       +---------- user browser ----------+
       |
       +-- connection ID + relative request --> origin-pinned proxy --> provider API
```

The broker is the only component that sees provider credentials. A browser receives a short-lived connect token, not the customer's server key. An agent receives a stable connection ID, not an access token.

## Data model

- `connect_sessions`: tenant/user/provider intent, return URL, requested scopes, expiry and consumption time.
- `oauth_states`: hash of random state, encrypted PKCE verifier, tenant/session binding, expiry and consumption time.
- `connections`: tenant/user/provider identity, encrypted token set or API key, granted scopes and lifecycle state.

Reconnect is an upsert on `(tenant, external user, provider)`, preserving the stable connection ID.

## Request invariants

1. The server API key selects the tenant; callers cannot supply a tenant ID.
2. A connect session and OAuth state can each succeed once.
3. Callback provider, session provider, tenant and stored state must agree.
4. The proxy resolves relative paths under the configured base URL and verifies the final origin.
5. Tokens are decrypted only immediately before exchange, refresh or proxy execution.

## Legacy workflow runtime

A responsible portal-to-API layer needs much more than blindly replaying a HAR file. The current implementation provides a deliberately narrow foundation:

1. **Explicit capture:** the operator exports a small HAR from their browser and uploads it intentionally. There is no hidden background recorder.
2. **Sanitizing compiler:** authorization, cookies, secrets, sensitive query parameters, credentials in JSON bodies and hop-by-hop headers are removed. Imports are single-origin and capped at 50 requests.
3. **Versioned definitions:** imports create immutable versions. Developers can publish reviewed declarative definitions with input templates and response extraction.
4. **Constrained executor:** the connection pins the destination, paths cannot escape its base URL, execution is sequential, each request has a timeout, and response bodies are capped.
5. **Drift detection:** every step declares acceptable statuses. A mismatch stops the run and records a `drifted` result for human review.
6. **Redacted evidence:** run records contain status and recursively redacted response data, never connection credentials.

Automatic workflow repair, password capture, MFA automation, anti-bot circumvention and unattended write retries are intentionally excluded.

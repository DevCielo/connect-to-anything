# connect-to-anything

An open-source, self-hosted toolkit for connecting modern products and agents to APIs and legacy web software. It provides hosted authorization, encrypted credential storage, sanitized HAR import, declarative request workflows, constrained execution, drift detection, and run evidence.

> [!WARNING]
> **Use this software entirely at your own risk.** It is experimental, comes with no warranty, and is not a managed security or compliance service. You are responsible for obtaining permission, respecting software terms and access policies, protecting credentials and personal data, reviewing every imported workflow, and testing all read/write operations. Never use it to bypass MFA, anti-bot controls, access restrictions, or another person's authorization.

Read the plain-language [disclaimer](DISCLAIMER.md) and [security policy](SECURITY.md) before running it.

## Why this exists

Many useful systems have no public API, an incomplete API, or a web portal built long before agent tooling. This project gives developers a transparent, inspectable way to turn network requests they are already authorized to make into a versioned workflow:

1. Your backend creates a short-lived connect session for one tenant, user, and provider.
2. The user authorizes with OAuth, an API key, or a manually supplied legacy session cookie.
3. Tokens are encrypted and kept server-side.
4. A developer exports a narrowly scoped HAR from browser developer tools and imports it; secrets are removed and only one origin is accepted.
5. The generated workflow is reviewed, parameterized and versioned.
6. The runtime executes each request on the connection's pinned origin, records redacted results, and stops if a status assertion drifts.

Credentials never reach an agent or browser client after connection. This is deliberately a workflow engine, not an access-control bypass or automatic “repair anything” promise. See [docs/architecture.md](docs/architecture.md) and [docs/safe-capture.md](docs/safe-capture.md).

## Run it

Requires Node 22.5+ (the built-in SQLite module is currently marked experimental by Node).

```bash
cp .env.example .env
export ENCRYPTION_KEY_BASE64="$(openssl rand -base64 32)"
export API_KEYS_JSON='{"replace-this-server-secret":"tenant-123"}'
node --env-file=.env src/server.js
```

Create a GitHub OAuth App whose callback is `http://localhost:4242/v1/oauth/callback/github`, add its client ID/secret to `.env`, then create a connect session from your **backend**:

```bash
curl -s http://localhost:4242/v1/connect-sessions \
  -H 'Authorization: Bearer replace-this-server-secret' \
  -H 'Content-Type: application/json' \
  -d '{"external_user_id":"user-42","provider":"github","return_url":"http://localhost:3000/integrations/done"}'
```

Open the returned `connect_url`. After authorization, list and use connections:

```bash
curl -s 'http://localhost:4242/v1/connections?external_user_id=user-42' \
  -H 'Authorization: Bearer replace-this-server-secret'

curl -s http://localhost:4242/v1/connections/CONNECTION_ID/proxy \
  -H 'Authorization: Bearer replace-this-server-secret' \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"user"}'
```

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/providers` | List built-in providers and configuration state |
| `POST /v1/connect-sessions` | Mint a ten-minute, one-use hosted connect URL |
| `GET /v1/connections` | List non-secret connection metadata, optionally by external user |
| `POST /v1/connections/:id/proxy` | Execute a relative request on the provider's pinned origin |
| `DELETE /v1/connections/:id` | Wipe credentials and mark a connection revoked |
| `POST /v1/workflows/import-har` | Sanitize a single-origin HAR into a review-required workflow version |
| `POST /v1/workflows` | Publish a reviewed declarative workflow version |
| `GET /v1/workflows` | List workflow versions |
| `POST /v1/workflows/:id/runs` | Run a workflow synchronously with inputs and a connection |
| `GET /v1/runs/:id` | Read redacted run evidence and drift/failure state |

Built-ins are GitHub, Slack, generic HTTP API-key auth, and an explicitly manual legacy web session. Add an OAuth provider in `src/providers.js`; its authorization URL, token URL, API origin, least-privilege default scopes, credential environment variables, and PKCE support are explicit data. Never export or import a HAR containing credentials without reviewing and sanitizing it first.

## Security posture

- Server API keys map to tenants, and every connection lookup includes the tenant.
- Connect tokens and OAuth state are stored as SHA-256 hashes, expire, and are consumed once. OAuth state is bound to the server-side tenant/user transaction; this MVP does not additionally bind it to a browser cookie.
- PKCE uses a fresh high-entropy verifier and `S256`; the verifier and provider tokens use AES-256-GCM at rest.
- Redirect destinations must be HTTPS except localhost development. Production should replace this with a per-tenant allowlist.
- Proxy requests accept only relative paths on a pinned origin. For user-supplied API-key endpoints, private, loopback, and link-local targets are rejected after DNS resolution to reduce SSRF risk. Explicit development mode permits localhost.
- Browser pages return restrictive CSP, frame denial, and `no-store`.
- Disconnect overwrites the encrypted credential field. Provider-side revocation is not yet implemented for every provider.

Read [docs/threat-model.md](docs/threat-model.md) before exposing this service. Production still needs an external secrets/KMS system, rate limits, audit logs, key rotation, a hardened reverse proxy, provider revocation adapters, DNS rebinding defenses at the network egress layer, and PostgreSQL or another production database.

## Test

```bash
npm test
```

The suite runs a complete mock OAuth exchange and workflow execution, and verifies PKCE, one-time state, tenant-scoped metadata, secret non-disclosure, HAR redaction, extraction, drift detection, proxy authorization, replay rejection, and disconnect behavior without real credentials.

## License

Apache-2.0.

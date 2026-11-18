# connect-to-anything

![A red braided cable joins a vintage serial connector to a modern USB-C plug](docs/assets/readme-banner.jpg)

An open-source, self-hosted toolkit for connecting modern products and agents to APIs and legacy web software. It provides hosted authorization, encrypted credential storage, sanitized HAR import, declarative request workflows, constrained execution, drift detection, and run evidence.

[Quick start](#run-it) · [Integration examples](#what-you-can-connect) · [What gets blocked](#what-gets-blocked) · [API reference](#api) · [Architecture](docs/architecture.md)

> [!WARNING]
> **Use this software entirely at your own risk.** It is experimental, comes with no warranty, and is not a managed security or compliance service. You are responsible for obtaining permission, respecting software terms and access policies, protecting credentials and personal data, reviewing every imported workflow, and testing all read/write operations. Never use it to bypass MFA, anti-bot controls, access restrictions, or another person's authorization.

Read the plain-language [disclaimer](DISCLAIMER.md) and [security policy](SECURITY.md) before running it.

## How it works

1. **Connect.** Your backend requests a short-lived link. The user opens the hosted page to authorize access or enter credentials.
2. **Call.** Your backend uses the connection ID to make a request to the configured service. Credentials are stored encrypted and applied server-side.
3. **Repeat.** For multi-step tasks, publish a reviewed workflow, pass in inputs, and inspect the recorded result. A status mismatch stops the run.

## What you can connect

Four connection types ship with the repo. The generic HTTP option can cover many systems that accept a key in a request header.

| Connection | Example use | What you need |
| --- | --- | --- |
| GitHub OAuth | Look up the signed-in user's profile | A GitHub OAuth app |
| Slack OAuth | Look up workspace users | A Slack OAuth app and the required scopes |
| HTTP API key | Read a support ticket, check an order, or fetch an inventory item | An HTTPS API, its base URL, and an authorized header-based key |
| Legacy web session | Read a record from an internal portal you have permission to integrate | A manually supplied session cookie and compatible HTTP endpoints |

The same HTTP setup can fit CRM records, fulfillment status, billing exports, help desk queues, and internal admin tools. Each integration depends on the service's authentication, API shape, and permissions. For an example of a reviewed, read-only workflow, see [legacy-read-workflow.json](examples/legacy-read-workflow.json).

### When a service has no public API

A portal may still have HTTP requests that your organization is authorized to integrate with. A narrowly scoped HAR can become a draft workflow for review. Check that the service permits this use, review the draft before publishing, and test it against a non-production account where available. For browser-only interactions or services that require steps outside the supported HTTP workflow, use a supported integration path. See the [safe capture guide](docs/safe-capture.md).

## Run it

### 1. Start the server

Run these commands from the cloned repo. You'll need Node 22.5 or later. The server uses Node's built-in SQLite module, which may emit an experimental warning.

```bash
cp .env.example .env
export ENCRYPTION_KEY_BASE64="$(openssl rand -base64 32)"
export API_KEYS_JSON='{"replace-this-server-secret":"tenant-123"}'
node --env-file=.env src/server.js
```

### 2. Check that it started

In another terminal, check the health endpoint. It returns `{"ok":true}` and requires no provider account.

```bash
curl -fsS http://localhost:4242/healthz
```

To see which connection types are available, call the provider list with the server key set in step 1.

```bash
curl -fsS http://localhost:4242/v1/providers \
  -H 'Authorization: Bearer replace-this-server-secret'
```

### 3. Make your first GitHub connection

Create a GitHub OAuth App whose callback is `http://localhost:4242/v1/oauth/callback/github`, add its client ID and secret to `.env`, restart the server with the same encryption key, and create a connect session from your **backend**:

```bash
curl -s http://localhost:4242/v1/connect-sessions \
  -H 'Authorization: Bearer replace-this-server-secret' \
  -H 'Content-Type: application/json' \
  -d '{"external_user_id":"user-42","provider":"github","return_url":"http://localhost:3000/integrations/done"}'
```

Open the returned `connect_url` in your browser and approve the connection. The example return URL is where your own application would receive the browser after authorization. You can confirm the connection from the terminal even if you have no app running on port 3000.

List the user's connections, copy the returned ID into `CONNECTION_ID`, then fetch the signed-in GitHub profile.

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

## What gets blocked

| Attempt or condition | What happens |
| --- | --- |
| Missing or invalid server API key | The backend API rejects the request. |
| Looking up a different tenant's connection or run | The resource lookup is scoped to the caller's tenant. |
| Reusing an expired or consumed connect link or OAuth state | The connection attempt is rejected. |
| Sending a request outside the connection's origin or base path | The runtime rejects the destination. |
| An upstream redirect | The runtime does not follow it automatically. |
| A detected private, loopback, or link-local target for a user-supplied API base URL | The outbound URL checks reject it, with local development exceptions. |
| Importing a HAR that spans more than one origin or contains more than 50 requests | The import is rejected. |
| Importing known sensitive headers such as `Authorization` or `Cookie` | The importer strips them from the draft. |
| Running a workflow against a connection on a different origin | The run request is rejected. |
| Receiving a status outside a workflow step's expected statuses | The run stops and records the mismatch as drift. |

MFA, access controls, and provider permissions still apply. Review the [threat model](docs/threat-model.md) for the limits of these checks.

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

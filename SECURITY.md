# Security policy

This is experimental infrastructure that handles powerful credentials. Do not expose it to the public internet without completing the production-hardening checklist in `docs/threat-model.md`.

## Reporting a vulnerability

Do not open a public issue containing credentials, real HAR files, access tokens, cookies, customer data or exploit details. Until a private reporting address is configured, prepare a minimal redacted reproduction and contact the repository owner privately.

## Never include in a report

- live OAuth authorization codes or state values;
- access/refresh tokens, API keys or session cookies;
- passwords or MFA codes;
- unredacted HAR files;
- personal or customer data.

## Supported status

Version `0.x` is an experimental preview. There is no production support commitment or security-response SLA.

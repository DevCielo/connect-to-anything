# Contributing

Contributions that make legacy integration safer, easier to inspect and easier to self-host are welcome.

Before submitting a change:

1. Do not commit credentials, HAR captures from real accounts, cookies or customer data.
2. Keep provider scopes minimal and document why each is needed.
3. Add tests for security boundaries and failure behavior.
4. Run `npm run check` and `git diff --check`.
5. Describe limitations honestly; do not claim that a provider or workflow is production-ready without real verification.

The project will not accept features intended to bypass authentication, MFA, anti-bot controls, provider authorization or rate limits.

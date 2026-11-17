const providers = {
  github: {
    name: "GitHub",
    auth: "oauth2",
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    apiBaseUrl: "https://api.github.com/",
    defaultScopes: ["read:user"],
    clientIdEnv: "GITHUB_CLIENT_ID",
    clientSecretEnv: "GITHUB_CLIENT_SECRET",
    supportsPkce: true,
  },
  slack: {
    name: "Slack",
    auth: "oauth2",
    authorizationUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    apiBaseUrl: "https://slack.com/api/",
    defaultScopes: ["users:read"],
    clientIdEnv: "SLACK_CLIENT_ID",
    clientSecretEnv: "SLACK_CLIENT_SECRET",
    supportsPkce: false,
  },
  "http-api": {
    name: "HTTP API key",
    auth: "api_key",
    apiBaseUrl: null,
    credentialFields: ["base_url", "header_name", "api_key"],
  },
  "legacy-session": {
    name: "Legacy web session",
    auth: "api_key",
    apiBaseUrl: null,
    credentialKind: "cookie",
    credentialFields: ["base_url", "session_cookie"],
  },
};

export function getProvider(key, custom = {}) {
  const provider = Object.hasOwn(custom, key) ? custom[key] : Object.hasOwn(providers, key) ? providers[key] : null;
  if (!provider) throw Object.assign(new Error("Unknown provider"), { status: 404 });
  return { key, ...provider };
}

export function listProviders(custom = {}) {
  return Object.entries({ ...providers, ...custom }).map(([key, value]) => ({
    key,
    name: value.name,
    auth: value.auth,
    configured: value.auth === "api_key" || Boolean(process.env[value.clientIdEnv]),
  }));
}

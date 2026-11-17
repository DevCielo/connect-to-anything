import { randomBytes } from "node:crypto";

export function loadConfig(overrides = {}) {
  const nodeEnv = overrides.nodeEnv ?? process.env.NODE_ENV;
  const development = nodeEnv === "development" || overrides.development === true;
  const rawKey = overrides.encryptionKeyBase64 ?? process.env.ENCRYPTION_KEY_BASE64;
  if (!rawKey && !development) throw new Error("ENCRYPTION_KEY_BASE64 is required unless NODE_ENV=development");
  const encryptionKey = rawKey ? Buffer.from(rawKey, "base64") : randomBytes(32);
  if (encryptionKey.length !== 32) throw new Error("ENCRYPTION_KEY_BASE64 must decode to 32 bytes");

  if (!overrides.apiKeys && !process.env.API_KEYS_JSON && !development) throw new Error("API_KEYS_JSON is required unless NODE_ENV=development");
  const apiKeys = overrides.apiKeys ?? JSON.parse(process.env.API_KEYS_JSON ?? '{"dev-secret":"demo-tenant"}');
  if (!Object.keys(apiKeys).length) throw new Error("At least one server API key is required");

  return {
    port: Number(overrides.port ?? process.env.PORT ?? 4242),
    publicUrl: overrides.publicUrl ?? process.env.PUBLIC_URL ?? "http://localhost:4242",
    dbPath: overrides.dbPath ?? process.env.DB_PATH ?? "data/connect.sqlite",
    encryptionKey,
    apiKeys,
    development,
  };
}

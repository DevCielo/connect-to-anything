import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { decryptJson, encryptJson, randomToken, safeEqual, sha256 } from "./crypto.js";
import { escapeHtml, readJson, redirect, sendJson } from "./http.js";
import { getProvider, listProviders } from "./providers.js";
import { compileHar, executeWorkflow, validateWorkflow } from "./workflows.js";

const now = () => Date.now();
const jsonScopes = (row) => JSON.parse(row.scopes_json);
const connectionView = (row) => ({ id: row.id, external_user_id: row.external_user_id, provider: row.provider, scopes: jsonScopes(row), status: row.status, created_at: new Date(row.created_at).toISOString(), updated_at: new Date(row.updated_at).toISOString() });
const tokenSet = (data, previous = {}) => ({
  type: "oauth2",
  access_token: data.access_token,
  refresh_token: data.refresh_token ?? previous.refresh_token,
  token_type: data.token_type,
  expires_in: data.expires_in ?? previous.expires_in,
  scope: data.scope ?? previous.scope,
  obtained_at: now(),
});

export function createApp({ config, store, fetchImpl = fetch, customProviders = {} }) {
  async function assertSafeOutboundUrl(url) {
    if (url.protocol !== "https:" && !(config.development && ["localhost", "127.0.0.1"].includes(url.hostname))) throw Object.assign(new Error("Outbound URL must use HTTPS"), { status: 400 });
    const blocked = (address) => /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(address);
    if (blocked(url.hostname)) throw Object.assign(new Error("Private and link-local proxy targets are blocked"), { status: 400 });
    if (!config.development || !["localhost", "127.0.0.1"].includes(url.hostname)) {
      const addresses = isIP(url.hostname) ? [{ address: url.hostname }] : await lookup(url.hostname, { all: true });
      if (!addresses.length || addresses.some(({ address }) => blocked(address))) throw Object.assign(new Error("Proxy target resolves to a private or link-local address"), { status: 400 });
    }
  }

  function authenticate(req) {
    const supplied = req.headers.authorization?.replace(/^Bearer\s+/i, "") ?? "";
    const match = Object.entries(config.apiKeys).find(([key]) => safeEqual(key, supplied));
    if (!match) throw Object.assign(new Error("Invalid server API key"), { status: 401 });
    return match[1];
  }

  function sessionForToken(token) {
    const session = store.sessionByTokenHash(sha256(token));
    if (!session || session.expires_at <= now() || session.used_at) throw Object.assign(new Error("Connect session is invalid or expired"), { status: 410 });
    return session;
  }

  async function exchangeCode(provider, code, verifier) {
    const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: `${config.publicUrl}/v1/oauth/callback/${provider.key}`, client_id: process.env[provider.clientIdEnv] ?? "", code_verifier: verifier });
    const clientSecret = process.env[provider.clientSecretEnv];
    if (clientSecret) body.set("client_secret", clientSecret);
    const response = await fetchImpl(provider.tokenUrl, { method: "POST", headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" }, body });
    const data = await response.json();
    if (!response.ok || data.error) throw Object.assign(new Error(`Token exchange failed: ${data.error_description ?? data.error ?? response.status}`), { status: 502 });
    return data;
  }

  async function activeCredentials(row, provider) {
    const credentials = decryptJson(row.credentials_ciphertext, config.encryptionKey);
    if (credentials.type !== "oauth2" || !credentials.refresh_token || !credentials.expires_in || credentials.obtained_at + Number(credentials.expires_in) * 1000 - 60_000 > now()) return credentials;
    const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: credentials.refresh_token, client_id: process.env[provider.clientIdEnv] ?? "" });
    const secret = process.env[provider.clientSecretEnv]; if (secret) body.set("client_secret", secret);
    const response = await fetchImpl(provider.tokenUrl, { method:"POST", headers:{ accept:"application/json", "content-type":"application/x-www-form-urlencoded" }, body });
    const refreshed = await response.json();
    if (!response.ok || refreshed.error) throw Object.assign(new Error("Connection token refresh failed; reconnect required"), { status: 401 });
    const merged = tokenSet(refreshed, credentials);
    store.updateCredentials(row.id, row.tenant_id, encryptJson(merged, config.encryptionKey), now());
    return merged;
  }

  async function providerRequest(row, request) {
    const provider = getProvider(row.provider, customProviders); const credentials = await activeCredentials(row, provider);
    const base = new URL(credentials.base_url ?? provider.apiBaseUrl); const target = new URL(String(request.path ?? "").replace(/^\/+/, ""), base);
    const basePrefix = base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`;
    if (target.origin !== base.origin || !target.pathname.startsWith(basePrefix)) throw Object.assign(new Error("Proxy target must stay under the provider base URL"), { status: 400 });
    if (credentials.type === "api_key") await assertSafeOutboundUrl(target);
    const headers = { accept:"application/json", "user-agent":"connect-to-anything/0.2" };
    for (const [key,value] of Object.entries(request.headers ?? {})) if (/^(accept|content-type|if-match|if-none-match|x-[a-z0-9-]+)$/i.test(key)) headers[key.toLowerCase()] = String(value);
    if (credentials.type === "oauth2") headers.authorization = `Bearer ${credentials.access_token}`;
    else headers[credentials.header_name] = credentials.api_key;
    if (request.body !== undefined && !headers["content-type"]) headers["content-type"] = "application/json";
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 15_000);
    try { return await fetchImpl(target, { method:String(request.method ?? "GET").toUpperCase(), headers, body:request.body === undefined ? undefined : JSON.stringify(request.body), redirect:"manual", signal:controller.signal }); }
    finally { clearTimeout(timer); }
  }

  async function handler(req, res) {
    try {
      const url = new URL(req.url, config.publicUrl);
      const parts = url.pathname.split("/").filter(Boolean);

      if (req.method === "GET" && url.pathname === "/healthz") return sendJson(res, 200, { ok: true });
      if (req.method === "GET" && url.pathname === "/v1/providers") { authenticate(req); return sendJson(res, 200, { providers: listProviders(customProviders) }); }

      if (req.method === "POST" && url.pathname === "/v1/connect-sessions") {
        const tenantId = authenticate(req);
        const body = await readJson(req); if (!body || typeof body !== "object" || Array.isArray(body)) throw Object.assign(new Error("JSON body must be an object"), { status:400 });
        if (!body.external_user_id || !body.provider || !body.return_url) throw Object.assign(new Error("external_user_id, provider and return_url are required"), { status: 400 });
        const provider = getProvider(body.provider, customProviders);
        let returnUrl; try { returnUrl = new URL(body.return_url); } catch { throw Object.assign(new Error("return_url is invalid"), { status:400 }); }
        if (!/^https?:$/.test(returnUrl.protocol) || (returnUrl.protocol === "http:" && returnUrl.hostname !== "localhost" && returnUrl.hostname !== "127.0.0.1")) throw Object.assign(new Error("return_url must use HTTPS (HTTP is allowed on localhost)"), { status: 400 });
        const token = randomToken();
        const scopes = body.scopes ?? provider.defaultScopes ?? []; if (!Array.isArray(scopes) || scopes.some(x => typeof x !== "string")) throw Object.assign(new Error("scopes must be an array of strings"), { status:400 });
        const session = { id: randomUUID(), tokenHash: sha256(token), tenantId, externalUserId: String(body.external_user_id), provider: provider.key, returnUrl: returnUrl.href, scopes, expiresAt: now() + 10 * 60_000, createdAt: now() };
        store.createSession(session);
        return sendJson(res, 201, { connect_url: `${config.publicUrl}/connect/${token}`, expires_at: new Date(session.expiresAt).toISOString() });
      }

      if (req.method === "GET" && parts[0] === "connect" && parts.length === 2) {
        const session = sessionForToken(parts[1]);
        const provider = getProvider(session.provider, customProviders);
        const credentialFields = provider.credentialKind === "cookie" ? `<label>Session cookie<input name="api_key" type="password" required autocomplete="off" placeholder="name=value; other=value"></label><input name="header_name" type="hidden" value="Cookie">` : `<label>Header name<input name="header_name" value="Authorization" required></label><label>API key<input name="api_key" type="password" required autocomplete="off"></label>`;
        const form = provider.auth === "api_key" ? `<form method="post" action="/connect/${escapeHtml(parts[1])}/credentials"><label>API base URL<input name="base_url" type="url" required placeholder="https://legacy.example.com/"></label>${credentialFields}<button>Connect securely</button></form>` : `<form method="post" action="/connect/${escapeHtml(parts[1])}/start"><button>Continue to ${escapeHtml(provider.name)}</button></form>`;
        const html = `<!doctype html><meta name="viewport" content="width=device-width"><title>Connect ${escapeHtml(provider.name)}</title><style>body{font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px;color:#171717}main{border:1px solid #ddd;border-radius:16px;padding:32px;box-shadow:0 12px 40px #0001}label{display:grid;gap:6px;margin:16px 0}input,button{font:inherit;padding:12px;border-radius:8px;border:1px solid #bbb}button{background:#171717;color:#fff;cursor:pointer;width:100%}.muted{color:#666;font-size:14px}</style><main><p class="muted">Connect to anything</p><h1>Connect ${escapeHtml(provider.name)}</h1><p>This grants access only for <strong>${escapeHtml(session.external_user_id)}</strong>. You can disconnect at any time.</p>${form}</main>`;
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'", "x-frame-options": "DENY", "cache-control": "no-store", "referrer-policy":"no-referrer" }); return res.end(html);
      }

      if (req.method === "POST" && parts[0] === "connect" && parts[2] === "start") {
        const session = sessionForToken(parts[1]);
        const provider = getProvider(session.provider, customProviders);
        if (provider.auth !== "oauth2") throw Object.assign(new Error("Provider does not use OAuth"), { status: 400 });
        if (!process.env[provider.clientIdEnv]) throw Object.assign(new Error("Provider is not configured"), { status:503 });
        const state = randomToken(); const verifier = randomToken(48); const challenge = sha256(verifier);
        store.createState({ stateHash: sha256(state), sessionId: session.id, tenantId: session.tenant_id, verifierCiphertext: encryptJson({ verifier }, config.encryptionKey), expiresAt: now() + 10 * 60_000 });
        const target = new URL(provider.authorizationUrl);
        target.searchParams.set("response_type", "code"); target.searchParams.set("client_id", process.env[provider.clientIdEnv] ?? ""); target.searchParams.set("redirect_uri", `${config.publicUrl}/v1/oauth/callback/${provider.key}`); target.searchParams.set("state", state); target.searchParams.set("scope", jsonScopes(session).join(" "));
        if (provider.supportsPkce !== false) { target.searchParams.set("code_challenge", challenge); target.searchParams.set("code_challenge_method", "S256"); }
        return redirect(res, target.href);
      }

      if (req.method === "POST" && parts[0] === "connect" && parts[2] === "credentials") {
        const session = sessionForToken(parts[1]); const provider = getProvider(session.provider, customProviders);
        if (provider.auth !== "api_key") throw Object.assign(new Error("Provider does not accept API keys"), { status: 400 });
        const chunks=[]; let formSize=0; for await(const chunk of req){ formSize+=chunk.length; if(formSize>64_000) throw Object.assign(new Error("Request body too large"),{status:413}); chunks.push(chunk); }
        const form = new URLSearchParams(Buffer.concat(chunks).toString());
        let base; try { base = new URL(form.get("base_url")); } catch { throw Object.assign(new Error("API base URL is invalid"), { status:400 }); } await assertSafeOutboundUrl(base);
        const headerName = form.get("header_name");
        const forbiddenHeaders = new Set(["host","cookie","content-length","connection","transfer-encoding","proxy-authorization"]);
        const explicitCookie = provider.credentialKind === "cookie" && headerName === "Cookie";
        if (!/^[A-Za-z0-9-]{1,64}$/.test(headerName ?? "") || (forbiddenHeaders.has(headerName.toLowerCase()) && !explicitCookie)) throw Object.assign(new Error("Invalid or unsafe header name"), { status: 400 });
        if (!form.get("api_key")) throw Object.assign(new Error("API key is required"), { status:400 });
        if (!store.useSession(session.id, now())) throw Object.assign(new Error("Connect session was already used"), { status: 409 });
        const id = store.upsertConnection({ id:randomUUID(), tenantId: session.tenant_id, externalUserId: session.external_user_id, provider: provider.key, credentialsCiphertext: encryptJson({ type:"api_key", base_url:base.href, header_name:headerName, api_key:form.get("api_key") }, config.encryptionKey), scopes: [], now: now() });
        const done = new URL(session.return_url); done.searchParams.set("connection_id", id); done.searchParams.set("status", "connected"); return redirect(res, done.href);
      }

      if (req.method === "GET" && parts[0] === "v1" && parts[1] === "oauth" && parts[2] === "callback" && parts[3]) {
        const state = store.consumeState(sha256(url.searchParams.get("state") ?? ""), now());
        if (!state) throw Object.assign(new Error("OAuth state is invalid, expired or already used"), { status: 400 });
        const session = store.sessionById(state.session_id);
        if (!session || session.tenant_id !== state.tenant_id || session.provider !== parts[3]) throw Object.assign(new Error("OAuth session mismatch"), { status: 400 });
        if (url.searchParams.get("error")) throw Object.assign(new Error(`Provider denied access: ${url.searchParams.get("error")}`), { status: 400 });
        if (!url.searchParams.get("code")) throw Object.assign(new Error("Provider callback is missing an authorization code"), { status:400 });
        if (!store.useSession(session.id, now())) throw Object.assign(new Error("OAuth connect session was already used"), { status:409 });
        const provider = getProvider(parts[3], customProviders); const { verifier } = decryptJson(state.verifier_ciphertext, config.encryptionKey);
        const tokens = await exchangeCode(provider, url.searchParams.get("code"), verifier);
        const scopes = tokens.scope ? String(tokens.scope).split(/[ ,]+/) : jsonScopes(session);
        const id = store.upsertConnection({ id:randomUUID(), tenantId: session.tenant_id, externalUserId: session.external_user_id, provider: provider.key, credentialsCiphertext: encryptJson(tokenSet(tokens), config.encryptionKey), scopes, now: now() });
        const done = new URL(session.return_url); done.searchParams.set("connection_id", id); done.searchParams.set("status", "connected"); return redirect(res, done.href);
      }

      if (url.pathname === "/v1/connections" && req.method === "GET") { const tenant = authenticate(req); return sendJson(res, 200, { connections: store.connections(tenant, url.searchParams.get("external_user_id")).map(connectionView) }); }

      if (url.pathname === "/v1/workflows" && req.method === "GET") { const tenant=authenticate(req); return sendJson(res,200,{ workflows:store.workflows(tenant).map(w=>({...w,created_at:new Date(w.created_at).toISOString(),updated_at:new Date(w.updated_at).toISOString()})) }); }

      if (url.pathname === "/v1/workflows" && req.method === "POST") {
        const tenant=authenticate(req); const body=await readJson(req,2*1024*1024); const definition=validateWorkflow(body?.definition); const name=String(body?.name ?? definition.name); const version=store.nextWorkflowVersion(tenant,name); const id=randomUUID();
        store.createWorkflow({ id,tenantId:tenant,name,version,definition:{...definition,name},source:"declarative",now:now() }); return sendJson(res,201,{id,name,version});
      }

      if (url.pathname === "/v1/workflows/import-har" && req.method === "POST") {
        const tenant=authenticate(req); const body=await readJson(req,2*1024*1024); const definition=compileHar(body?.har,{name:String(body?.name ?? "")}); const version=store.nextWorkflowVersion(tenant,definition.name); const id=randomUUID();
        store.createWorkflow({ id,tenantId:tenant,name:definition.name,version,definition,source:"sanitized-har",now:now() }); return sendJson(res,201,{id,name:definition.name,version,steps:definition.steps.length,review_required:true});
      }

      if (parts[0]==="v1" && parts[1]==="workflows" && parts[2] && parts[3]==="runs" && req.method==="POST") {
        const tenant=authenticate(req); const workflow=store.workflow(parts[2],tenant); if(!workflow) throw Object.assign(new Error("Workflow not found"),{status:404});
        const body=await readJson(req); const connection=store.connection(body?.connection_id,tenant); if(!connection) throw Object.assign(new Error("Connection not found"),{status:404});
        const definition=JSON.parse(workflow.definition_json); const provider=getProvider(connection.provider,customProviders); const credentials=decryptJson(connection.credentials_ciphertext,config.encryptionKey); const base=new URL(credentials.base_url ?? provider.apiBaseUrl);
        if(new URL(definition.origin).origin!==base.origin) throw Object.assign(new Error("Workflow origin does not match the selected connection"),{status:400});
        const runId=randomUUID(); store.createRun({id:runId,tenantId:tenant,workflowId:workflow.id,connectionId:connection.id,startedAt:now()});
        try { const outcome=await executeWorkflow({definition,inputs:body.inputs,request:reqDef=>providerRequest(connection,reqDef)}); store.finishRun(runId,tenant,"succeeded",outcome.steps,null,now()); return sendJson(res,200,{run_id:runId,status:"succeeded",steps:outcome.steps,outputs:outcome.outputs}); }
        catch(error){ const status=error.drift?"drifted":"failed"; store.finishRun(runId,tenant,status,error.results??[],error.message,now()); return sendJson(res,error.drift?409:502,{run_id:runId,status,error:error.message,steps:error.results??[]}); }
      }

      if(parts[0]==="v1" && parts[1]==="runs" && parts[2] && req.method==="GET") { const tenant=authenticate(req); const run=store.run(parts[2],tenant); if(!run) throw Object.assign(new Error("Run not found"),{status:404}); return sendJson(res,200,{id:run.id,workflow_id:run.workflow_id,connection_id:run.connection_id,status:run.status,steps:JSON.parse(run.steps_json),error:run.error,started_at:new Date(run.started_at).toISOString(),finished_at:run.finished_at?new Date(run.finished_at).toISOString():null}); }

      if (parts[0] === "v1" && parts[1] === "connections" && parts[2] && req.method === "DELETE") { const tenant = authenticate(req); if (!store.disconnect(parts[2], tenant, now())) throw Object.assign(new Error("Connection not found"), { status: 404 }); return sendJson(res, 200, { status: "disconnected" }); }

      if (parts[0] === "v1" && parts[1] === "connections" && parts[3] === "proxy" && req.method === "POST") {
        const tenant = authenticate(req); const row = store.connection(parts[2], tenant); if (!row) throw Object.assign(new Error("Connection not found"), { status: 404 });
        const request = await readJson(req); if (!request || typeof request !== "object" || Array.isArray(request)) throw Object.assign(new Error("JSON body must be an object"), {status:400}); const method = String(request.method ?? "GET").toUpperCase();
        if (!["GET","POST","PUT","PATCH","DELETE"].includes(method)) throw Object.assign(new Error("Unsupported method"), { status: 400 });
        const upstream = await providerRequest(row, request);
        const responseText = await upstream.text(); let responseBody; try { responseBody = JSON.parse(responseText); } catch { responseBody = responseText; }
        return sendJson(res, upstream.status, { status: upstream.status, headers: { "content-type": upstream.headers.get("content-type") }, body: responseBody });
      }

      throw Object.assign(new Error("Not found"), { status: 404 });
    } catch (error) { sendJson(res, error.status ?? 500, { error: error.status ? error.message : "Internal server error" }); }
  }
  return createServer(handler);
}

import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { loadConfig } from "../src/config.js";
import { createStore } from "../src/store.js";
import { createApp } from "../src/app.js";

async function fixture() {
  const store = createStore(":memory:");
  const key = Buffer.alloc(32, 7).toString("base64");
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith("/token")) return new Response(JSON.stringify({ access_token:"secret-token", token_type:"Bearer", scope:"profile" }), { status:200, headers:{"content-type":"application/json"} });
    return new Response(JSON.stringify({ ok:true, authorization:init.headers.authorization }), { status:200, headers:{"content-type":"application/json"} });
  };
  const providers = { mock:{ name:"Mock", auth:"oauth2", authorizationUrl:"https://auth.example/authorize", tokenUrl:"https://auth.example/token", apiBaseUrl:"https://api.example/v1/", defaultScopes:["profile"], clientIdEnv:"MOCK_ID", clientSecretEnv:"MOCK_SECRET", supportsPkce:true } };
  process.env.MOCK_ID = "client"; process.env.MOCK_SECRET = "secret";
  const config = loadConfig({ port:0, publicUrl:"http://127.0.0.1", dbPath:":memory:", encryptionKeyBase64:key, apiKeys:{"test-key":"tenant-a"} });
  const server = createApp({ config, store, fetchImpl:fakeFetch, customProviders:providers }); server.listen(0); await once(server,"listening");
  const base = `http://127.0.0.1:${server.address().port}`; config.publicUrl = base;
  return { base, calls, store, close:()=>new Promise(r=>server.close(()=>{store.close();r()})) };
}

const api = (url, init={}) => fetch(url, { ...init, headers:{ authorization:"Bearer test-key", "content-type":"application/json", ...init.headers }, redirect:"manual" });

test("OAuth connect is one-time, PKCE protected, tenant scoped and proxyable", async () => {
  const f = await fixture();
  try {
    const created = await api(`${f.base}/v1/connect-sessions`, { method:"POST", body:JSON.stringify({ external_user_id:"user-1", provider:"mock", return_url:"http://localhost/done" }) });
    assert.equal(created.status, 201); const { connect_url } = await created.json();
    const start = await fetch(`${connect_url}/start`, { method:"POST", redirect:"manual" }); assert.equal(start.status,302);
    const auth = new URL(start.headers.get("location")); assert.equal(auth.searchParams.get("code_challenge_method"),"S256"); assert.ok(auth.searchParams.get("code_challenge"));
    const callback = await fetch(`${f.base}/v1/oauth/callback/mock?code=abc&state=${auth.searchParams.get("state")}`, { redirect:"manual" }); assert.equal(callback.status,302);
    const done = new URL(callback.headers.get("location")); const id = done.searchParams.get("connection_id"); assert.ok(id);
    const replay = await fetch(`${f.base}/v1/oauth/callback/mock?code=abc&state=${auth.searchParams.get("state")}`); assert.equal(replay.status,400);
    const listed = await api(`${f.base}/v1/connections?external_user_id=user-1`); const listBody=await listed.json(); assert.equal(listBody.connections.length,1); assert.equal(listBody.connections[0].provider,"mock"); assert.equal(JSON.stringify(listBody).includes("secret-token"),false);
    const proxied = await api(`${f.base}/v1/connections/${id}/proxy`, { method:"POST", body:JSON.stringify({ path:"me" }) }); assert.equal(proxied.status,200); const proxyBody=await proxied.json(); assert.equal(proxyBody.body.authorization,"Bearer secret-token");
    const workflowCreated=await api(`${f.base}/v1/workflows`,{method:"POST",body:JSON.stringify({name:"Read profile",definition:{schema_version:1,name:"Read profile",origin:"https://api.example",inputs:{},steps:[{id:"read",request:{method:"GET",path:"me"},assert:{status:[200]},extract:{authorized:"authorization"}}]}})}); assert.equal(workflowCreated.status,201); const workflow=await workflowCreated.json();
    const run=await api(`${f.base}/v1/workflows/${workflow.id}/runs`,{method:"POST",body:JSON.stringify({connection_id:id,inputs:{}})}); assert.equal(run.status,200); const runBody=await run.json(); assert.equal(runBody.status,"succeeded"); assert.equal(runBody.outputs.read.extracted.authorized,"[REDACTED]");
    const storedRun=await api(`${f.base}/v1/runs/${runBody.run_id}`); assert.equal(storedRun.status,200); assert.equal((await storedRun.json()).status,"succeeded");
    const disconnected = await api(`${f.base}/v1/connections/${id}`, { method:"DELETE" }); assert.equal(disconnected.status,200);
    const after = await api(`${f.base}/v1/connections/${id}/proxy`, { method:"POST", body:JSON.stringify({path:"me"}) }); assert.equal(after.status,404);
  } finally { await f.close(); }
});

test("rejects bad API keys, unsafe returns and cross-origin proxy paths", async () => {
  const f = await fixture();
  try {
    assert.equal((await fetch(`${f.base}/v1/connections`)).status,401);
    const unsafe = await api(`${f.base}/v1/connect-sessions`, { method:"POST", body:JSON.stringify({ external_user_id:"u", provider:"mock", return_url:"http://evil.example/done" }) }); assert.equal(unsafe.status,400);
  } finally { await f.close(); }
});

import { randomUUID } from "node:crypto";

const SENSITIVE_KEY = /pass(word)?|secret|token|api[-_]?key|authorization|cookie|session|csrf/i;
const SAFE_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const MAX_STEPS = 50;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (typeof value === "string" && (/^(bearer|basic)\s+/i.test(value) || /^xox[a-z]-/i.test(value) || /^[\w-]{20,}\.[\w-]{10,}\.[\w-]{10,}$/.test(value))) return "[REDACTED]";
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SENSITIVE_KEY.test(key) ? "[REDACTED]" : redact(item)]));
}

function safeHeaders(headers = []) {
  const blocked = /^(authorization|cookie|set-cookie|proxy-authorization|host|content-length|connection|transfer-encoding)$/i;
  return Object.fromEntries(headers.filter(h => h?.name && !blocked.test(h.name) && !SENSITIVE_KEY.test(h.name)).map(h => [h.name.toLowerCase(), String(h.value ?? "")]));
}

function safeUrl(raw) {
  const url = new URL(raw);
  for (const key of [...url.searchParams.keys()]) if (SENSITIVE_KEY.test(key)) url.searchParams.set(key, "[REDACTED]");
  url.username = ""; url.password = ""; url.hash = "";
  return url;
}

function parseBody(postData) {
  if (!postData?.text) return undefined;
  if (postData.mimeType?.includes("json")) {
    try { return redact(JSON.parse(postData.text)); } catch { return undefined; }
  }
  return undefined;
}

export function compileHar(har, { name }) {
  const entries = har?.log?.entries;
  if (!name || !Array.isArray(entries) || !entries.length) throw Object.assign(new Error("A workflow name and non-empty HAR log.entries are required"), { status:400 });
  if (entries.length > MAX_STEPS) throw Object.assign(new Error(`HAR has more than ${MAX_STEPS} requests; capture a smaller workflow`), { status:400 });
  const origins = new Set();
  const steps = entries.map((entry, index) => {
    const method = String(entry.request?.method ?? "").toUpperCase();
    if (!SAFE_METHODS.has(method)) throw Object.assign(new Error(`Unsupported method at HAR entry ${index}`), { status:400 });
    const url = safeUrl(entry.request?.url); origins.add(url.origin);
    const expected = Number(entry.response?.status);
    return {
      id: `step_${index + 1}`,
      name: entry.comment || `${method} ${url.pathname}`,
      request: { method, path: `${url.pathname}${url.search}`, headers: safeHeaders(entry.request.headers), ...(parseBody(entry.request.postData) === undefined ? {} : { body:parseBody(entry.request.postData) }) },
      assert: { status: Number.isInteger(expected) && expected > 0 ? [expected] : [200,201,202,204] },
      extract: {},
    };
  });
  if (origins.size !== 1) throw Object.assign(new Error("One workflow may target only one origin"), { status:400 });
  return { schema_version:1, name, origin:[...origins][0], inputs:{}, steps };
}

export function validateWorkflow(definition) {
  if (!definition || definition.schema_version !== 1 || !definition.name || !Array.isArray(definition.steps) || !definition.steps.length || definition.steps.length > MAX_STEPS) throw Object.assign(new Error("Invalid workflow definition"), { status:400 });
  new URL(definition.origin);
  for (const [index, step] of definition.steps.entries()) {
    if (!step.id || !step.request || !SAFE_METHODS.has(String(step.request.method).toUpperCase()) || typeof step.request.path !== "string") throw Object.assign(new Error(`Invalid workflow step ${index + 1}`), { status:400 });
    if (/^https?:\/\//i.test(step.request.path)) throw Object.assign(new Error(`Step ${index + 1} path must be relative`), { status:400 });
  }
  return definition;
}

function valueAt(value, path) { return String(path).split(".").reduce((current, key) => current?.[key], value); }
function render(value, context) {
  if (Array.isArray(value)) return value.map(item => render(item, context));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,render(v,context)]));
  if (typeof value !== "string") return value;
  const exact = value.match(/^\{\{\s*([\w.]+)\s*\}\}$/); if (exact) return valueAt(context, exact[1]);
  return value.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, path) => String(valueAt(context,path) ?? ""));
}

async function boundedBody(response) {
  const declared = Number(response.headers.get("content-length") ?? 0); if (declared > MAX_RESPONSE_BYTES) throw new Error("Upstream response is too large");
  const bytes = Buffer.from(await response.arrayBuffer()); if (bytes.length > MAX_RESPONSE_BYTES) throw new Error("Upstream response is too large");
  const text = bytes.toString(); try { return JSON.parse(text); } catch { return text; }
}

export async function executeWorkflow({ definition, inputs, request, onStep }) {
  validateWorkflow(definition);
  const context = { inputs:inputs ?? {}, steps:{} }; const results=[];
  for (const step of definition.steps) {
    const rendered = render(step.request, context);
    const response = await request(rendered); const body = await boundedBody(response);
    const allowed = step.assert?.status ?? [200,201,202,204];
    const result = { id:step.id, name:step.name, status:response.status, ok:allowed.includes(response.status), body:redact(body) };
    results.push(result); await onStep?.(result);
    if (!result.ok) throw Object.assign(new Error(`Drift detected at ${step.id}: expected ${allowed.join("/")}, got ${response.status}`), { results, drift:true });
    const extracted={}; for (const [key,path] of Object.entries(step.extract ?? {})) extracted[key]=valueAt(body,path);
    context.steps[step.id]={ status:response.status, body, extracted };
  }
  const outputs=Object.fromEntries(Object.entries(context.steps).map(([id,step])=>[id,{status:step.status,extracted:redact(step.extracted)}]));
  return { id:randomUUID(), outputs, steps:results };
}

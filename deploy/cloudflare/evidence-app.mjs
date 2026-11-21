import { DurableObject } from "cloudflare:workers";

const MAX_BODY = 1_048_576;
const RETENTION_MS = 3 * 24 * 60 * 60 * 1000;
const response = (status, body) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json" },
});
const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (value) => Uint8Array.from(value.match(/../g) ?? [], (x) => parseInt(x, 16));
const digest = async (bytes) => hex(await crypto.subtle.digest("SHA-256", bytes));
const validOrigin = (value) => {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password && u.pathname === "/" && !u.search && !u.hash ? u.origin : null;
  } catch { return null; }
};
function settings(env) {
  const origin = validOrigin(env.HOSTED_ASSURANCE_ORIGIN);
  let repositories;
  try { repositories = JSON.parse(env.ALLOWED_REPOSITORIES); } catch { repositories = null; }
  if (!origin || typeof env.GITHUB_WEBHOOK_SECRET !== "string" || new TextEncoder().encode(env.GITHUB_WEBHOOK_SECRET).length < 32 ||
      !Array.isArray(repositories) || repositories.length === 0 || repositories.some((x) => typeof x !== "string" || !/^[^/\s]+\/[^/\s]+$/.test(x)) ||
      !env.DELIVERIES || !env.DELIVERY_BODIES) return null;
  return { origin, repositories: new Set(repositories), secret: env.GITHUB_WEBHOOK_SECRET };
}
async function readBounded(request) {
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = []; let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY) { await reader.cancel(); throw new RangeError("body too large"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const out = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}
async function signatureValid(body, signature, secret) {
  if (!/^sha256=[0-9a-f]{64}$/i.test(signature)) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));
  const actual = fromHex(signature.slice(7));
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) mismatch |= expected[i] ^ actual[i];
  return mismatch === 0;
}
function webhookHeaders(request) {
  return {
    signature: request.headers.get("X-Hub-Signature-256") ?? "",
    event: request.headers.get("X-GitHub-Event") ?? "",
    delivery: request.headers.get("X-GitHub-Delivery") ?? "",
  };
}
function validDelivery(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function repositoryOf(payload) {
  const owner = payload?.repository?.owner?.login;
  const name = payload?.repository?.name;
  const fullName = payload?.repository?.full_name;
  return typeof owner === "string" && typeof name === "string" && fullName === `${owner}/${name}` ? fullName : "";
}
async function ready(origin, env) {
  try {
    const r = await fetch(`${origin}/readyz`, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(5000), headers: { accept: "application/json" } });
    return r.status === 200;
  } catch { return false; }
}
function pathMethod(request, path, method) { return new URL(request.url).pathname === path && request.method === method; }
function parsedPayload(body) {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
}
async function acceptWebhook(request, env, config) {
  let body;
  try { body = await readBounded(request); } catch (e) {
    const tooLarge = e instanceof RangeError;
    return response(tooLarge ? 413 : 400, { error: tooLarge ? "E_WEBHOOK_BODY_TOO_LARGE" : "E_WEBHOOK_BODY" });
  }
  const headers = webhookHeaders(request);
  if (!await signatureValid(body, headers.signature, config.secret)) return response(401, { error: "E_WEBHOOK_SIGNATURE" });
  if (!/^[a-z_]{1,64}$/.test(headers.event) || !validDelivery(headers.delivery)) return response(400, { error: "E_WEBHOOK_HEADERS" });
  let payload;
  try { payload = parsedPayload(body); } catch { return response(400, { error: "E_WEBHOOK_BODY" }); }
  if (headers.event === "ping") return response(200, { status: "authenticated", markers: ["GITHUB_PING_AUTHENTICATED"] });
  if (headers.event !== "pull_request") return response(202, { status: "ignored", markers: ["GITHUB_EVENT_IGNORED"] });
  const repository = repositoryOf(payload);
  if (!config.repositories.has(repository)) return response(403, { error: "E_REPOSITORY_NOT_ALLOWED" });
  const payloadSha = await digest(body);
  try {
    const escrow = env.DELIVERY_BODIES.getByName(repository);
    await escrow.put(headers.delivery, payloadSha, body, Date.now() + RETENTION_MS);
    await env.DELIVERIES.send({ repository, digest: payloadSha, delivery: headers.delivery, event: headers.event, signature: headers.signature });
  } catch { return response(503, { error: "CLOUDFLARE_DELIVERY_NOT_QUEUED" }); }
  return response(202, { status: "queued", markers: ["CLOUDFLARE_DELIVERY_QUEUED"], event: { delivery_id: headers.delivery, payload_sha256: payloadSha } });
}

/** Authenticate and queue bounded raw webhook transport without a verdict. */
export async function fetchRequest(request, env) {
  if (pathMethod(request, "/healthz", "GET")) return response(200, { status: "live", markers: ["CLOUDFLARE_EDGE_LIVE"] });
  const config = settings(env);
  if (!config) return response(503, { error: "CLOUDFLARE_NOT_READY" });
  if (pathMethod(request, "/readyz", "GET")) {
    return await ready(config.origin, env) ? response(200, { status: "ready", markers: ["HOSTED_BACKEND_READY"] }) : response(503, { error: "HOSTED_BACKEND_NOT_READY" });
  }
  if (!pathMethod(request, "/v1/github/webhooks", "POST")) return response(404, { error: "NOT_FOUND" });
  return acceptWebhook(request, env, config);
}

function validPointer(pointer, config) {
  return Boolean(pointer && typeof pointer.repository === "string" && config.repositories.has(pointer.repository) &&
    /^[a-f0-9]{64}$/.test(pointer.digest) && pointer.event === "pull_request" && validDelivery(pointer.delivery) && typeof pointer.signature === "string");
}
async function verifiedQueuedBody(pointer, env, config) {
  const body = await env.DELIVERY_BODIES.getByName(pointer.repository).get(pointer.delivery, pointer.digest);
  if (!(body instanceof Uint8Array) || body.byteLength === 0 || body.byteLength > MAX_BODY || await digest(body) !== pointer.digest ||
      !await signatureValid(body, pointer.signature, config.secret)) throw new Error("escrow integrity failure");
  if (repositoryOf(parsedPayload(body)) !== pointer.repository) throw new Error("repository mismatch");
  return body;
}
function validHostedReceipt(result, pointer) {
  const markers = result?.markers;
  return Array.isArray(markers) && (markers.includes("HOSTED_INGRESS_TRANSACTIONAL") || markers.includes("HOSTED_INGRESS_DUPLICATE_ACCEPTED")) &&
    result?.event?.delivery_id === pointer.delivery && result?.event?.payload_sha256 === pointer.digest && result?.event?.repository === pointer.repository;
}
async function forwardToHosted(pointer, body, config) {
  const r = await fetch(`${config.origin}/v1/github/webhooks`, {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(5000), body,
    headers: { "content-type": "application/json", "X-Hub-Signature-256": pointer.signature,
      "X-GitHub-Event": pointer.event, "X-GitHub-Delivery": pointer.delivery, "X-Factory-Delivery-Mode": "queue-retry" },
  });
  if (![200, 201, 202].includes(r.status)) throw new Error("hosted ingress rejected delivery");
  const result = await r.json();
  if (!validHostedReceipt(result, pointer)) throw new Error("hosted ingress receipt mismatch");
}

/** Recheck queued bytes and await authoritative hosted ingress before acknowledgement. */
export async function consumeMessage(message, env) {
  try {
    const config = settings(env);
    if (!config) throw new Error("configuration unavailable");
    const p = message.body;
    if (!validPointer(p, config)) throw new Error("invalid queue pointer");
    const body = await verifiedQueuedBody(p, env, config);
    await forwardToHosted(p, body, config);
    message.ack();
    return { status: "forwarded", markers: ["CLOUDFLARE_DELIVERY_FORWARDED"], event: { delivery_id: p.delivery, payload_sha256: p.digest, repository: p.repository } };
  } catch {
    message.retry();
  }
}

export class DeliveryEscrow extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS escrow (delivery_id TEXT NOT NULL, digest TEXT NOT NULL, body BLOB NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (delivery_id, digest))");
      await this.scheduleExpiry();
    });
  }
  async put(deliveryId, digestValue, bodyValue, expiresAt) {
    const body = bodyValue instanceof Uint8Array ? bodyValue : new Uint8Array(bodyValue);
    if (!validDelivery(deliveryId) || !/^[a-f0-9]{64}$/.test(digestValue) || body.length === 0 || body.length > MAX_BODY || await digest(body) !== digestValue) throw new Error("invalid escrow body");
    const now = Date.now();
    this.ctx.storage.sql.exec("INSERT OR IGNORE INTO escrow (delivery_id, digest, body, expires_at) VALUES (?, ?, ?, ?)", deliveryId, digestValue, body, Math.min(expiresAt, now + RETENTION_MS));
    const row = this.ctx.storage.sql.exec("SELECT body, expires_at FROM escrow WHERE delivery_id = ? AND digest = ?", deliveryId, digestValue).toArray()[0];
    if (!row || row.expires_at <= now || hex(await crypto.subtle.digest("SHA-256", row.body)) !== digestValue) throw new Error("escrow collision or expired content");
    await this.scheduleExpiry();
  }
  async get(deliveryId, digestValue) {
    if (!validDelivery(deliveryId) || !/^[a-f0-9]{64}$/.test(digestValue)) throw new Error("invalid escrow key");
    const row = this.ctx.storage.sql.exec("SELECT body, expires_at FROM escrow WHERE delivery_id = ? AND digest = ?", deliveryId, digestValue).toArray()[0];
    if (!row || row.expires_at <= Date.now()) throw new Error("escrow unavailable");
    return new Uint8Array(row.body);
  }
  async alarm() {
    this.ctx.storage.sql.exec("DELETE FROM escrow WHERE expires_at <= ?", Date.now());
    await this.scheduleExpiry();
  }
  async scheduleExpiry() {
    const row = this.ctx.storage.sql.exec("SELECT MIN(expires_at) AS next FROM escrow").toArray()[0];
    if (row?.next) await this.ctx.storage.setAlarm(row.next);
    else await this.ctx.storage.deleteAlarm();
  }
}

export default {
  fetch(request, env) { return fetchRequest(request, env); },
  queue(batch, env) { return Promise.all(batch.messages.map((message) => consumeMessage(message, env))); },
};

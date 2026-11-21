import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// Node-only import shim: these tests exercise handler logic, not Workers native storage.
const source = (await readFile(new URL("./evidence-app.mjs", import.meta.url), "utf8"))
  .replace('import { DurableObject } from "cloudflare:workers";', "class DurableObject { constructor(ctx) { this.ctx = ctx; } }");
const app = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
const secret = "unit-test-secret-with-at-least-thirty-two-bytes";
const id = "123e4567-e89b-42d3-a456-426614174000";
const body = new TextEncoder().encode(JSON.stringify({ action: "opened", repository: { name: "repo", full_name: "acme/repo", owner: { login: "acme" } } }));
const sha = (bytes) => crypto.subtle.digest("SHA-256", bytes).then((x) => Buffer.from(x).toString("hex"));
const sign = async (bytes) => {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return `sha256=${Buffer.from(await crypto.subtle.sign("HMAC", key, bytes)).toString("hex")}`;
};
function modeledSql() {
  const rows = new Map();
  return {
    rows,
    exec(query, ...args) {
      if (query.startsWith("CREATE TABLE")) return { toArray: () => [] };
      if (query.startsWith("INSERT OR IGNORE")) {
        const [delivery, digest, body, expires] = args; const key = `${delivery}:${digest}`;
        if (!rows.has(key)) rows.set(key, { delivery_id: delivery, digest, body: body.slice(), expires_at: expires });
        return { toArray: () => [] };
      }
      if (query.startsWith("SELECT body")) {
        const row = rows.get(`${args[0]}:${args[1]}`);
        return { toArray: () => row ? [{ ...row, body: row.body.slice() }] : [] };
      }
      if (query.startsWith("SELECT MIN")) {
        const expiries = [...rows.values()].map((x) => x.expires_at);
        return { toArray: () => [{ next: expiries.length ? Math.min(...expiries) : null }] };
      }
      if (query.startsWith("DELETE")) {
        for (const [key, row] of rows) if (row.expires_at <= args[0]) rows.delete(key);
        return { toArray: () => [] };
      }
      throw new Error(`unexpected SQL in model: ${query}`);
    },
  };
}
function modeledContext() {
  const sql = modeledSql(); const state = { alarm: undefined };
  const ctx = { storage: { sql, async setAlarm(value) { state.alarm = value; }, async deleteAlarm() { state.alarm = undefined; } },
    blockConcurrencyWhile(fn) { this.ready = fn(); } };
  return { ctx, state, sql };
}
function env(overrides = {}) {
  return { HOSTED_ASSURANCE_ORIGIN: "https://assurance.example", ALLOWED_REPOSITORIES: '["acme/repo"]', GITHUB_WEBHOOK_SECRET: secret,
    stored: new Map(), queued: [], ...overrides };
}
function bindEnv(overrides = {}) {
  const e = env(overrides); const thisStore = e.stored; const thisQueue = e.queued;
  e.DELIVERY_BODIES = { getByName() { return { async put(delivery, k, v) { thisStore.set(`${delivery}:${k}`, v.slice()); }, async get(delivery, k) { return thisStore.get(`${delivery}:${k}`)?.slice(); } }; } };
  e.DELIVERIES = overrides.DELIVERIES ?? { async send(v) { thisQueue.push(v); } };
  return e;
}
async function webhook(bodyBytes = body, { event = "pull_request", delivery = id, signature } = {}) {
  return new Request("https://worker.example/v1/github/webhooks", { method: "POST", body: bodyBytes,
    headers: { "X-Hub-Signature-256": signature ?? await sign(bodyBytes), "X-GitHub-Event": event, "X-GitHub-Delivery": delivery } });
}

test("health is liveness; unconfigured edge never claims ready", async () => {
  assert.equal((await app.fetchRequest(new Request("https://w/healthz"), {})).status, 200);
  const r = await app.fetchRequest(new Request("https://w/readyz"), {});
  assert.equal(r.status, 503); assert.equal((await r.json()).error, "CLOUDFLARE_NOT_READY");
});

test("signed ping is acknowledged without escrow or queue work", async () => {
  const e = bindEnv(); const r = await app.fetchRequest(await webhook(new TextEncoder().encode("{}"), { event: "ping" }), e);
  assert.equal(r.status, 200); assert.equal(e.queued.length, 0); assert.equal(e.stored.size, 0);
});

test("allowed pull request stores bytes privately and queues only a pointer", async () => {
  const e = bindEnv(); const r = await app.fetchRequest(await webhook(), e); const result = await r.json();
  assert.equal(r.status, 202); assert.equal(result.markers[0], "CLOUDFLARE_DELIVERY_QUEUED");
  assert.deepEqual(Object.keys(e.queued[0]).sort(), ["delivery", "digest", "event", "repository", "signature"]);
  assert.equal(e.queued[0].repository, "acme/repo"); assert.equal(e.queued[0].digest, await sha(body));
  assert.deepEqual([...e.stored.values()][0], body);
});

test("bad HMAC, disallowed repository, oversized body and queue failure do not report queued", async () => {
  let e = bindEnv(); let r = await app.fetchRequest(await webhook(body, { signature: `sha256=${"0".repeat(64)}` }), e);
  assert.equal(r.status, 401); assert.equal(e.queued.length, 0);
  const other = new TextEncoder().encode(JSON.stringify({ repository: { name: "else", full_name: "acme/else", owner: { login: "acme" } } }));
  r = await app.fetchRequest(await webhook(other), e); assert.equal(r.status, 403); assert.equal(e.queued.length, 0);
  const inconsistent = new TextEncoder().encode(JSON.stringify({ repository: { name: "repo", full_name: "acme/else", owner: { login: "acme" } } }));
  r = await app.fetchRequest(await webhook(inconsistent), e); assert.equal(r.status, 403); assert.equal(e.queued.length, 0);
  r = await app.fetchRequest(await webhook(new Uint8Array(1_048_577)), e); assert.equal(r.status, 413);
  e = bindEnv({ DELIVERIES: { async send() { throw new Error("queue unavailable"); } } });
  r = await app.fetchRequest(await webhook(), e); assert.equal(r.status, 503); assert.equal((await r.json()).error, "CLOUDFLARE_DELIVERY_NOT_QUEUED");
});

test("consumer forwards only fixed-origin authenticated retry and acks matching hosted receipt", async () => {
  const e = bindEnv(); const signature = await sign(body); const digest = await sha(body);
  e.stored.set(`${id}:${digest}`, body); let outbound;
  globalThis.fetch = async (url, init) => {
    outbound = { url, init };
    return new Response(JSON.stringify({ markers: ["HOSTED_INGRESS_TRANSACTIONAL"], event: { delivery_id: id, payload_sha256: digest, repository: "acme/repo" } }), { status: 202, headers: { "content-type": "application/json" } });
  };
  const calls = []; const forwarded = await app.consumeMessage({ body: { repository: "acme/repo", digest, delivery: id, event: "pull_request", signature }, ack() { calls.push("ack"); }, retry() { calls.push("retry"); } }, e);
  assert.deepEqual(calls, ["ack"]); assert.equal(outbound.url, "https://assurance.example/v1/github/webhooks");
  assert.deepEqual(forwarded.markers, ["CLOUDFLARE_DELIVERY_FORWARDED"]);
  assert.equal(outbound.init.redirect, "manual"); assert.equal(outbound.init.headers["X-Factory-Delivery-Mode"], "queue-retry");
  assert.equal(outbound.init.headers.authorization, undefined); assert.equal(outbound.init.headers.cookie, undefined);
});

test("tampered bytes, conflicts, redirects and forged/mismatched receipts retry, never ack", async (t) => {
  const digest = await sha(body); const signature = await sign(body);
  for (const outcome of [
    { status: 203, value: { markers: ["HOSTED_INGRESS_TRANSACTIONAL"], event: { delivery_id: id, payload_sha256: digest, repository: "acme/repo" } } },
    { status: 206, value: { markers: ["HOSTED_INGRESS_TRANSACTIONAL"], event: { delivery_id: id, payload_sha256: digest, repository: "acme/repo" } } },
    { status: 409, value: { markers: [], event: { delivery_id: id, payload_sha256: digest } } },
    { status: 302, value: {} },
    { status: 202, value: { markers: ["HOSTED_INGRESS_TRANSACTIONAL"], event: { delivery_id: id, payload_sha256: "f".repeat(64) } } },
    { status: 202, value: { markers: ["HOSTED_INGRESS_TRANSACTIONAL"], event: { delivery_id: id, payload_sha256: digest, repository: "acme/other" } } },
    { status: 202, value: "<html>" },
  ]) {
    await t.test(`status ${outcome.status}`, async () => {
      const e = bindEnv(); e.stored.set(`${id}:${digest}`, body);
      globalThis.fetch = async () => new Response(typeof outcome.value === "string" ? outcome.value : JSON.stringify(outcome.value), { status: outcome.status, headers: { "content-type": "application/json" } });
      const calls = []; await app.consumeMessage({ body: { repository: "acme/repo", digest, delivery: id, event: "pull_request", signature }, ack() { calls.push("ack"); }, retry() { calls.push("retry"); } }, e);
      assert.deepEqual(calls, ["retry"]);
    });
  }
  const e = bindEnv(); e.stored.set(`${id}:${digest}`, new TextEncoder().encode("tampered")); const calls = [];
  await app.consumeMessage({ body: { repository: "acme/repo", digest, delivery: id, event: "pull_request", signature }, ack() { calls.push("ack"); }, retry() { calls.push("retry"); } }, e);
  assert.deepEqual(calls, ["retry"]);
});

test("modeled per-delivery escrow preserves fixed TTL and purges/reschedules alarms", async () => {
  const originalNow = Date.now; const now = 2_000_000_000_000; Date.now = () => now;
  try {
    const { ctx, state, sql } = modeledContext(); const escrow = new app.DeliveryEscrow(ctx, {}); await ctx.ready;
    await escrow.scheduleExpiry();
    assert.equal(state.alarm, undefined);
    const digest = await sha(body); const secondId = "223e4567-e89b-42d3-a456-426614174000";
    await escrow.put(id, digest, body, now + 3 * 24 * 60 * 60 * 1000);
    const firstExpiry = sql.rows.get(`${id}:${digest}`).expires_at;
    Date.now = () => now + 1000;
    await escrow.put(id, digest, body, now + 1000 + 3 * 24 * 60 * 60 * 1000);
    await escrow.put(secondId, digest, body, now + 1000 + 3 * 24 * 60 * 60 * 1000);
    assert.equal(sql.rows.get(`${id}:${digest}`).expires_at, firstExpiry);
    assert.notEqual(sql.rows.get(`${secondId}:${digest}`).expires_at, firstExpiry);
    assert.equal(sql.rows.size, 2); assert.equal(state.alarm, firstExpiry);
    Date.now = () => firstExpiry;
    await escrow.alarm();
    assert.equal(sql.rows.has(`${id}:${digest}`), false); assert.equal(sql.rows.has(`${secondId}:${digest}`), true);
    assert.equal(state.alarm, sql.rows.get(`${secondId}:${digest}`).expires_at);
    await assert.rejects(() => escrow.get(id, digest)); assert.deepEqual(await escrow.get(secondId, digest), body);
  } finally { Date.now = originalNow; }
});

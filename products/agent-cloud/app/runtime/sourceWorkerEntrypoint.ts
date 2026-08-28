import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { ConvexHttpClient } from "convex/browser";
import { makeFunctionReference } from "convex/server";
import { parseWorkerServiceConfig, executeWorkerCycle, waitForWorkerIdle, workerHealth, type WorkerServiceState } from "./sourceWorkerService.js";
import type { SourceWorkerDependencies, WorkerObservation, WorkerSourceDefinition } from "./sourceWorker.js";
import { createWorkerIdentityProvider, createWorkerReferenceResolver } from "./sourceWorkerCredentials.js";
import { readConfinedMountedSecret, readWorkerIdentityFile } from "./sourceWorkerNodeSecrets.js";

const config = parseWorkerServiceConfig(process.env);
const convex = new ConvexHttpClient(config.convexUrl);
const identityProvider = createWorkerIdentityProvider(config.identity, { readTextFile: readWorkerIdentityFile, readEnvironment: (key) => process.env[key] });
const referenceResolver = createWorkerReferenceResolver(config.vaultMount, { readMountedSecret: readConfinedMountedSecret, readEnvironment: (key) => process.env[key] });
const listSources = makeFunctionReference<"query", { agentSpecId: string }, { sources: WorkerSourceDefinition[] }>("authoritativeSources:listWorkerDefinitions");
const recordObservation = makeFunctionReference<"mutation", WorkerObservation, unknown>("authoritativeSources:recordWorkerObservation");
const state: WorkerServiceState = { startedAt: Date.now(), cycleRunning: false, sourcesObserved: 0, failedSources: 0 };

async function boundedBody(response: Response) {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > 2_097_152) { await reader.cancel(); return new Uint8Array(2_097_153); }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}

const dependencies: SourceWorkerDependencies = {
  resolveReference: referenceResolver,
  request: async (url, timeoutMs) => {
    const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json,text/plain,text/html;q=0.8,*/*;q=0.5", "user-agent": "Agent-Oven-Source-Assurance/1.0" } });
    return { status: response.status, body: await boundedBody(response), headers: { "last-modified": response.headers.get("last-modified") ?? "" } };
  },
  sha256: async (content) => createHash("sha256").update(content).digest("hex"),
  now: Date.now,
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

async function sendAlert(event: { code: string; failedSources: number; observedSources: number; occurredAt: number }) {
  if (!config.alertWebhookUrl) return;
  const response = await fetch(config.alertWebhookUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(event), signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error("E_SOURCE_WORKER_ALERT_FAILED");
}

async function runCycle() {
  if (state.cycleRunning) return;
  try {
    await executeWorkerCycle({
      authenticate: async () => { convex.setAuth(await identityProvider()); },
      listSources: async () => (await convex.query(listSources, { agentSpecId: config.agentSpecId })).sources,
      recordObservation: async (observation) => { await convex.mutation(recordObservation, observation); },
    }, dependencies, state, sendAlert);
  } catch (error) {
    const code = error instanceof Error && /^E_[A-Z0-9_]+$/.test(error.message) ? error.message : "E_SOURCE_WORKER_CYCLE_FAILED";
    process.stderr.write(`${code}\n`);
  }
}

const server = createServer((request, response) => {
  const health = workerHealth(state, Date.now(), config.pollIntervalMs);
  if (request.url === "/healthz") { response.writeHead(health.alive ? 200 : 503, { "content-type": "application/json" }); response.end(JSON.stringify({ alive: health.alive })); return; }
  if (request.url === "/readyz") { response.writeHead(health.ready ? 200 : 503, { "content-type": "application/json" }); response.end(JSON.stringify(health)); return; }
  response.writeHead(404).end();
});

server.listen(config.healthPort, "0.0.0.0", () => { process.stdout.write(`SOURCE_WORKER_LISTENING port=${config.healthPort}\n`); });
void runCycle();
const timer = setInterval(() => void runCycle(), config.pollIntervalMs);

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  server.close();
  const idle = await waitForWorkerIdle(state, 10_000, Date.now, (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  process.exit(idle ? 0 : 1);
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());

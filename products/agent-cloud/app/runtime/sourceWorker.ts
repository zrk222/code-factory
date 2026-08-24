export type WorkerSourceDefinition = {
  sourceId: string;
  configDigest: string;
  canonicalLocator: string;
  endpointRef?: string;
};

export type WorkerObservation = {
  sourceId: string;
  expectedConfigDigest: string;
  observationKey: string;
  outcome: "success" | "failure";
  observedAt: number;
  latencyMs: number;
  sourcePublishedAt?: number;
  contentDigest?: string;
  failureCode?: "timeout" | "authentication" | "authorization" | "rate-limited" | "upstream-unavailable" | "invalid-response" | "unknown";
};

export type SourceWorkerDependencies = {
  resolveReference: (reference: string) => Promise<string>;
  request: (url: string, timeoutMs: number) => Promise<{ status: number; body: Uint8Array; headers?: Record<string, string> }>;
  sha256: (content: Uint8Array) => Promise<string>;
  now: () => number;
  sleep: (milliseconds: number) => Promise<void>;
};

const RETRY_BACKOFF_MS = [250, 1000] as const;
const MAX_BODY_BYTES = 2_097_152;

function safeResolvedEndpoint(value: string) {
  let endpoint: URL;
  try { endpoint = new URL(value); } catch { throw new Error("E_SOURCE_WORKER_ENDPOINT_UNSAFE"); }
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) throw new Error("E_SOURCE_WORKER_ENDPOINT_UNSAFE");
  return endpoint.toString();
}

function failureForStatus(status: number): WorkerObservation["failureCode"] {
  if (status === 401) return "authentication";
  if (status === 403) return "authorization";
  if (status === 429) return "rate-limited";
  if (status >= 500 && status <= 599) return "upstream-unavailable";
  return "invalid-response";
}

const retryable = (code: WorkerObservation["failureCode"]) => code === "timeout" || code === "rate-limited" || code === "upstream-unavailable";
const successfulStatus = (status: number) => status >= 200 && status <= 299;
const trustedPublishedAt = (value: number, observedAt: number) => Number.isFinite(value) && value <= observedAt ? value : undefined;
const failureForThrown = (error: unknown): WorkerObservation["failureCode"] => error instanceof Error && error.message === "timeout" ? "timeout" : "unknown";

async function attemptSourceProbe(source: WorkerSourceDefinition, endpoint: string, startedAt: number, dependencies: SourceWorkerDependencies): Promise<{ observation?: WorkerObservation; failureCode: WorkerObservation["failureCode"] }> {
  try {
    const response = await dependencies.request(endpoint, 10_000);
    if (!successfulStatus(response.status)) return { failureCode: failureForStatus(response.status) };
    if (response.body.byteLength > MAX_BODY_BYTES) return { failureCode: "invalid-response" };
    const observedAt = dependencies.now();
    const published = response.headers?.["last-modified"] ? Date.parse(response.headers["last-modified"]) : Number.NaN;
    const contentDigest = await dependencies.sha256(response.body);
    if (!/^[a-f0-9]{64}$/.test(contentDigest)) return { failureCode: "invalid-response" };
    return {
      failureCode: undefined,
      observation: { sourceId: source.sourceId, expectedConfigDigest: source.configDigest, observationKey: `${source.sourceId}:${source.configDigest}:${startedAt}`, outcome: "success", observedAt, latencyMs: Math.max(0, observedAt - startedAt), sourcePublishedAt: trustedPublishedAt(published, observedAt), contentDigest },
    };
  } catch (error) {
    return { failureCode: failureForThrown(error) };
  }
}

/** Probes one source with bounded retries and returns metadata plus a digest, never source content. */
export async function probeAuthoritativeSource(source: WorkerSourceDefinition, dependencies: SourceWorkerDependencies): Promise<WorkerObservation> {
  const startedAt = dependencies.now();
  const resolved = source.endpointRef ? await dependencies.resolveReference(source.endpointRef) : source.canonicalLocator;
  const endpoint = safeResolvedEndpoint(resolved);
  let failureCode: WorkerObservation["failureCode"] = "unknown";
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await attemptSourceProbe(source, endpoint, startedAt, dependencies);
    if (result.observation) return result.observation;
    failureCode = result.failureCode;
    if (!retryable(failureCode) || attempt === 2) break;
    await dependencies.sleep(RETRY_BACKOFF_MS[attempt]);
  }
  const observedAt = dependencies.now();
  return { sourceId: source.sourceId, expectedConfigDigest: source.configDigest, observationKey: `${source.sourceId}:${source.configDigest}:${startedAt}`, outcome: "failure", observedAt, latencyMs: Math.max(0, observedAt - startedAt), failureCode };
}

/** Runs a monitoring cycle in batches of five so one upstream cannot exhaust the worker. */
export async function runSourceMonitoringCycle(sources: readonly WorkerSourceDefinition[], dependencies: SourceWorkerDependencies) {
  const observations: WorkerObservation[] = [];
  for (let offset = 0; offset < sources.length; offset += 5) {
    observations.push(...await Promise.all(sources.slice(offset, offset + 5).map((source) => probeAuthoritativeSource(source, dependencies))));
  }
  return observations;
}

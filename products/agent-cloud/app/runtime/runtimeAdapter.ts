export const runtimeEngines = [
  "mastra",
  "langgraph",
  "openai-agents",
  "microsoft-agent-framework",
  "google-adk",
] as const;

export type RuntimeEngine = typeof runtimeEngines[number];
export type RuntimeTransport = "mastra-native-v1" | "agent-oven-bridge-v1";

export type RuntimeCapabilityManifest = {
  engine: RuntimeEngine;
  label: string;
  transport: RuntimeTransport;
  streaming: boolean;
  suspendResume: boolean;
  multiAgent: boolean;
  traces: boolean;
  nativeAdapter: boolean;
};

export const runtimeCapabilityRegistry: readonly RuntimeCapabilityManifest[] = [
  { engine: "mastra", label: "Mastra", transport: "mastra-native-v1", streaming: true, suspendResume: true, multiAgent: true, traces: true, nativeAdapter: true },
  { engine: "langgraph", label: "LangGraph", transport: "agent-oven-bridge-v1", streaming: true, suspendResume: true, multiAgent: true, traces: true, nativeAdapter: false },
  { engine: "openai-agents", label: "OpenAI Agents SDK", transport: "agent-oven-bridge-v1", streaming: true, suspendResume: false, multiAgent: true, traces: true, nativeAdapter: false },
  { engine: "microsoft-agent-framework", label: "Microsoft Agent Framework", transport: "agent-oven-bridge-v1", streaming: true, suspendResume: true, multiAgent: true, traces: true, nativeAdapter: false },
  { engine: "google-adk", label: "Google ADK", transport: "agent-oven-bridge-v1", streaming: true, suspendResume: true, multiAgent: true, traces: true, nativeAdapter: false },
] as const;

export type RuntimeDispatchContract = {
  schema: "agent-oven.dispatch.v1";
  dispatchDigest: string;
  jobId: string;
  idempotencyKey: string;
  engine: RuntimeEngine;
  targetId: string;
  blueprintId: string;
  blueprintVersion: number;
  inputRef: string;
  inputDigest: string;
  runtimePresetDigest?: string;
  adapterConfigDigest: string;
};

export type RuntimeAdapterRequest = {
  url: string;
  init: RequestInit;
  timeoutMs: 30_000;
  transport: RuntimeTransport;
};

export type RuntimeAdapterResult = {
  externalRunId: string;
  status: "accepted" | "running" | "suspended" | "completed";
  resultDigest: string;
};

export type RuntimeRequirements = {
  streaming?: boolean;
  suspendResume?: boolean;
  multiAgent?: boolean;
  traces?: boolean;
  preferNative?: boolean;
};

export type RuntimeRecommendation = RuntimeCapabilityManifest & {
  score: number;
  reasons: string[];
  eligible: boolean;
};

/** Ranks engines deterministically; missing required capabilities make an engine ineligible. */
export function recommendRuntimeEngines(requirements: RuntimeRequirements): RuntimeRecommendation[] {
  return runtimeCapabilityRegistry.map((manifest) => {
    const reasons: string[] = [];
    let eligible = true;
    let score = 0;
    for (const [field, label] of [["streaming", "streaming"], ["suspendResume", "durable resume"], ["multiAgent", "multi-agent"], ["traces", "traces"]] as const) {
      if (requirements[field]) {
        if (manifest[field]) { score += 20; reasons.push(label); }
        else { eligible = false; reasons.push(`missing ${label}`); }
      }
    }
    if (requirements.preferNative && manifest.nativeAdapter) { score += 15; reasons.push("native Agent Oven adapter"); }
    if (manifest.nativeAdapter) score += 2;
    return { ...manifest, score, reasons, eligible };
  }).sort((left, right) => Number(right.eligible) - Number(left.eligible) || right.score - left.score || left.label.localeCompare(right.label));
}

function capabilityFor(engine: RuntimeEngine) {
  const manifest = runtimeCapabilityRegistry.find((item) => item.engine === engine);
  if (!manifest) throw new Error("E_RUNTIME_ENGINE_UNSUPPORTED");
  return manifest;
}

export function assertSafeRuntimeEndpoint(value: string) {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("E_RUNTIME_ENDPOINT_UNSAFE"); }
  const loopback = url.protocol === "http:" && ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !loopback) throw new Error("E_RUNTIME_ENDPOINT_UNSAFE");
  if (url.username || url.password || url.search) throw new Error("E_RUNTIME_ENDPOINT_UNSAFE");
  return url;
}

export function buildRuntimeRequest(endpoint: string, authToken: string | undefined, contract: RuntimeDispatchContract): RuntimeAdapterRequest {
  const base = assertSafeRuntimeEndpoint(endpoint);
  const capability = capabilityFor(contract.engine);
  const path = contract.engine === "mastra"
    ? `/api/agents/${encodeURIComponent(contract.targetId)}/generate`
    : "/v1/agent-oven/runs";
  const url = new URL(path, `${base.origin}${base.pathname.replace(/\/$/, "")}/`).toString();
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "idempotency-key": contract.idempotencyKey,
    "x-agent-oven-dispatch-digest": contract.dispatchDigest,
  };
  if (authToken) headers.authorization = `Bearer ${authToken}`;
  const body = contract.engine === "mastra"
    ? {
        messages: [{ role: "user", content: JSON.stringify({ inputRef: contract.inputRef, inputDigest: contract.inputDigest }) }],
        runId: contract.jobId,
        requestContext: {
          agentOvenDispatchDigest: contract.dispatchDigest,
          agentOvenBlueprintVersion: contract.blueprintVersion,
          agentOvenPresetDigest: contract.runtimePresetDigest,
        },
      }
    : contract;
  return { url, init: { method: "POST", headers, body: JSON.stringify(body) }, timeoutMs: 30_000, transport: capability.transport };
}

export function parseRuntimeResponse(value: unknown): RuntimeAdapterResult {
  if (!value || typeof value !== "object") throw new Error("E_RUNTIME_RESPONSE_INVALID");
  const candidate = value as Record<string, unknown>;
  const allowed = ["accepted", "running", "suspended", "completed"];
  if (typeof candidate.externalRunId !== "string" || candidate.externalRunId.trim() === "" ||
      typeof candidate.status !== "string" || !allowed.includes(candidate.status) ||
      typeof candidate.resultDigest !== "string" || candidate.resultDigest.trim() === "") {
    throw new Error("E_RUNTIME_RESPONSE_INVALID");
  }
  return candidate as RuntimeAdapterResult;
}

export async function executeRuntimeDispatch(
  endpoint: string,
  authToken: string | undefined,
  contract: RuntimeDispatchContract,
  fetchImpl: typeof fetch = fetch,
): Promise<RuntimeAdapterResult> {
  const request = buildRuntimeRequest(endpoint, authToken, contract);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), request.timeoutMs);
  try {
    const response = await fetchImpl(request.url, { ...request.init, signal: controller.signal });
    if (!response.ok) throw new Error(`E_RUNTIME_HTTP_${response.status}`);
    return parseRuntimeResponse(await response.json());
  } finally {
    clearTimeout(timeout);
  }
}

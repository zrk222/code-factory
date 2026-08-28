import { describe, expect, test, vi } from "vitest";
import { buildRuntimeRequest, executeRuntimeDispatch, parseRuntimeResponse, recommendRuntimeEngines, runtimeCapabilityRegistry, runtimeEngines, type RuntimeDispatchContract } from "./runtimeAdapter";

const base: RuntimeDispatchContract = {
  schema: "agent-oven.dispatch.v1",
  dispatchDigest: "dispatch-digest",
  jobId: "job-1",
  idempotencyKey: "job-key",
  engine: "mastra",
  targetId: "ops-agent",
  blueprintId: "blueprint-1",
  blueprintVersion: 3,
  inputRef: "object://inputs/1.json",
  inputDigest: "input-digest",
  adapterConfigDigest: "adapter-digest",
};

describe("runtime adapter contract", () => {
  test("publishes five explicit engine manifests", () => {
    expect(runtimeEngines).toHaveLength(5);
    expect(runtimeCapabilityRegistry.map((item) => item.engine)).toEqual(runtimeEngines);
    expect(runtimeCapabilityRegistry.find((item) => item.engine === "mastra")).toMatchObject({ nativeAdapter: true, transport: "mastra-native-v1" });
    expect(runtimeCapabilityRegistry.filter((item) => item.engine !== "mastra").every((item) => item.transport === "agent-oven-bridge-v1")).toBe(true);
  });

  test("recommends engines from declared recipe needs without hiding missing capabilities", () => {
    const ranked = recommendRuntimeEngines({ streaming: true, suspendResume: true, multiAgent: true, traces: true, preferNative: true });
    expect(ranked[0]).toMatchObject({ engine: "mastra", eligible: true, score: 97 });
    expect(ranked.find((item) => item.engine === "openai-agents")).toMatchObject({ eligible: false });
    expect(ranked.find((item) => item.engine === "openai-agents")?.reasons).toContain("missing durable resume");
  });

  test("builds native Mastra and common bridge requests without secrets in the body", () => {
    const mastra = buildRuntimeRequest("https://runtime.example/base", "worker-secret", base);
    expect(mastra.url).toBe("https://runtime.example/api/agents/ops-agent/generate");
    expect(mastra.transport).toBe("mastra-native-v1");
    expect(mastra.init.headers).toMatchObject({ authorization: "Bearer worker-secret", "idempotency-key": "job-key" });
    expect(mastra.init.body).not.toContain("worker-secret");
    const bridge = buildRuntimeRequest("https://bridge.example", undefined, { ...base, engine: "langgraph" });
    expect(bridge.url).toBe("https://bridge.example/v1/agent-oven/runs");
    expect(bridge.transport).toBe("agent-oven-bridge-v1");
  });

  test("rejects non-TLS remote endpoints and malformed proof responses", () => {
    expect(() => buildRuntimeRequest("http://runtime.example", undefined, base)).toThrow("E_RUNTIME_ENDPOINT_UNSAFE");
    expect(() => buildRuntimeRequest("https://user:pass@runtime.example", undefined, base)).toThrow("E_RUNTIME_ENDPOINT_UNSAFE");
    expect(() => parseRuntimeResponse({ externalRunId: "run", status: "completed" })).toThrow("E_RUNTIME_RESPONSE_INVALID");
  });

  test("executes one validated request and returns bounded proof fields", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ externalRunId: "mastra-run", status: "completed", resultDigest: "result-digest" }), { status: 200, headers: { "content-type": "application/json" } }));
    await expect(executeRuntimeDispatch("http://127.0.0.1:4111", undefined, base, fetchImpl as typeof fetch)).resolves.toEqual({ externalRunId: "mastra-run", status: "completed", resultDigest: "result-digest" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

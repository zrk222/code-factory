import { describe, expect, test, vi } from "vitest";
import { deliverWorkerAlert, executeWorkerCycle, parseWorkerServiceConfig, waitForWorkerIdle, workerHealth, type WorkerServiceState } from "./sourceWorkerService";
import type { SourceWorkerDependencies } from "./sourceWorker";

const validEnvironment = { CONVEX_URL: "https://tenant.convex.cloud", SOURCE_WORKER_AGENT_SPEC_ID: "agent-1", SOURCE_WORKER_OIDC_TOKEN: "opaque-oidc-token" };

describe("source worker service", () => {
  test("parses bounded startup configuration and rejects unsafe endpoints", () => {
    expect(parseWorkerServiceConfig(validEnvironment)).toMatchObject({ pollIntervalMs: 60_000, healthPort: 8080, agentSpecId: "agent-1", identity: { mode: "static-development" } });
    expect(() => parseWorkerServiceConfig({ ...validEnvironment, CONVEX_URL: "http://tenant.example" })).toThrow("E_SOURCE_WORKER_CONFIG_CONVEX_URL");
    expect(() => parseWorkerServiceConfig({ ...validEnvironment, SOURCE_WORKER_POLL_SECONDS: "5" })).toThrow("E_SOURCE_WORKER_CONFIG_POLL_SECONDS");
    expect(() => parseWorkerServiceConfig({ ...validEnvironment, SOURCE_WORKER_ALERT_WEBHOOK_URL: "http://alerts.example" })).toThrow("E_SOURCE_WORKER_CONFIG_ALERT_WEBHOOK");
  });

  test("authenticates before source access on every cycle", async () => {
    const order: string[] = [];
    const state: WorkerServiceState = { startedAt: 0, cycleRunning: false, sourcesObserved: 0, failedSources: 0 };
    const dependencies: SourceWorkerDependencies = { resolveReference: async (value) => value, request: async () => ({ status: 200, body: new Uint8Array([1]) }), sha256: async () => "a".repeat(64), now: () => 100, sleep: async () => undefined };
    const control = { authenticate: async () => { order.push("auth"); }, listSources: async () => { order.push("list"); return []; }, recordObservation: async () => undefined };
    await executeWorkerCycle(control, dependencies, state, async () => undefined);
    await executeWorkerCycle(control, dependencies, state, async () => undefined);
    expect(order).toEqual(["auth", "list", "auth", "list"]);
  });

  test("retries alert delivery without exposing the monitored endpoint", async () => {
    const alert = vi.fn().mockRejectedValueOnce(new Error("secret upstream detail")).mockResolvedValue(undefined);
    const sleep = vi.fn(async () => undefined);
    await deliverWorkerAlert(alert, { code: "SOURCE_WORKER_SOURCE_FAILURES", failedSources: 1, observedSources: 2, occurredAt: 123 }, sleep);
    expect(alert).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(250);
    expect(JSON.stringify(alert.mock.calls)).not.toContain("secret upstream detail");
  });

  test("records every observation and emits metadata-only failure alerts", async () => {
    let now = 1000;
    const dependencies: SourceWorkerDependencies = { resolveReference: async () => "https://law.example.gov", request: async (url) => ({ status: url.includes("law") ? 503 : 200, body: new Uint8Array([1]) }), sha256: async () => "a".repeat(64), now: () => (now += 10), sleep: async () => undefined };
    const recorded = vi.fn(async () => undefined);
    const alert = vi.fn(async () => undefined);
    const state: WorkerServiceState = { startedAt: 900, cycleRunning: false, sourcesObserved: 0, failedSources: 0 };
    const observations = await executeWorkerCycle({ listSources: async () => [{ sourceId: "one", configDigest: "a", canonicalLocator: "https://law.example.gov" }], recordObservation: recorded }, dependencies, state, alert);
    expect(observations).toHaveLength(1);
    expect(recorded).toHaveBeenCalledTimes(1);
    expect(alert).toHaveBeenCalledWith(expect.objectContaining({ code: "SOURCE_WORKER_SOURCE_FAILURES", failedSources: 1, observedSources: 1 }));
    expect(JSON.stringify(alert.mock.calls)).not.toContain("law.example.gov");
  });

  test("readiness expires after three missed polling intervals", () => {
    const state: WorkerServiceState = { startedAt: 0, cycleRunning: false, lastCycleSucceededAt: 1_000, sourcesObserved: 2, failedSources: 0 };
    expect(workerHealth(state, 180_000, 60_000).ready).toBe(true);
    expect(workerHealth(state, 182_000, 60_000).ready).toBe(false);
    expect(workerHealth({ ...state, failedSources: 1, lastErrorCode: "SOURCE_WORKER_SOURCE_FAILURES" }, 2_000, 60_000).ready).toBe(false);
  });

  test("waits for an active cycle but stops at the shutdown deadline", async () => {
    const state: WorkerServiceState = { startedAt: 0, cycleRunning: true, sourcesObserved: 0, failedSources: 0 };
    let current = 0;
    const idle = await waitForWorkerIdle(state, 100, () => current, async (milliseconds) => { current += milliseconds; });
    expect(idle).toBe(false);
    state.cycleRunning = false;
    expect(await waitForWorkerIdle(state, 100, () => current, async () => undefined)).toBe(true);
  });
});

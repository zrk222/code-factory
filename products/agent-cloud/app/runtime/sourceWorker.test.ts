import { describe, expect, test, vi } from "vitest";
import { probeAuthoritativeSource, runSourceMonitoringCycle, type SourceWorkerDependencies } from "./sourceWorker";

const source = { sourceId: "source-1", configDigest: "config-a", canonicalLocator: "https://law.example.gov/current", endpointRef: "env:LAW_ENDPOINT" };

function dependencies(request: SourceWorkerDependencies["request"]): SourceWorkerDependencies {
  let now = 1_000;
  return { resolveReference: vi.fn(async () => "https://api.example.gov/current"), request, sha256: vi.fn(async () => "a".repeat(64)), now: () => (now += 25), sleep: vi.fn(async () => undefined) };
}

describe("source availability worker", () => {
  test("recovers from a transient outage with declared backoff and returns no body", async () => {
    const request = vi.fn().mockResolvedValueOnce({ status: 503, body: new Uint8Array() }).mockResolvedValueOnce({ status: 200, body: new Uint8Array([1, 2, 3]), headers: { "last-modified": "Mon, 21 Jul 2026 00:00:00 GMT" } });
    const deps = dependencies(request);
    const observation = await probeAuthoritativeSource(source, deps);
    expect(request).toHaveBeenCalledTimes(2);
    expect(deps.sleep).toHaveBeenCalledWith(250);
    expect(observation).toMatchObject({ outcome: "success", contentDigest: "a".repeat(64), expectedConfigDigest: "config-a" });
    expect(observation).not.toHaveProperty("body");
  });

  test("does not retry permanent failures or oversized responses", async () => {
    const denied = vi.fn(async () => ({ status: 403, body: new Uint8Array() }));
    expect(await probeAuthoritativeSource(source, dependencies(denied))).toMatchObject({ outcome: "failure", failureCode: "authorization" });
    expect(denied).toHaveBeenCalledTimes(1);
    const oversized = vi.fn(async () => ({ status: 200, body: new Uint8Array(2_097_153) }));
    expect(await probeAuthoritativeSource(source, dependencies(oversized))).toMatchObject({ outcome: "failure", failureCode: "invalid-response" });
    expect(oversized).toHaveBeenCalledTimes(1);
  });

  test("limits monitoring concurrency to batches of five", async () => {
    let active = 0; let maximum = 0;
    const request = async () => { active += 1; maximum = Math.max(maximum, active); await Promise.resolve(); active -= 1; return { status: 200, body: new Uint8Array([1]) }; };
    const observations = await runSourceMonitoringCycle(Array.from({ length: 12 }, (_, index) => ({ ...source, sourceId: `source-${index}` })), dependencies(request));
    expect(observations).toHaveLength(12);
    expect(maximum).toBeLessThanOrEqual(5);
  });
});

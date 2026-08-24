import { describe, expect, test } from "vitest";
import { assessSourceGroups, evaluateSourceState, validateAuthoritativeLocator, validateOpaqueSourceReference, type SourceAssuranceInput } from "./sourceAssurance";

const now = Date.UTC(2026, 6, 21, 12);
const source = (overrides: Partial<SourceAssuranceInput> = {}): SourceAssuranceInput => ({
  sourceGroup: "property-law",
  authorityCategory: "official-regulator",
  status: "ready",
  freshnessSloSeconds: 3_600,
  maximumAgeSeconds: 10_800,
  minimumAuthoritativeSources: 2,
  requiredForRuns: true,
  lastSuccessfulAt: now - 1_000,
  consecutiveFailures: 0,
  ...overrides,
});

describe("authoritative source assurance", () => {
  test("accepts public HTTPS identity and opaque worker references only", () => {
    expect(validateAuthoritativeLocator("https://laws.example.gov/source")).toBe("https://laws.example.gov/source");
    expect(() => validateAuthoritativeLocator("https://user:secret@laws.example.gov/?api_key=raw")).toThrow("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
    expect(validateOpaqueSourceReference("vault:licenses/laws")).toBe("vault:licenses/laws");
    expect(validateOpaqueSourceReference("env:SOURCE_ENDPOINT_OFFICIAL_LAW")).toBe("env:SOURCE_ENDPOINT_OFFICIAL_LAW");
    expect(() => validateOpaqueSourceReference("env:SOURCE_WORKER_OIDC_TOKEN")).toThrow("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
    expect(() => validateOpaqueSourceReference("vault:../worker-token")).toThrow("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
    expect(() => validateOpaqueSourceReference("https://runtime.example/token")).toThrow("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
  });

  test("classifies freshness, failures, maximum age, and setup state deterministically", () => {
    expect(evaluateSourceState(source(), now).state).toBe("healthy");
    expect(evaluateSourceState(source({ lastSuccessfulAt: now - 7_200_000 }), now)).toMatchObject({ state: "degraded", reason: "SOURCE_FRESHNESS_SLO_EXCEEDED" });
    expect(evaluateSourceState(source({ consecutiveFailures: 2 }), now)).toMatchObject({ state: "degraded", reason: "SOURCE_RECENT_FAILURES" });
    expect(evaluateSourceState(source({ lastSuccessfulAt: now - 20_000_000 }), now)).toMatchObject({ state: "stale", reason: "SOURCE_MAXIMUM_AGE_EXCEEDED" });
    expect(evaluateSourceState(source({ consecutiveFailures: 3 }), now)).toMatchObject({ state: "unavailable", reason: "SOURCE_FAILURE_THRESHOLD_EXCEEDED" });
    expect(evaluateSourceState(source({ status: "setup-required", lastSuccessfulAt: undefined }), now).state).toBe("setup-required");
  });

  test("requires the declared count and one healthy authoritative source", () => {
    const ready = assessSourceGroups([
      source(),
      source({ authorityCategory: "licensed-system-of-record", consecutiveFailures: 1 }),
      source({ authorityCategory: "secondary-corroboration" }),
    ], now)[0];
    expect(ready).toMatchObject({ state: "ready", qualifyingAuthoritativeSources: 2, healthyAuthoritativeSources: 1 });

    const noHealthy = assessSourceGroups([
      source({ consecutiveFailures: 1 }),
      source({ authorityCategory: "licensed-system-of-record", consecutiveFailures: 2 }),
    ], now)[0];
    expect(noHealthy).toMatchObject({ state: "blocked", reason: "NO_HEALTHY_AUTHORITATIVE_SOURCE" });
  });

  test("never counts secondary corroboration as authority", () => {
    const assessment = assessSourceGroups([
      source({ minimumAuthoritativeSources: 1, authorityCategory: "secondary-corroboration" }),
    ], now)[0];
    expect(assessment).toMatchObject({ state: "blocked", reason: "AUTHORITATIVE_COUNT_BELOW_MINIMUM", qualifyingAuthoritativeSources: 0 });
  });
});

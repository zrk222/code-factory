import { describe, expect, test, vi } from "vitest";
import { parseSourceWorkerActivationPolicy, runSourceWorkerActivationPreflight, runSourceWorkerRotationDrill, type SourceWorkerActivationDependencies } from "./sourceWorkerActivation";

const environment = {
  SOURCE_WORKER_EXPECTED_ISSUER: "https://issuer.example",
  SOURCE_WORKER_EXPECTED_AUDIENCE: "agent-oven-source-worker",
  SOURCE_WORKER_EXPECTED_SUBJECT: "system:serviceaccount:agent-oven:source-worker",
  SOURCE_WORKER_ACTIVATION_REFERENCES: '["vault:licensed/source","env:SOURCE_ENDPOINT_OFFICIAL"]',
};

const claims = { iss: environment.SOURCE_WORKER_EXPECTED_ISSUER, aud: ["other", environment.SOURCE_WORKER_EXPECTED_AUDIENCE], sub: environment.SOURCE_WORKER_EXPECTED_SUBJECT, exp: 2_000, nbf: 990, iat: 990 };

function dependencies(overrides: Partial<SourceWorkerActivationDependencies> = {}): SourceWorkerActivationDependencies {
  return {
    loadIdentity: async () => "header.payload.signature",
    resolveReference: async (reference) => reference.includes("vault") ? "https://licensed.example" : "https://official.example",
    decodeJwtPayload: () => claims,
    digest: async (value) => `digest:${value}`,
    nowSeconds: () => 1_000,
    sleep: async () => undefined,
    ...overrides,
  };
}

describe("source worker activation preflight", () => {
  test("parses a bounded secret-free policy", () => {
    expect(parseSourceWorkerActivationPolicy(environment)).toEqual({ expectedIssuer: environment.SOURCE_WORKER_EXPECTED_ISSUER, expectedAudience: environment.SOURCE_WORKER_EXPECTED_AUDIENCE, expectedSubject: environment.SOURCE_WORKER_EXPECTED_SUBJECT, sourceReferences: ["vault:licensed/source", "env:SOURCE_ENDPOINT_OFFICIAL"], rotationDrillSeconds: undefined });
  });

  test("rejects missing and invalid configuration before credential access", () => {
    expect(() => parseSourceWorkerActivationPolicy({})).toThrow("E_SOURCE_WORKER_ACTIVATION_CONFIG_MISSING");
    expect(() => parseSourceWorkerActivationPolicy({ ...environment, SOURCE_WORKER_ACTIVATION_REFERENCES: "not-json" })).toThrow("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID");
    expect(() => parseSourceWorkerActivationPolicy({ ...environment, SOURCE_WORKER_ACTIVATION_REFERENCES: '["env:SOURCE_WORKER_OIDC_TOKEN"]' })).toThrow("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID");
    expect(() => parseSourceWorkerActivationPolicy({ ...environment, SOURCE_WORKER_ROTATION_DRILL_SECONDS: "301" })).toThrow("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID");
  });

  test("rejects development identity before reading credentials", async () => {
    const loadIdentity = vi.fn(async () => "header.payload.signature");
    await expect(runSourceWorkerActivationPreflight(parseSourceWorkerActivationPolicy(environment), { mode: "static-development", environmentKey: "SOURCE_WORKER_OIDC_TOKEN" }, dependencies({ loadIdentity }))).rejects.toThrow("E_SOURCE_WORKER_PRODUCTION_IDENTITY_REQUIRED");
    expect(loadIdentity).not.toHaveBeenCalled();
  });

  test("returns a ready receipt that explicitly defers signature verification and contains no secrets", async () => {
    const receipt = await runSourceWorkerActivationPreflight(parseSourceWorkerActivationPolicy(environment), { mode: "rotating-file", tokenFile: "/identity/token" }, dependencies());
    expect(receipt).toEqual({ schemaVersion: 1, status: "ready", checkedAt: 1_000, referenceCount: 2, signatureVerified: false, requiresControlPlaneVerification: true });
    const serialized = JSON.stringify(receipt);
    for (const forbidden of ["header.payload.signature", "issuer.example", "agent-oven-source-worker", "serviceaccount", "licensed/source", "licensed.example", "/identity/token", "digest:"]) expect(serialized).not.toContain(forbidden);
  });

  test("rejects malformed claims and each trust mismatch", async () => {
    const policy = parseSourceWorkerActivationPolicy(environment);
    const identity = { mode: "rotating-file", tokenFile: "/identity/token" } as const;
    await expect(runSourceWorkerActivationPreflight(policy, identity, dependencies({ loadIdentity: async () => "not-a-jwt" }))).rejects.toThrow("E_SOURCE_WORKER_IDENTITY_CLAIMS_INVALID");
    await expect(runSourceWorkerActivationPreflight(policy, identity, dependencies({ decodeJwtPayload: () => ({ ...claims, iss: "wrong" }) }))).rejects.toThrow("E_SOURCE_WORKER_IDENTITY_ISSUER_MISMATCH");
    await expect(runSourceWorkerActivationPreflight(policy, identity, dependencies({ decodeJwtPayload: () => ({ ...claims, aud: "wrong" }) }))).rejects.toThrow("E_SOURCE_WORKER_IDENTITY_AUDIENCE_MISMATCH");
    await expect(runSourceWorkerActivationPreflight(policy, identity, dependencies({ decodeJwtPayload: () => ({ ...claims, sub: "wrong" }) }))).rejects.toThrow("E_SOURCE_WORKER_IDENTITY_SUBJECT_MISMATCH");
  });

  test("rejects expired, immature, and future-issued identities", async () => {
    const policy = parseSourceWorkerActivationPolicy(environment);
    const identity = { mode: "rotating-file", tokenFile: "/identity/token" } as const;
    for (const invalid of [{ ...claims, exp: 1_119 }, { ...claims, nbf: 1_031 }, { ...claims, iat: 1_031 }]) {
      await expect(runSourceWorkerActivationPreflight(policy, identity, dependencies({ decodeJwtPayload: () => invalid }))).rejects.toThrow("E_SOURCE_WORKER_IDENTITY_TIME_INVALID");
    }
  });

  test("preserves closed resolver failures and returns no receipt", async () => {
    await expect(runSourceWorkerActivationPreflight(parseSourceWorkerActivationPolicy(environment), { mode: "rotating-file", tokenFile: "/identity/token" }, dependencies({ resolveReference: async () => { throw new Error("E_SOURCE_WORKER_SECRET_FILE_UNSAFE"); } }))).rejects.toThrow("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  });

  test("observes identity and every reference rotating", async () => {
    const policy = parseSourceWorkerActivationPolicy({ ...environment, SOURCE_WORKER_ROTATION_DRILL_SECONDS: "5" });
    const identities = ["header.payload.signature-a", "header.payload.signature-b"];
    const sourceValues = ["source-a1", "source-a2", "source-b1", "source-b2"];
    let now = 1_000;
    const receipt = await runSourceWorkerRotationDrill(policy, { mode: "rotating-file", tokenFile: "/identity/token" }, dependencies({ loadIdentity: async () => identities.shift() ?? "header.payload.signature-b", resolveReference: async () => sourceValues.shift() ?? "source-b2", nowSeconds: () => now, sleep: async () => { now += 1; } }));
    expect(receipt).toEqual({ schemaVersion: 1, status: "rotated", checkedAt: 1_001, samples: 2, identityRotated: true, rotatedReferences: 2 });
  });

  test("fails closed when rotation is not observed in the configured interval", async () => {
    const policy = parseSourceWorkerActivationPolicy({ ...environment, SOURCE_WORKER_ROTATION_DRILL_SECONDS: "5" });
    await expect(runSourceWorkerRotationDrill(policy, { mode: "rotating-file", tokenFile: "/identity/token" }, dependencies())).rejects.toThrow("E_SOURCE_WORKER_ROTATION_NOT_OBSERVED");
  });
});

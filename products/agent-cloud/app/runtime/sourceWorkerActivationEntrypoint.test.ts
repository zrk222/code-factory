import { describe, expect, test } from "vitest";
import { executeSourceWorkerActivationCommand, type SourceWorkerActivationCommandDependencies } from "./sourceWorkerActivationEntrypoint";

const now = 1_000;
const payload = { iss: "https://issuer.example", aud: "agent-oven-source-worker", sub: "system:serviceaccount:agent-oven:source-worker", exp: 2_000, nbf: 990, iat: 990 };

function jwt(claims = payload, suffix = "signature") {
  return `${Buffer.from("header").toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${Buffer.from(suffix).toString("base64url")}`;
}

const environment = {
  SOURCE_WORKER_EXPECTED_ISSUER: payload.iss,
  SOURCE_WORKER_EXPECTED_AUDIENCE: payload.aud,
  SOURCE_WORKER_EXPECTED_SUBJECT: payload.sub,
  SOURCE_WORKER_ACTIVATION_REFERENCES: '["vault:licensed/source"]',
  SOURCE_WORKER_OIDC_TOKEN_FILE: "/identity/token",
  SOURCE_WORKER_VAULT_MOUNT: "/vault",
};

function dependencies(overrides: Partial<SourceWorkerActivationCommandDependencies> = {}): SourceWorkerActivationCommandDependencies {
  return {
    readTextFile: async () => jwt(),
    readMountedSecret: async () => "https://licensed.example/secret-endpoint",
    readEnvironment: () => undefined,
    digest: async (value) => `digest:${value}`,
    nowSeconds: () => now,
    sleep: async () => undefined,
    ...overrides,
  };
}

function output() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return { stdout, stderr, io: { writeStdout: (value: string) => stdout.push(value), writeStderr: (value: string) => stderr.push(value) } };
}

describe("source worker activation command", () => {
  test("emits exactly one redacted ready receipt line", async () => {
    const result = output();
    expect(await executeSourceWorkerActivationCommand(environment, dependencies(), result.io)).toBe(0);
    expect(result.stderr).toEqual([]);
    expect(result.stdout).toHaveLength(1);
    expect(JSON.parse(result.stdout[0])).toEqual({ schemaVersion: 1, status: "ready", checkedAt: now, referenceCount: 1, signatureVerified: false, requiresControlPlaneVerification: true });
    for (const forbidden of [jwt(), payload.iss, payload.aud, payload.sub, "licensed/source", "licensed.example", "/identity/token", "/vault", "digest:"]) expect(result.stdout[0]).not.toContain(forbidden);
  });

  test("emits exactly one closed error line and no receipt on failure", async () => {
    const result = output();
    expect(await executeSourceWorkerActivationCommand({ ...environment, SOURCE_WORKER_EXPECTED_ISSUER: "https://wrong.example" }, dependencies(), result.io)).toBe(1);
    expect(result.stdout).toEqual([]);
    expect(result.stderr).toEqual(["E_SOURCE_WORKER_IDENTITY_ISSUER_MISMATCH\n"]);
  });

  test("observes externally rotated identity and mounted source values", async () => {
    const result = output();
    const identities = [jwt(payload, "signature-a"), jwt(payload, "signature-b")];
    const sources = ["source-a", "source-b"];
    let clock = now;
    const configured = { ...environment, SOURCE_WORKER_ROTATION_DRILL_SECONDS: "5" };
    const exit = await executeSourceWorkerActivationCommand(configured, dependencies({ readTextFile: async () => identities.shift() ?? jwt(payload, "signature-b"), readMountedSecret: async () => sources.shift() ?? "source-b", nowSeconds: () => clock, sleep: async () => { clock += 1; } }), result.io);
    expect(exit).toBe(0);
    expect(result.stderr).toEqual([]);
    expect(JSON.parse(result.stdout[0])).toEqual({ schemaVersion: 1, status: "rotated", checkedAt: 1_001, samples: 2, identityRotated: true, rotatedReferences: 1 });
    expect(result.stdout[0]).not.toContain("source-a");
    expect(result.stdout[0]).not.toContain("source-b");
  });
});

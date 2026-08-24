import { describe, expect, test } from "vitest";
import { evaluateProductionReadiness, type ProductionReadinessEnvironment } from "./productionReadinessDomain";

const complete: ProductionReadinessEnvironment = {
  AUTH0_DOMAIN: "login.agentoven.example",
  AUTH0_CLIENT_ID: "client_identifier_123",
  AGENT_OVEN_APP_URL: "https://agentoven.example",
  AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF: "vault://agent-oven/billing-webhook",
  AGENT_OVEN_EMAIL_CONNECTION_REF: "aws-sm://agent-oven/transactional-email",
  AGENT_OVEN_RUNTIME_WORKER_SECRET_REF: "azure-kv://agent-oven/runtime-worker",
  AGENT_OVEN_BACKUP_STORAGE_REF: "gcp-sm://agent-oven/backup-storage",
  AGENT_OVEN_SECURITY_CONTACT: "security@agentoven.example",
};

describe("production readiness classifier", () => {
  test("validateHostname, validateClientIdentifier, and validateIdentity reject malformed identity configuration", () => {
    const result = evaluateProductionReadiness({ ...complete, AUTH0_DOMAIN: "https://login.example/path", AUTH0_CLIENT_ID: "bad id" });
    expect(result.controls.find((item) => item.key === "identity")?.status).toBe("invalid");
  });

  test("validateHttpsUrl, validateSecretReference, and validateEmail reject malformed operations configuration", () => {
    const result = evaluateProductionReadiness({ ...complete, AGENT_OVEN_APP_URL: "http://agentoven.example", AGENT_OVEN_RUNTIME_WORKER_SECRET_REF: "raw-secret", AGENT_OVEN_SECURITY_CONTACT: "not-an-email" });
    expect(result.controls.find((item) => item.key === "app-endpoint")?.status).toBe("invalid");
    expect(result.controls.find((item) => item.key === "runtime-worker")?.status).toBe("invalid");
    expect(result.controls.find((item) => item.key === "security-contact")?.status).toBe("invalid");
  });

  test("distinguishes a live control plane from enterprise operations", () => {
    const result = evaluateProductionReadiness({ AUTH0_DOMAIN: complete.AUTH0_DOMAIN, AUTH0_CLIENT_ID: complete.AUTH0_CLIENT_ID, AGENT_OVEN_APP_URL: complete.AGENT_OVEN_APP_URL });
    expect(result).toMatchObject({ marker: "PRODUCTION_READINESS_EXPLAINED", evidenceMarker: "READINESS_RESPONSE_REDACTED", phaseMarker: "PRODUCTION_PILOT_READY", status: "pilot", controlPlaneReady: true, enterpriseReady: false, summary: { ready: 2, total: 7 } });
    expect(result.controls).toHaveLength(7);
    expect(result.controls.filter((item) => item.status === "missing")).toHaveLength(5);
    expect(result.controls.filter((item) => item.status !== "ready").every((item) => Boolean(item.nextAction))).toBe(true);
  });

  test("returns ready only when every declared control is valid", () => {
    const result = evaluateProductionReadiness(complete);
    expect(result).toMatchObject({ phaseMarker: "ENTERPRISE_OPERATIONS_READY", status: "ready", controlPlaneReady: true, enterpriseReady: true, summary: { ready: 7, total: 7 } });
    expect(result.controls.every((item) => item.status === "ready" && item.nextAction === null)).toBe(true);
  });

  test("fails the foundation closed when identity or endpoint is absent", () => {
    const missingIdentity = evaluateProductionReadiness({ ...complete, AUTH0_DOMAIN: "" });
    const invalidEndpoint = evaluateProductionReadiness({ ...complete, AGENT_OVEN_APP_URL: "http://agentoven.example" });
    expect(missingIdentity).toMatchObject({ phaseMarker: "PRODUCTION_ACTIVATION_BLOCKED", status: "blocked", controlPlaneReady: false });
    expect(invalidEndpoint.controls.find((item) => item.key === "app-endpoint")?.status).toBe("invalid");
    expect(invalidEndpoint.status).toBe("blocked");
  });

  test("rejects raw credentials and never reflects configured values or configuration names", () => {
    const rawValues = { ...complete, AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF: "https://user:password@billing.example/hook?token=private-token" };
    const result = evaluateProductionReadiness(rawValues);
    expect(result.controls.find((item) => item.key === "billing-webhook")?.status).toBe("invalid");
    const serialized = JSON.stringify(result);
    for (const value of Object.values(rawValues)) expect(serialized).not.toContain(value);
    for (const name of Object.keys(rawValues)) expect(serialized).not.toContain(name);
    expect(serialized).not.toContain("private-token");
    expect(serialized).not.toContain("password");
  });

  test("mutation matrix makes every missing dependency non-ready", () => {
    for (const key of Object.keys(complete) as Array<keyof ProductionReadinessEnvironment>) {
      const mutated = { ...complete, [key]: "" };
      const result = evaluateProductionReadiness(mutated);
      expect(result.enterpriseReady, key).toBe(false);
      expect(result.summary.ready, key).toBeLessThan(7);
    }
    expect(new Set(evaluateProductionReadiness(complete).controls.map((item) => item.key)).size).toBe(7);
  });
});

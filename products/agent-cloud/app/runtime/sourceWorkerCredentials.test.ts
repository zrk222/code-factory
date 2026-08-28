import { describe, expect, test, vi } from "vitest";
import { createWorkerIdentityProvider, createWorkerReferenceResolver, parseWorkerIdentityConfig, parseWorkerVaultMount, validateWorkerIdentityToken } from "./sourceWorkerCredentials";

describe("source worker credential contract", () => {
  test("selects rotating file identity without returning token contents", () => {
    const config = parseWorkerIdentityConfig({ SOURCE_WORKER_OIDC_TOKEN_FILE: "/var/run/agent-oven/oidc-token" });
    expect(config).toEqual({ mode: "rotating-file", tokenFile: "/var/run/agent-oven/oidc-token" });
    expect(JSON.stringify(config)).not.toContain("token-value");
    expect(parseWorkerVaultMount({ SOURCE_WORKER_VAULT_MOUNT: "/var/run/agent-oven/source-secrets" })).toBe("/var/run/agent-oven/source-secrets");
  });

  test("rejects conflicting, missing, and malformed identity configuration", () => {
    expect(() => parseWorkerIdentityConfig({ SOURCE_WORKER_OIDC_TOKEN_FILE: "/token", SOURCE_WORKER_OIDC_TOKEN: "static-token" })).toThrow("E_SOURCE_WORKER_IDENTITY_CONFLICT");
    expect(() => parseWorkerIdentityConfig({})).toThrow("E_SOURCE_WORKER_IDENTITY_MISSING");
    expect(() => parseWorkerIdentityConfig({ SOURCE_WORKER_OIDC_TOKEN_FILE: "relative/token" })).toThrow("E_SOURCE_WORKER_IDENTITY_FILE_INVALID");
    expect(() => validateWorkerIdentityToken("short")).toThrow("E_SOURCE_WORKER_IDENTITY_INVALID");
    expect(() => validateWorkerIdentityToken("contains whitespace")).toThrow("E_SOURCE_WORKER_IDENTITY_INVALID");
  });

  test("rereads and applies rotated identity material on every call", async () => {
    const values = ["identity-token-a", "identity-token-b"];
    const readTextFile = vi.fn(async () => values.shift() ?? "identity-token-b");
    const provider = createWorkerIdentityProvider({ mode: "rotating-file", tokenFile: "/var/run/token" }, { readTextFile, readEnvironment: () => undefined });
    expect(await provider()).toBe("identity-token-a");
    expect(await provider()).toBe("identity-token-b");
    expect(readTextFile).toHaveBeenCalledTimes(2);
  });

  test("rereads environment references instead of caching them", async () => {
    let current = "https://first.example.gov";
    const resolver = createWorkerReferenceResolver(undefined, { readEnvironment: () => current, readMountedSecret: async () => "unused" });
    expect(await resolver("env:SOURCE_ENDPOINT_OFFICIAL")).toContain("first.example.gov");
    current = "https://second.example.gov";
    expect(await resolver("env:SOURCE_ENDPOINT_OFFICIAL")).toContain("second.example.gov");
  });

  test("prevents source references from reading worker identity variables", async () => {
    const readEnvironment = vi.fn(() => "identity-token-secret");
    const resolver = createWorkerReferenceResolver(undefined, { readEnvironment, readMountedSecret: async () => "unused" });
    await expect(resolver("env:SOURCE_WORKER_OIDC_TOKEN")).rejects.toThrow("E_SOURCE_WORKER_ENV_REFERENCE_INVALID");
    expect(readEnvironment).not.toHaveBeenCalled();
  });

  test("resolves a valid mounted-vault key without exposing reference metadata", async () => {
    const readMountedSecret = vi.fn(async () => "https://licensed.example.gov");
    const resolver = createWorkerReferenceResolver("/vault", { readEnvironment: () => undefined, readMountedSecret });
    expect(await resolver("vault:licenses/licensed-source-api")).toBe("https://licensed.example.gov");
    expect(readMountedSecret).toHaveBeenCalledWith("/vault", "licenses/licensed-source-api");
  });

  test("rejects unsafe or unconfigured vault references before file access", async () => {
    const readMountedSecret = vi.fn(async () => "secret");
    const configured = createWorkerReferenceResolver("/vault", { readEnvironment: () => undefined, readMountedSecret });
    await expect(configured("vault:../production-token")).rejects.toThrow("E_SOURCE_WORKER_VAULT_REFERENCE_INVALID");
    await expect(configured("vault:licenses\\production-token")).rejects.toThrow("E_SOURCE_WORKER_VAULT_REFERENCE_INVALID");
    expect(readMountedSecret).not.toHaveBeenCalled();
    const missing = createWorkerReferenceResolver(undefined, { readEnvironment: () => undefined, readMountedSecret });
    await expect(missing("vault:licenses/licensed-source-api")).rejects.toThrow("E_SOURCE_WORKER_VAULT_MOUNT_REQUIRED");
    expect(readMountedSecret).not.toHaveBeenCalled();
  });
});

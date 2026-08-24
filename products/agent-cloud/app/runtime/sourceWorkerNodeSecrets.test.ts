import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { readConfinedMountedSecret, readWorkerIdentityFile } from "./sourceWorkerNodeSecrets";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryPaths.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "agent-oven-source-worker-"));
  temporaryPaths.push(root);
  const mount = join(root, "vault");
  await mkdir(mount);
  return { root, mount };
}

describe("source worker confined file adapter", () => {
  test("reads bounded identity and vault files", async () => {
    const { mount } = await fixture();
    const token = join(mount, "oidc-token");
    const endpoint = join(mount, "licensed-source");
    await writeFile(token, "identity-token-a", { mode: 0o440 });
    await writeFile(endpoint, "https://licensed.example.gov", { mode: 0o440 });
    expect(await readWorkerIdentityFile(token)).toBe("identity-token-a");
    expect(await readConfinedMountedSecret(mount, "licensed-source")).toContain("licensed.example.gov");
  });

  test("rejects mount traversal and oversized files", async () => {
    const { root, mount } = await fixture();
    const outside = join(root, "outside-secret");
    await writeFile(outside, "do-not-read", { mode: 0o440 });
    await expect(readConfinedMountedSecret(mount, "../outside-secret")).rejects.toThrow("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
    const oversized = join(mount, "oversized");
    await writeFile(oversized, "x".repeat(65_537), { mode: 0o440 });
    await expect(readConfinedMountedSecret(mount, "oversized")).rejects.toThrow("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  });

  test("rejects world-readable secrets on non-Windows hosts", async () => {
    if (process.platform === "win32") return;
    const { mount } = await fixture();
    const path = join(mount, "public-secret");
    await writeFile(path, "identity-token-a", { mode: 0o444 });
    await chmod(path, 0o444);
    await expect(readWorkerIdentityFile(path)).rejects.toThrow("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  });
});

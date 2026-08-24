import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { parseSourceWorkerActivationPolicy, runSourceWorkerActivationPreflight, runSourceWorkerRotationDrill, type SourceWorkerActivationDependencies } from "./sourceWorkerActivation.js";
import { createWorkerIdentityProvider, createWorkerReferenceResolver, parseWorkerIdentityConfig, parseWorkerVaultMount, type WorkerCredentialDependencies } from "./sourceWorkerCredentials.js";
import { readConfinedMountedSecret, readWorkerIdentityFile } from "./sourceWorkerNodeSecrets.js";

export type SourceWorkerActivationCommandDependencies = WorkerCredentialDependencies & Pick<SourceWorkerActivationDependencies, "digest" | "nowSeconds" | "sleep">;

export type SourceWorkerActivationCommandIo = {
  writeStdout: (value: string) => void;
  writeStderr: (value: string) => void;
};

/** Decodes only the payload of a compact JWT; the returned claims are never signature verification. */
export function decodeCompactJwtPayload(compactJwt: string): unknown {
  const segments = compactJwt.split(".");
  if (segments.length !== 3 || segments.some((segment) => !/^[A-Za-z0-9_-]+$/.test(segment))) throw new Error("E_SOURCE_WORKER_IDENTITY_CLAIMS_INVALID");
  return JSON.parse(Buffer.from(segments[1], "base64url").toString("utf8"));
}

function closedErrorCode(error: unknown) {
  return error instanceof Error && /^E_SOURCE_WORKER_[A-Z0-9_]+$/.test(error.message) ? error.message : "E_SOURCE_WORKER_ACTIVATION_FAILED";
}

/** Executes one activation preflight or bounded rotation drill with closed, single-line output. */
export async function executeSourceWorkerActivationCommand(environment: Record<string, string | undefined>, dependencies: SourceWorkerActivationCommandDependencies, io: SourceWorkerActivationCommandIo): Promise<0 | 1> {
  try {
    const policy = parseSourceWorkerActivationPolicy(environment);
    const identity = parseWorkerIdentityConfig(environment);
    const vaultMount = parseWorkerVaultMount(environment);
    const loadIdentity = createWorkerIdentityProvider(identity, dependencies);
    const resolveReference = createWorkerReferenceResolver(vaultMount, dependencies);
    const activationDependencies: SourceWorkerActivationDependencies = { loadIdentity, resolveReference, decodeJwtPayload: decodeCompactJwtPayload, digest: dependencies.digest, nowSeconds: dependencies.nowSeconds, sleep: dependencies.sleep };
    const receipt = policy.rotationDrillSeconds === undefined
      ? await runSourceWorkerActivationPreflight(policy, identity, activationDependencies)
      : await runSourceWorkerRotationDrill(policy, identity, activationDependencies);
    io.writeStdout(`${JSON.stringify(receipt)}\n`);
    return 0;
  } catch (error) {
    io.writeStderr(`${closedErrorCode(error)}\n`);
    return 1;
  }
}

const nodeDependencies: SourceWorkerActivationCommandDependencies = {
  readTextFile: readWorkerIdentityFile,
  readMountedSecret: readConfinedMountedSecret,
  readEnvironment: (key) => process.env[key],
  digest: async (value) => createHash("sha256").update(value).digest("hex"),
  nowSeconds: () => Math.floor(Date.now() / 1_000),
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

async function main() {
  process.exitCode = await executeSourceWorkerActivationCommand(process.env, nodeDependencies, { writeStdout: (value) => process.stdout.write(value), writeStderr: (value) => process.stderr.write(value) });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) void main();

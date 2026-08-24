export type WorkerIdentityConfig =
  | { mode: "rotating-file"; tokenFile: string }
  | { mode: "static-development"; environmentKey: "SOURCE_WORKER_OIDC_TOKEN" };

export type WorkerCredentialDependencies = {
  readTextFile: (path: string) => Promise<string>;
  readMountedSecret: (mountPath: string, key: string) => Promise<string>;
  readEnvironment: (key: string) => string | undefined;
};

const VAULT_SEGMENT = /^[A-Za-z0-9._-]{1,40}$/;
const ENV_ENDPOINT_KEY = /^SOURCE_ENDPOINT_[A-Z0-9_]{1,100}$/;
const WINDOWS_ABSOLUTE = /^[A-Za-z]:[\\/]/;
const MAX_SECRET_CHARACTERS = 65_536;

function absolutePath(value: string, code: string) {
  const path = value.trim();
  if ((!path.startsWith("/") && !WINDOWS_ABSOLUTE.test(path)) || path.includes("\0")) throw new Error(code);
  return path;
}

function vaultKey(value: string) {
  const segments = value.split("/");
  if (value.length > 120 || segments.length > 8 || segments.some((segment) => !VAULT_SEGMENT.test(segment) || segment === "." || segment === "..")) throw new Error("E_SOURCE_WORKER_VAULT_REFERENCE_INVALID");
  return value;
}

/** Parses the closed source-reference syntax shared by admission and worker resolution. */
export function parseWorkerSourceReference(reference: string): { scheme: "env" | "vault"; key: string } {
  if (reference.startsWith("env:")) {
    const key = reference.slice(4);
    if (!ENV_ENDPOINT_KEY.test(key)) throw new Error("E_SOURCE_WORKER_ENV_REFERENCE_INVALID");
    return { scheme: "env", key };
  }
  if (reference.startsWith("vault:")) return { scheme: "vault", key: vaultKey(reference.slice(6)) };
  throw new Error("E_SOURCE_WORKER_REFERENCE_UNSUPPORTED");
}

function secretText(value: string, code: string) {
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_SECRET_CHARACTERS || normalized.includes("\0")) throw new Error(code);
  return normalized;
}

/** Parses identity selection without copying a static token into the returned configuration. */
export function parseWorkerIdentityConfig(environment: Record<string, string | undefined>): WorkerIdentityConfig {
  const tokenFile = environment.SOURCE_WORKER_OIDC_TOKEN_FILE?.trim();
  const staticToken = environment.SOURCE_WORKER_OIDC_TOKEN?.trim();
  if (tokenFile && staticToken) throw new Error("E_SOURCE_WORKER_IDENTITY_CONFLICT");
  if (!tokenFile && !staticToken) throw new Error("E_SOURCE_WORKER_IDENTITY_MISSING");
  if (tokenFile) return { mode: "rotating-file", tokenFile: absolutePath(tokenFile, "E_SOURCE_WORKER_IDENTITY_FILE_INVALID") };
  return { mode: "static-development", environmentKey: "SOURCE_WORKER_OIDC_TOKEN" };
}

/** Parses the optional provider-neutral mounted-vault boundary. */
export function parseWorkerVaultMount(environment: Record<string, string | undefined>) {
  const mount = environment.SOURCE_WORKER_VAULT_MOUNT?.trim();
  return mount ? absolutePath(mount, "E_SOURCE_WORKER_VAULT_MOUNT_INVALID") : undefined;
}

/** Rejects malformed identity material before it reaches the Convex client. */
export function validateWorkerIdentityToken(value: string) {
  if (value.length < 8 || value.length > 16_384 || /\s/.test(value) || value.includes("\0")) throw new Error("E_SOURCE_WORKER_IDENTITY_INVALID");
  return value;
}

/** Creates a provider that rereads file and environment sources for every cycle. */
export function createWorkerIdentityProvider(config: WorkerIdentityConfig, dependencies: Pick<WorkerCredentialDependencies, "readTextFile" | "readEnvironment">) {
  return async () => {
    const value = config.mode === "rotating-file" ? await dependencies.readTextFile(config.tokenFile) : dependencies.readEnvironment(config.environmentKey);
    if (value === undefined) throw new Error("E_SOURCE_WORKER_IDENTITY_INVALID");
    return validateWorkerIdentityToken(value.trim());
  };
}

/** Resolves only closed env and mounted-vault references and rereads values on every call. */
export function createWorkerReferenceResolver(vaultMount: string | undefined, dependencies: Pick<WorkerCredentialDependencies, "readMountedSecret" | "readEnvironment">) {
  return async (reference: string) => {
    const parsed = parseWorkerSourceReference(reference);
    if (parsed.scheme === "env") {
      const value = dependencies.readEnvironment(parsed.key);
      if (value === undefined) throw new Error("E_SOURCE_WORKER_REFERENCE_UNRESOLVED");
      return secretText(value, "E_SOURCE_WORKER_REFERENCE_UNRESOLVED");
    }
    if (!vaultMount) throw new Error("E_SOURCE_WORKER_VAULT_MOUNT_REQUIRED");
    return secretText(await dependencies.readMountedSecret(vaultMount, parsed.key), "E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  };
}

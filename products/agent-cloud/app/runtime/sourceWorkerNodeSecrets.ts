import { readFile, realpath, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";

const MAX_SECRET_BYTES = 65_536;

function insideMount(mountPath: string, candidatePath: string) {
  const mount = mountPath.toLowerCase();
  const candidate = candidatePath.toLowerCase();
  return candidate.startsWith(`${mount}${sep.toLowerCase()}`);
}
async function readSafeSecretFile(path: string) {
  const details = await stat(path);
  if (!details.isFile() || details.size > MAX_SECRET_BYTES || (process.platform !== "win32" && (details.mode & 0o007) !== 0)) throw new Error("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  return readFile(path, "utf8");
}

/** Reads an identity token after file type, size, and non-Windows permissions checks. */
export async function readWorkerIdentityFile(path: string) {
  try { return await readSafeSecretFile(await realpath(path)); }
  catch (error) {
    if (error instanceof Error && error.message === "E_SOURCE_WORKER_SECRET_FILE_UNSAFE") throw error;
    throw new Error("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  }
}

/** Resolves a vault key through real paths and rejects mount escape before reading. */
export async function readConfinedMountedSecret(mountPath: string, key: string) {
  try {
    const mount = await realpath(mountPath);
    const candidate = await realpath(resolve(mount, key));
    if (!insideMount(mount, candidate)) throw new Error("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
    return await readSafeSecretFile(candidate);
  } catch (error) {
    if (error instanceof Error && error.message === "E_SOURCE_WORKER_SECRET_FILE_UNSAFE") throw error;
    throw new Error("E_SOURCE_WORKER_SECRET_FILE_UNSAFE");
  }
}

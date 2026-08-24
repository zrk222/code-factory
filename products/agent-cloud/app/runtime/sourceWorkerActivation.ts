import { parseWorkerSourceReference, type WorkerIdentityConfig } from "./sourceWorkerCredentials.js";

export type SourceWorkerActivationPolicy = {
  expectedIssuer: string;
  expectedAudience: string;
  expectedSubject: string;
  sourceReferences: string[];
  rotationDrillSeconds?: number;
};

export type SourceWorkerActivationReceipt = {
  schemaVersion: 1;
  status: "ready";
  checkedAt: number;
  referenceCount: number;
  signatureVerified: false;
  requiresControlPlaneVerification: true;
};

export type SourceWorkerRotationReceipt = {
  schemaVersion: 1;
  status: "rotated";
  checkedAt: number;
  samples: number;
  identityRotated: true;
  rotatedReferences: number;
};

export type SourceWorkerActivationDependencies = {
  loadIdentity: () => Promise<string>;
  resolveReference: (sourceReference: string) => Promise<string>;
  decodeJwtPayload: (compactJwt: string) => unknown;
  digest: (value: string) => Promise<string>;
  nowSeconds: () => number;
  sleep: (milliseconds: number) => Promise<void>;
};

type ActivationSnapshot = {
  identityDigest: string;
  sourceDigests: string[];
  checkedAt: number;
};

const COMPACT_JWT_SEGMENT = /^[A-Za-z0-9_-]+$/;
const MAX_POLICY_TEXT = 512;
const MAX_SECRET_CHARACTERS = 65_536;

function requiredPolicyText(value: string | undefined) {
  if (value === undefined || value.trim() === "") throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_MISSING");
  const normalized = value.trim();
  if (normalized.length > MAX_POLICY_TEXT || normalized.includes("\0")) throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID");
  return normalized;
}

/** Parses a secret-free activation policy and validates every closed source reference. */
export function parseSourceWorkerActivationPolicy(environment: Record<string, string | undefined>): SourceWorkerActivationPolicy {
  const expectedIssuer = requiredPolicyText(environment.SOURCE_WORKER_EXPECTED_ISSUER);
  const expectedAudience = requiredPolicyText(environment.SOURCE_WORKER_EXPECTED_AUDIENCE);
  const expectedSubject = requiredPolicyText(environment.SOURCE_WORKER_EXPECTED_SUBJECT);
  const serializedReferences = environment.SOURCE_WORKER_ACTIVATION_REFERENCES;
  if (serializedReferences === undefined || serializedReferences.trim() === "") throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_MISSING");
  let sourceReferences: unknown;
  try { sourceReferences = JSON.parse(serializedReferences); }
  catch { throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID"); }
  if (!Array.isArray(sourceReferences) || sourceReferences.length < 1 || sourceReferences.length > 32 || sourceReferences.some((value) => typeof value !== "string")) throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID");
  try { sourceReferences.forEach((value) => parseWorkerSourceReference(value)); }
  catch { throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID"); }
  const drillValue = environment.SOURCE_WORKER_ROTATION_DRILL_SECONDS?.trim();
  const rotationDrillSeconds = drillValue === undefined || drillValue === "" ? undefined : Number(drillValue);
  if (rotationDrillSeconds !== undefined && (!Number.isInteger(rotationDrillSeconds) || rotationDrillSeconds < 5 || rotationDrillSeconds > 300)) throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID");
  return { expectedIssuer, expectedAudience, expectedSubject, sourceReferences, rotationDrillSeconds };
}

function claimsObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("E_SOURCE_WORKER_IDENTITY_CLAIMS_INVALID");
  return value as Record<string, unknown>;
}

function validateIdentityClaims(tokenValue: string, policy: SourceWorkerActivationPolicy, dependencies: SourceWorkerActivationDependencies, now: number) {
  const segments = tokenValue.split(".");
  if (segments.length !== 3 || segments.some((segment) => !COMPACT_JWT_SEGMENT.test(segment))) throw new Error("E_SOURCE_WORKER_IDENTITY_CLAIMS_INVALID");
  let decoded: unknown;
  try { decoded = dependencies.decodeJwtPayload(tokenValue); }
  catch { throw new Error("E_SOURCE_WORKER_IDENTITY_CLAIMS_INVALID"); }
  const claims = claimsObject(decoded);
  if (claims.iss !== policy.expectedIssuer) throw new Error("E_SOURCE_WORKER_IDENTITY_ISSUER_MISMATCH");
  const audiences = typeof claims.aud === "string" ? [claims.aud] : Array.isArray(claims.aud) && claims.aud.every((value) => typeof value === "string") ? claims.aud : [];
  if (!audiences.includes(policy.expectedAudience)) throw new Error("E_SOURCE_WORKER_IDENTITY_AUDIENCE_MISMATCH");
  if (claims.sub !== policy.expectedSubject) throw new Error("E_SOURCE_WORKER_IDENTITY_SUBJECT_MISMATCH");
  if (!Number.isInteger(claims.exp) || (claims.exp as number) < now + 120) throw new Error("E_SOURCE_WORKER_IDENTITY_TIME_INVALID");
  for (const name of ["nbf", "iat"] as const) {
    const value = claims[name];
    if (value !== undefined && (!Number.isInteger(value) || (value as number) > now + 30)) throw new Error("E_SOURCE_WORKER_IDENTITY_TIME_INVALID");
  }
}

async function collectActivationSnapshot(policy: SourceWorkerActivationPolicy, identity: WorkerIdentityConfig, dependencies: SourceWorkerActivationDependencies): Promise<ActivationSnapshot> {
  if (identity.mode !== "rotating-file") throw new Error("E_SOURCE_WORKER_PRODUCTION_IDENTITY_REQUIRED");
  const tokenValue = await dependencies.loadIdentity();
  const checkedAt = dependencies.nowSeconds();
  validateIdentityClaims(tokenValue, policy, dependencies, checkedAt);
  const sourceDigests: string[] = [];
  for (const sourceReference of policy.sourceReferences) {
    const resolved = (await dependencies.resolveReference(sourceReference)).trim();
    if (!resolved || resolved.length > MAX_SECRET_CHARACTERS || resolved.includes("\0")) throw new Error("E_SOURCE_WORKER_REFERENCE_UNRESOLVED");
    sourceDigests.push(await dependencies.digest(resolved));
  }
  return { identityDigest: await dependencies.digest(tokenValue), sourceDigests, checkedAt };
}

function readyReceipt(checkedAt: number, count: number): SourceWorkerActivationReceipt {
  return { schemaVersion: 1, status: "ready", checkedAt, referenceCount: count, signatureVerified: false, requiresControlPlaneVerification: true };
}

/** Validates the production credential boundary and returns only a redacted readiness receipt. */
export async function runSourceWorkerActivationPreflight(policy: SourceWorkerActivationPolicy, identity: WorkerIdentityConfig, dependencies: SourceWorkerActivationDependencies): Promise<SourceWorkerActivationReceipt> {
  const snapshot = await collectActivationSnapshot(policy, identity, dependencies);
  return readyReceipt(snapshot.checkedAt, snapshot.sourceDigests.length);
}

/** Samples the live boundary once per second until identity and all configured sources rotate. */
export async function runSourceWorkerRotationDrill(policy: SourceWorkerActivationPolicy, identity: WorkerIdentityConfig, dependencies: SourceWorkerActivationDependencies): Promise<SourceWorkerRotationReceipt> {
  if (policy.rotationDrillSeconds === undefined) throw new Error("E_SOURCE_WORKER_ACTIVATION_CONFIG_MISSING");
  const baseline = await collectActivationSnapshot(policy, identity, dependencies);
  let samples = 1;
  for (let elapsed = 1; elapsed <= policy.rotationDrillSeconds; elapsed += 1) {
    await dependencies.sleep(1_000);
    const current = await collectActivationSnapshot(policy, identity, dependencies);
    samples += 1;
    const identityRotated = current.identityDigest !== baseline.identityDigest;
    const rotatedReferences = current.sourceDigests.filter((value, index) => value !== baseline.sourceDigests[index]).length;
    if (identityRotated && rotatedReferences === baseline.sourceDigests.length) return { schemaVersion: 1, status: "rotated", checkedAt: current.checkedAt, samples, identityRotated: true, rotatedReferences };
  }
  throw new Error("E_SOURCE_WORKER_ROTATION_NOT_OBSERVED");
}

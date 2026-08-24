import { parseWorkerSourceReference } from "./sourceWorkerCredentials";

export const SOURCE_AUTHORITY_CATEGORIES = [
  "primary-law",
  "official-regulator",
  "official-registry",
  "licensed-system-of-record",
  "secondary-corroboration",
] as const;

export type SourceAuthorityCategory = typeof SOURCE_AUTHORITY_CATEGORIES[number];
export type SourceState = "healthy" | "degraded" | "stale" | "unavailable" | "setup-required" | "disabled";
export type SourceGroupState = "ready" | "blocked";

export type SourceAssuranceInput = {
  sourceGroup: string;
  authorityCategory: SourceAuthorityCategory;
  status: "setup-required" | "ready" | "disabled";
  freshnessSloSeconds: number;
  maximumAgeSeconds: number;
  minimumAuthoritativeSources: number;
  requiredForRuns: boolean;
  lastSuccessfulAt?: number;
  consecutiveFailures: number;
};

export type SourceAssessment = {
  state: SourceState;
  ageSeconds: number | null;
  reason:
    | "SOURCE_HEALTHY"
    | "SOURCE_FRESHNESS_SLO_EXCEEDED"
    | "SOURCE_RECENT_FAILURES"
    | "SOURCE_MAXIMUM_AGE_EXCEEDED"
    | "SOURCE_NEVER_OBSERVED"
    | "SOURCE_FAILURE_THRESHOLD_EXCEEDED"
    | "SOURCE_SETUP_REQUIRED"
    | "SOURCE_DISABLED";
  countsAsAuthoritative: boolean;
};

export type SourceGroupAssessment = {
  sourceGroup: string;
  state: SourceGroupState;
  reason: "READY" | "AUTHORITATIVE_COUNT_BELOW_MINIMUM" | "NO_HEALTHY_AUTHORITATIVE_SOURCE";
  requiredForRuns: boolean;
  minimumAuthoritativeSources: number;
  qualifyingAuthoritativeSources: number;
  healthyAuthoritativeSources: number;
  totalSources: number;
};

const SOURCE_SECRET_QUERY_KEY = /(?:token|key|secret|password|credential|signature|api[_-]?key)/i;

/** Validates a credential-free canonical HTTPS locator for public source identity. */
export function validateAuthoritativeLocator(value: string) {
  const clean = value.trim();
  if (clean.length === 0 || clean.length > 500) throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
  let locator: URL;
  try { locator = new URL(clean); } catch { throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN"); }
  if (locator.protocol !== "https:") throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
  if (locator.username) throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
  if (locator.password) throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
  for (const key of locator.searchParams.keys()) {
    if (SOURCE_SECRET_QUERY_KEY.test(key)) throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
  }
  return locator.toString();
}

/** Accepts only opaque worker-resolved endpoint and license references. */
export function validateOpaqueSourceReference(value: string) {
  const clean = value.trim();
  try { parseWorkerSourceReference(clean); }
  catch { throw new Error("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN"); }
  return clean;
}

/** Evaluates one source at a caller-supplied timestamp so every admission decision shares one clock. */
export function evaluateSourceState(source: SourceAssuranceInput, nowMs: number): SourceAssessment {
  const countsAsAuthoritative = source.authorityCategory !== "secondary-corroboration";
  if (source.status === "disabled") return { state: "disabled", ageSeconds: null, reason: "SOURCE_DISABLED", countsAsAuthoritative };
  if (source.status === "setup-required") return { state: "setup-required", ageSeconds: null, reason: "SOURCE_SETUP_REQUIRED", countsAsAuthoritative };
  if (source.lastSuccessfulAt === undefined) return { state: "unavailable", ageSeconds: null, reason: "SOURCE_NEVER_OBSERVED", countsAsAuthoritative };

  const ageSeconds = Math.max(0, Math.floor((nowMs - source.lastSuccessfulAt) / 1000));
  if (source.consecutiveFailures >= 3) return { state: "unavailable", ageSeconds, reason: "SOURCE_FAILURE_THRESHOLD_EXCEEDED", countsAsAuthoritative };
  if (ageSeconds > source.maximumAgeSeconds) return { state: "stale", ageSeconds, reason: "SOURCE_MAXIMUM_AGE_EXCEEDED", countsAsAuthoritative };
  if (source.consecutiveFailures > 0) return { state: "degraded", ageSeconds, reason: "SOURCE_RECENT_FAILURES", countsAsAuthoritative };
  if (ageSeconds > source.freshnessSloSeconds) return { state: "degraded", ageSeconds, reason: "SOURCE_FRESHNESS_SLO_EXCEEDED", countsAsAuthoritative };
  return { state: "healthy", ageSeconds, reason: "SOURCE_HEALTHY", countsAsAuthoritative };
}

/** Computes fail-closed redundancy for every required group without promoting secondary sources. */
export function assessSourceGroups<T extends SourceAssuranceInput>(sources: readonly T[], nowMs: number): SourceGroupAssessment[] {
  const grouped = new Map<string, T[]>();
  for (const source of sources) {
    const current = grouped.get(source.sourceGroup) ?? [];
    current.push(source);
    grouped.set(source.sourceGroup, current);
  }
  return [...grouped.entries()].map(([sourceGroup, groupSources]): SourceGroupAssessment => {
    const requiredForRuns = groupSources.some((source) => source.requiredForRuns);
    const minimumAuthoritativeSources = Math.max(...groupSources.map((source) => source.minimumAuthoritativeSources));
    const authoritative = groupSources
      .map((source) => evaluateSourceState(source, nowMs))
      .filter((assessment) => assessment.countsAsAuthoritative);
    const qualifyingAuthoritativeSources = authoritative.filter((assessment) => assessment.state === "healthy" || assessment.state === "degraded").length;
    const healthyAuthoritativeSources = authoritative.filter((assessment) => assessment.state === "healthy").length;
    const reason = qualifyingAuthoritativeSources < minimumAuthoritativeSources
      ? "AUTHORITATIVE_COUNT_BELOW_MINIMUM" as const
      : healthyAuthoritativeSources === 0
        ? "NO_HEALTHY_AUTHORITATIVE_SOURCE" as const
        : "READY" as const;
    return {
      sourceGroup,
      state: reason === "READY" ? "ready" : "blocked",
      reason,
      requiredForRuns,
      minimumAuthoritativeSources,
      qualifyingAuthoritativeSources,
      healthyAuthoritativeSources,
      totalSources: groupSources.length,
    };
  }).sort((left, right) => left.sourceGroup.localeCompare(right.sourceGroup));
}

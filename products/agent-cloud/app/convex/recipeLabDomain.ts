export type RecipeMemoryMode = "none" | "run-only" | "governed";
export type RecipeAuthorityMode = "read-only" | "propose" | "approval-required";

export type RecipeCandidate = {
  model: string;
  retrievalTopK: number;
  memoryMode: RecipeMemoryMode;
  authorityMode: RecipeAuthorityMode;
};

export type RecipeMetrics = {
  recipeDigest: string;
  qualityScore: number;
  costCredits: number;
  latencyMs: number;
  policyViolations: number;
};

export type RecipeConstraints = {
  minQuality: number;
  maxLatencyMs: number;
  perTrialCreditCap: number;
};

export type RecipeWeights = {
  quality: number;
  cost: number;
  latency: number;
};

type SearchSpace = {
  trialCount: number;
  models: readonly string[];
  retrievalTopK: readonly number[];
  memoryModes: readonly RecipeMemoryMode[];
  authorityModes: readonly RecipeAuthorityMode[];
};

const unique = <T>(items: readonly T[]) => [...new Set(items)];

/** Validates and expands a bounded search space into deterministic unique candidates. */
export function generateRecipeCandidates(space: SearchSpace): RecipeCandidate[] {
  const models = unique(space.models.map((item) => item.trim()).filter(Boolean));
  const retrieval = unique(space.retrievalTopK);
  const memories = unique(space.memoryModes);
  const authorities = unique(space.authorityModes);
  validateSearchBounds(space.trialCount, models, retrieval, memories, authorities);
  const candidates: RecipeCandidate[] = [];
  for (const model of models) {
    for (const retrievalTopK of retrieval) {
      for (const memoryMode of memories) {
        for (const authorityMode of authorities) candidates.push({ model, retrievalTopK, memoryMode, authorityMode });
      }
    }
  }
  if (candidates.length < space.trialCount) throw new Error("E_RECIPE_SEARCH_SPACE_INVALID");
  return candidates.slice(0, space.trialCount);
}

function validateSearchBounds(
  trialCount: number,
  models: readonly string[],
  retrieval: readonly number[],
  memories: readonly RecipeMemoryMode[],
  authorities: readonly RecipeAuthorityMode[],
) {
  const counts = [models.length <= 8, retrieval.length <= 4, memories.length <= 3, authorities.length <= 3];
  const nonempty = [models.length, retrieval.length, memories.length, authorities.length].every((value) => value >= 1);
  const trialCountValid = Number.isInteger(trialCount) && trialCount >= 2 && trialCount <= 24;
  const retrievalValid = retrieval.every((value) => integerWithin(value, 1, 100));
  if (!trialCountValid || !nonempty || counts.includes(false) || !retrievalValid) {
    throw new Error("E_RECIPE_SEARCH_SPACE_INVALID");
  }
}

const integerWithin = (value: number, minimum: number, maximum: number) => Number.isInteger(value) && value >= minimum && value <= maximum;

/** Applies hard trust, quality, cost, and latency constraints to one result. */
export function evaluateRecipeEligibility(metrics: RecipeMetrics, constraints: RecipeConstraints) {
  const reasons: string[] = [];
  if (metrics.policyViolations > 0) reasons.push("policy-violation");
  if (metrics.qualityScore < constraints.minQuality) reasons.push("quality-below-floor");
  if (metrics.costCredits > constraints.perTrialCreditCap) reasons.push("trial-credit-cap");
  if (metrics.latencyMs > constraints.maxLatencyMs) reasons.push("latency-cap");
  return { eligible: reasons.length === 0, reasons };
}

const dominates = (left: RecipeMetrics, right: RecipeMetrics) => {
  const noWorse = left.qualityScore >= right.qualityScore && left.costCredits <= right.costCredits && left.latencyMs <= right.latencyMs;
  const better = left.qualityScore > right.qualityScore || left.costCredits < right.costCredits || left.latencyMs < right.latencyMs;
  return noWorse && better;
};

const weightedScore = (trial: RecipeMetrics, constraints: RecipeConstraints, weights: RecipeWeights) => {
  const costScore = Math.max(0, 100 - Math.round((trial.costCredits / constraints.perTrialCreditCap) * 100));
  const latencyScore = Math.max(0, 100 - Math.round((trial.latencyMs / Math.max(1, constraints.maxLatencyMs)) * 100));
  return trial.qualityScore * weights.quality + costScore * weights.cost + latencyScore * weights.latency;
};

/** Returns the eligible Pareto frontier and a deterministic weighted champion. */
export function selectRecipeChampion(trials: RecipeMetrics[], constraints: RecipeConstraints, weights: RecipeWeights) {
  if (weights.quality + weights.cost + weights.latency !== 100) throw new Error("E_RECIPE_WEIGHTS_INVALID");
  const eligible = trials.filter((trial) => evaluateRecipeEligibility(trial, constraints).eligible);
  if (eligible.length === 0) return { champion: null, frontier: [] as RecipeMetrics[] };
  const frontier = eligible.filter((candidate) => !eligible.some((other) => other.recipeDigest !== candidate.recipeDigest && dominates(other, candidate)));
  const ranked = [...frontier].sort((left, right) => weightedScore(right, constraints, weights) - weightedScore(left, constraints, weights) || left.recipeDigest.localeCompare(right.recipeDigest));
  return { champion: ranked[0], frontier, weightedScore: weightedScore(ranked[0], constraints, weights) };
}

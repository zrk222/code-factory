import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { assertRequiredSourcesReady } from "./authoritativeSources";

/** Applies the authoritative-source gate at execution admission using one server timestamp. */
export function enforceAuthoritativeSourceAdmission(ctx: MutationCtx, agentSpecId: Id<"agentSpecs">, now: number) {
  return assertRequiredSourcesReady(ctx, agentSpecId, now);
}

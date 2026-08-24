import { describe, expect, test } from "vitest";

const sources = import.meta.glob("./*.ts", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

const manifest: Record<string, readonly string[]> = {
  "access.ts": ["bootstrapOwner", "addMember", "revokeMember", "myAccess", "myWorkspaces", "readAgentSpec"],
  "agentIntelligence.ts": ["savePreset", "publishPreset", "getPreset", "addClarification", "answerClarification", "saveOpsRule", "publishOpsRule", "resumeJob", "runIntelligence"],
  "authoritativeSources.ts": ["configure", "listReadiness", "listWorkerDefinitions", "recordWorkerObservation", "disable"],
  "budget.ts": ["reserveCall", "reconcileCall", "releaseCall", "status"],
  "blueprints.ts": ["save", "simulate", "activate", "get"],
  "control.ts": ["saveAgentSpec", "launchRun", "decideApproval", "runDetail"],
  "credits.ts": ["quote", "reserveBlueprint", "settle", "status", "plans"],
  "concierge.ts": ["saveProfile", "configureAdapter", "submitLead", "requestBooking", "approveBooking", "recordOutcome", "overview"],
  "dashboard.ts": ["overview"],
  "databaseTools.ts": ["configureConnection", "registerOperation", "publishOperation", "requestOperation", "approveWrite", "list"],
  "execution.ts": ["enqueue", "cancel", "status"],
  "enterpriseIdentity.ts": ["createOrganization", "addOrganizationAdmin", "configureDirectory", "provisionWorkspaceMember", "posture"],
  "enterpriseGovernance.ts": ["configurePolicy", "placeLegalHold", "releaseLegalHold", "requestDeletion", "posture"],
  "enterpriseSecurity.ts": ["configureAdmission", "qualification"],
  "incidents.ts": ["openIncident", "recordRecoveryCheck", "resolveIncident"],
  "inferenceBindings.ts": ["bind", "get"],
  "knowledgeConnectors.ts": ["configure", "list", "disable"],
  "lifecycle.ts": ["exportAgentSpec", "importAgentSpec", "rollbackAgentSpec", "setLifecycle", "configureProvider"],
  "memory.ts": ["add", "correct", "remove", "enforceRetention", "listActive", "recallScoped", "exportGoverned"],
  "operations.ts": ["productionReadiness", "health", "requestBackup", "requestRestoreDrill"],
  "releases.ts": ["startCanary", "recordObservation", "promoteCanary", "rollbackCanary"],
  "recipeLab.ts": ["createStudy", "startStudy", "finalizeStudy", "approveChampion", "getStudy"],
  "runtimeAdapters.ts": ["configure", "list", "disable"],
  "seed.ts": ["ensureDemo"],
  "trust.ts": ["issueCapability", "authorizeToolCall", "revokeCapability", "status"],
};

describe("complete public route authorization manifest", () => {
  test("classifies every public query and mutation and keeps an identity guard in its handler block", () => {
    for (const [file, expected] of Object.entries(manifest)) {
      const source = sources[`./${file}`];
      expect(source, `${file} source`).toBeTypeOf("string");
      const discovered = [...source.matchAll(/export const (\w+) = (?:query|mutation)\s*\(/g)].map((match) => match[1]);
      expect(discovered, `${file} public API drift`).toEqual(expected);
      for (const [index, route] of discovered.entries()) {
        const start = source.indexOf(`export const ${route} =`);
        const end = index + 1 < discovered.length ? source.indexOf(`export const ${discovered[index + 1]} =`, start) : source.length;
        const block = source.slice(start, end);
        expect(block, `${file}.${route} has no server-derived identity guard`).toMatch(/requireWorkspaceRole\(|requireOrganizationRole\(|principal\(/);
      }
    }
  });
});

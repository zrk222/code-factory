import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, vi } from "vitest";
import App from "./App";

const mutate = vi.fn(async () => ({ marker: "OK", version: 2 }));
const now = Date.now();
const mockData = {
  marker: "PRODUCT_VIEWS_BOUND",
  workspace: { _id: "workspace", _creationTime: now, slug: "factory-lab", name: "Factory Lab", plan: "pilot", createdAt: now },
  agentSpec: { _id: "spec", _creationTime: now, workspaceId: "workspace", name: "PR Assurance", repository: "zrk222/code-factory", providerProfile: "balanced", memoryMode: "architecture-history", authorityMode: "approval-required", hardBudgetCents: 450, validators: ["Test suite"], version: 1, status: "active", updatedAt: now },
  blueprint: null, blueprintVersions: [],
  creditAccount: { _id: "credits", _creationTime: now, workspaceId: "workspace", plan: "starter", availableCredits: 500, reservedCredits: 0, spentCredits: 0, monthlyAllocation: 500, periodStart: now, periodEnd: now + 1000, status: "active", updatedAt: now }, creditTransactions: [], inferenceBinding: null,
  creditPlans: [{ plan: "starter", name: "Starter", monthlyCredits: 500, agentLimit: 2, audience: "Solo builders" }],
  executionJobs: [],
  backupSnapshots: [], restoreDrills: [],
  runs: [{
    _id: "run", _creationTime: now, workspaceId: "workspace", agentSpecId: "spec", branch: "feature/budget",
    commitSha: "c".repeat(40), status: "awaiting-approval", estimatedCostCents: 127, actualCostCents: 120,
    proposedAction: "Create proposal", actionDigest: "digest", startedAt: now, gates: [], approval: null,
  }], approvals: [], receipts: [], memories: [], memoryLedger: [], auditEvents: [],
  memoryExport: { marker: "MEMORY_EXPORT_READY", sanitizedMarker: "MEMORY_EXPORT_SANITIZED", canonical: JSON.stringify({ schema: "code-factory.MemoryExport.v1", records: [] }), digest: "fedcba9876543210", records: [] },
  routes: [{ _id: "route", _creationTime: now, workspaceId: "workspace", profile: "balanced", primaryProvider: "OpenAI", primaryModel: "gpt-5", fallbackProvider: "Anthropic", fallbackModel: "claude-sonnet", cacheAffinity: true, updatedAt: now }],
  versions: [{ _id: "version", _creationTime: now, workspaceId: "workspace", agentSpecId: "spec", version: 1, name: "PR Assurance", repository: "zrk222/code-factory", providerProfile: "balanced", memoryMode: "architecture-history", authorityMode: "approval-required", hardBudgetCents: 450, validators: ["Test suite"], digest: "0123456789abcdef", source: "seed", createdAt: now }],
  providerConnections: [],
  knowledgeConnectors: [],
  agentSpecExport: { marker: "AGENT_SPEC_EXPORTED", canonical: JSON.stringify({ name: "PR Assurance", repository: "zrk222/code-factory", providerProfile: "balanced", memoryMode: "architecture-history", authorityMode: "approval-required", hardBudgetCents: 450, validators: ["Test suite"] }), digest: "0123456789abcdef", version: 1 },
};
const conciergeData = { marker: "CONCIERGE_OVERVIEW_READY", profile: null, adapters: [], leads: [], approvals: [], bookings: [], outcomes: [], metrics: { leads: 0, qualified: 0, bookings: 0, attended: 0, noShows: 0, canceled: 0, modeledPipelineValueCents: 0, observedRevenueCents: 0 } };

vi.mock("convex/react", () => ({
  useQuery: (_query: unknown, args?: unknown) => args && typeof args === "object" && "workspaceId" in args
    ? mockData
    : args && typeof args === "object" && "agentSpecId" in args
      ? conciergeData
      : { marker: "AUTHENTICATED_WORKSPACES_DERIVED", workspaces: [{ workspace: mockData.workspace, role: "owner", memberLabel: "Test owner" }] },
  useMutation: () => mutate,
}));

beforeEach(() => window.localStorage.clear());

describe("Agent Oven shell", () => {
  test("renders the product promise and all six views", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: /every important pr arrives with proof/i })).toBeInTheDocument();
    for (const label of ["Overview", "Outcome Exchange", "Agent Builder", "Runs", "Evidence", "Memory", "Settings"]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
  });

  test("navigates to the Agent Builder configuration", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Agent Builder" }));
    expect(screen.getByRole("heading", { name: /configure the job/i })).toBeInTheDocument();
    expect(screen.getByDisplayValue("zrk222/code-factory")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run six assurance gates/i })).toBeInTheDocument();
  });

  test("applies a novice template without saving or launching", async () => {
    mutate.mockClear();
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Agent Builder" }));
    await userEvent.click(screen.getByRole("button", { name: /community memory guide/i }));
    await userEvent.click(screen.getByRole("button", { name: /use this recipe/i }));
    expect(screen.getByDisplayValue("your-org/community-memory-guide")).toBeInTheDocument();
    expect(screen.getByDisplayValue("20.00")).toBeInTheDocument();
    expect(mutate).not.toHaveBeenCalled();
  });

  test("opens the Booked Job Concierge as a recipe-specific guided journey", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Agent Builder" }));
    await userEvent.click(screen.getByRole("button", { name: /booked job concierge/i }));
    await userEvent.click(screen.getByRole("button", { name: /use this recipe/i }));
    expect(screen.getByRole("heading", { name: /turn the next qualified inquiry/i })).toBeInTheDocument();
    expect(screen.getByText(/sandbox setup and testing: 0 credits/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /run six assurance gates/i })).not.toBeInTheDocument();
  });

  test("feeds an approved operating guideline into the governed Knowledge Wall", async () => {
    mutate.mockClear();
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Agent Builder" }));
    await userEvent.selectOptions(screen.getByLabelText("Knowledge type"), "Policy and guardrail");
    await userEvent.type(screen.getByLabelText("Source reference"), "handbook/returns.md");
    await userEvent.type(screen.getByLabelText("Guideline or approved extract"), "Escalate refunds above $500 for human approval.");
    await userEvent.click(screen.getByRole("button", { name: /add to knowledge wall/i }));
    expect(mutate).toHaveBeenCalledWith(expect.objectContaining({ purpose: "Agent operating manual", source: "handbook/returns.md", retentionDays: 365 }));
  });

  test("renders Phase 1 lifecycle and secret-reference controls", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(screen.getByRole("heading", { name: /control the agent/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /pause agent/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /save openai reference/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /save anthropic reference/i })).toBeInTheDocument();
    expect(screen.getByDisplayValue("env:OPENAI_API_KEY")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /workspace access boundary/i })).toBeInTheDocument();
    expect(screen.getByText(/oidc session enforced/i)).toBeInTheDocument();
    expect(screen.getByText(/server checks every route/i)).toBeInTheDocument();
  });

  test("renders the execution-time Trust gateway on runs", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Runs" }));
    expect(screen.getByRole("heading", { name: /trust gateway/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /issue 5-minute capability/i })).toBeDisabled();
    expect(screen.getByText(/stores no raw credential and invokes no connector/i)).toBeInTheDocument();
  });

  test("renders Phase 2 memory governance controls", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Memory" }));
    expect(screen.getByRole("heading", { name: /correct the record/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /store with provenance/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /enforce retention/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /recall safely/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /scoped recall lab/i })).toBeInTheDocument();
    expect(screen.getByText(/0 authority fields/i)).toBeInTheDocument();
  });

  test("renders the atomic budget gateway on a run", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Runs" }));
    expect(screen.getByRole("heading", { name: /budget gateway/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reserve before call/i })).toBeInTheDocument();
  });
});

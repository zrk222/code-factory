import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import axe from "axe-core";
import { GovernedRuntimePanel } from "./GovernedRuntimePanel";
import { DatabaseToolPanel } from "./DatabaseToolPanel";

const mocked = vi.hoisted(() => ({ query: undefined as unknown, mutate: vi.fn(async () => ({ marker: "OK", version: 1 })) }));
vi.mock("convex/react", () => ({ useQuery: () => mocked.query, useMutation: () => mocked.mutate }));
const agentSpec = { _id: "agent", workspaceId: "workspace", name: "Ops agent", repository: "org/repo", providerProfile: "balanced", memoryMode: "run-only", authorityMode: "approval-required", hardBudgetCents: 800, validators: [], version: 1, status: "active", updatedAt: 1 } as never;

describe("governed runtime assembly", () => {
  beforeEach(() => { mocked.query = undefined; mocked.mutate.mockClear(); });

  test("shows Perplexity and Mastra-derived controls in novice language", async () => {
    const { container } = render(<GovernedRuntimePanel agentSpec={agentSpec} />);
    expect(screen.getByRole("heading", { name: /choose the rails before the agent runs/i })).toBeInTheDocument();
    expect(screen.getByText(/plan, gather, check, act/i)).toBeInTheDocument();
    expect(screen.getByText(/exact usage/i)).toBeInTheDocument();
    expect(screen.getByText(/component scores/i)).toBeInTheDocument();
    expect(screen.getByText(/durable resume/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /save preset/i }));
    expect(mocked.mutate).toHaveBeenCalledWith(expect.objectContaining({ updateChannel: "frozen", maxSteps: 24, requireClarification: true, rubricVersion: "agent-oven.runtime-rubric.v1" }));
    const accessibility = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(accessibility.violations).toEqual([]);
  });

  test("offers remote database assembly using references and allowlists", async () => {
    mocked.query = { connection: null, operations: [], requests: [] };
    render(<DatabaseToolPanel agentSpec={agentSpec} />);
    expect(screen.getByRole("heading", { name: /let agents use operations data/i })).toBeInTheDocument();
    expect(screen.getByDisplayValue("env:DATABASE_ENDPOINT")).toBeInTheDocument();
    expect(screen.getByDisplayValue("vault:agent-oven/database/operations")).toBeInTheDocument();
    expect(screen.getByText(/arbitrary sql, raw credentials/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /add secure database/i }));
    expect(mocked.mutate).toHaveBeenCalledWith(expect.objectContaining({ engine: "postgresql", allowedNamespaces: ["operations"], secretRef: "vault:agent-oven/database/operations" }));
  });
});

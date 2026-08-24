import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import axe from "axe-core";
import { AgentRecipeLab } from "./AgentRecipeLab";

const mocked = vi.hoisted(() => ({ query: null as unknown, mutate: vi.fn(async () => ({ studyId: "study", marker: "OK" })) }));
vi.mock("convex/react", () => ({ useQuery: () => mocked.query, useMutation: () => mocked.mutate }));
const agentSpec = { _id: "agent", workspaceId: "workspace", name: "Ops agent", repository: "org/repo", providerProfile: "balanced", memoryMode: "run-only", authorityMode: "approval-required", hardBudgetCents: 800, validators: [], version: 1, status: "active", updatedAt: 1 } as never;

describe("Agent Recipe Lab", () => {
  beforeEach(() => { mocked.query = null; mocked.mutate.mockClear(); });

  test("presents all six novice stages and queues a bounded study", async () => {
    const user = userEvent.setup();
    const { container } = render(<AgentRecipeLab agentSpec={agentSpec} />);
    const stageNames = screen.getByRole("list", { name: /recipe lab stages/i }).textContent;
    expect(stageNames).toMatch(/Use case.*Evaluation set.*Search space.*Guardrails.*Optimize.*Review/);
    expect(screen.getByText(/zero policy violations/i)).toBeInTheDocument();
    expect(screen.getByText(/independent approval before activation/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /optimize within these rails/i }));
    expect(mocked.mutate).toHaveBeenCalledTimes(2);
    expect(await axe.run(container)).toHaveProperty("violations", []);
  });
});

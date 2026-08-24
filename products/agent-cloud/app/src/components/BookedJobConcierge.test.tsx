import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import axe from "axe-core";
import { BookedJobConcierge } from "./BookedJobConcierge";

const mocked = vi.hoisted(() => ({ query: undefined as unknown, mutate: vi.fn(async () => ({ marker: "OK" })) }));
vi.mock("convex/react", () => ({ useQuery: () => mocked.query, useMutation: () => mocked.mutate }));

const agentSpec = { _id: "agent", _creationTime: 1, workspaceId: "workspace", name: "Booked Job Concierge", repository: "org/agent", providerProfile: "balanced", memoryMode: "run-only", authorityMode: "approval-required", hardBudgetCents: 800, validators: ["Booking approval"], version: 1, status: "active", updatedAt: 1 } as never;
const empty = { marker: "CONCIERGE_OVERVIEW_READY", profile: null, adapters: [], leads: [], approvals: [], bookings: [], outcomes: [], metrics: { leads: 0, qualified: 0, bookings: 0, attended: 0, noShows: 0, canceled: 0, modeledPipelineValueCents: 0, observedRevenueCents: 0 } };

describe("Booked Job Concierge novice journey", () => {
  beforeEach(() => { mocked.query = empty; mocked.mutate.mockClear(); });

  test("explains price, human control, sandbox value, and secure production boundary", async () => {
    const { container } = render(<BookedJobConcierge agentSpec={agentSpec} />);
    expect(screen.getByRole("heading", { name: /turn the next qualified inquiry/i })).toBeInTheDocument();
    expect(screen.getByText("55 credits")).toBeInTheDocument();
    expect(screen.getByText(/sandbox setup and testing: 0 credits/i)).toBeInTheDocument();
    expect(screen.getByText(/approval required is locked on/i)).toBeInTheDocument();
    expect(screen.getByText("Not measured")).toBeInTheDocument();
    expect(screen.getByText("SANDBOX ONLY")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /save my booking setup/i }));
    expect(mocked.mutate).toHaveBeenCalledWith(expect.objectContaining({ serviceName: "Emergency plumbing", minimumLeadScore: 80, modeledJobValueCents: 32500 }));
    const accessibility = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(accessibility.violations).toEqual([]);
  });

  test("shows server-owned decision reasons and one clear next action", async () => {
    mocked.query = { ...empty, profile: { serviceName: "Emergency plumbing", serviceArea: "Toronto" }, leads: [{ _id: "lead", score: 100, classification: "qualified", status: "new", decisionReasons: ["service-matched", "service-area-matched", "contact-ready", "urgency-urgent"] }], metrics: { ...empty.metrics, leads: 1, qualified: 1, modeledPipelineValueCents: 0 } };
    render(<BookedJobConcierge agentSpec={agentSpec} />);
    expect(screen.getByText(/why this lead scored 100/i)).toBeInTheDocument();
    expect(screen.getByText("service area matched")).toBeInTheDocument();
    const next = screen.getByRole("button", { name: /request sample booking/i });
    await userEvent.click(next);
    expect(mocked.mutate).toHaveBeenCalledWith(expect.objectContaining({ leadId: "lead", environment: "sandbox" }));
  });
});

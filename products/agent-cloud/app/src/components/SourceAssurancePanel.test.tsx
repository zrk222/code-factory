import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import axe from "axe-core";
import { SourceAssurancePanel } from "./SourceAssurancePanel";

const mocked = vi.hoisted(() => ({ query: undefined as unknown, mutate: vi.fn(async () => ({ marker: "AUTHORITATIVE_SOURCE_CONFIGURED" })) }));
vi.mock("convex/react", () => ({ useQuery: () => mocked.query, useMutation: () => mocked.mutate }));
const agentSpec = { _id: "agent", workspaceId: "workspace", name: "Legal agent", repository: "org/repo", providerProfile: "balanced", memoryMode: "run-only", authorityMode: "approval-required", hardBudgetCents: 800, validators: [], version: 1, status: "active", updatedAt: 1 } as never;

describe("authoritative source operator experience", () => {
  beforeEach(() => { mocked.query = undefined; mocked.mutate.mockClear(); });

  test("explains the uptime boundary and creates a novice-safe source definition", async () => {
    const { container } = render(<SourceAssurancePanel agentSpec={agentSpec} />);
    expect(screen.getByRole("heading", { name: /keep regulated answers current/i })).toBeInTheDocument();
    expect(screen.getByText(/secondary material can corroborate, but can never unlock a run/i)).toBeInTheDocument();
    expect(screen.getByText(/does not claim external publisher or government uptime/i)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Publisher"), "Government of Canada");
    await userEvent.type(screen.getByLabelText("Jurisdiction"), "Canada");
    await userEvent.type(screen.getByLabelText("Canonical public HTTPS page"), "https://laws-lois.justice.gc.ca/");
    await userEvent.click(screen.getByRole("button", { name: /save authority source/i }));
    expect(mocked.mutate).toHaveBeenCalledWith(expect.objectContaining({ authorityCategory: "official-regulator", freshnessSloSeconds: 86_400, maximumAgeSeconds: 259_200, requiredForRuns: true }));
    const accessibility = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(accessibility.violations).toEqual([]);
  });

  test("shows exact group and source reasons", () => {
    mocked.query = {
      governance: "supervised source assurance",
      groups: [{ sourceGroup: "federal-law", state: "blocked", reason: "NO_HEALTHY_AUTHORITATIVE_SOURCE", requiredForRuns: true, minimumAuthoritativeSources: 2, qualifyingAuthoritativeSources: 2, healthyAuthoritativeSources: 0, totalSources: 2 }],
      sources: [{ _id: "source", label: "Justice Laws", publisher: "Department of Justice", jurisdiction: "Canada", authorityCategory: "primary-law", assurance: { state: "degraded", ageSeconds: 7_200, reason: "SOURCE_FRESHNESS_SLO_EXCEEDED" } }],
    };
    render(<SourceAssurancePanel agentSpec={agentSpec} />);
    expect(screen.getByText("NO_HEALTHY_AUTHORITATIVE_SOURCE")).toBeInTheDocument();
    expect(screen.getByText("SOURCE_FRESHNESS_SLO_EXCEEDED")).toBeInTheDocument();
    expect(screen.getByText("2h ago")).toBeInTheDocument();
  });
});

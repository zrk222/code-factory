import { render, screen } from "@testing-library/react";
import { vi } from "vitest";
import { AgentExchangePanel } from "./AgentExchangePanel";

const mutate = vi.fn(async () => ({ marker: "OK" }));
vi.mock("convex/react", () => ({
  useMutation: () => mutate,
  useQuery: () => ({
    marker: "OUTCOME_EXCHANGE_OVERVIEW_READY",
    account: { availableCredits: 500 },
    contracts: [],
    paymentRails: [
      { rail: "platform-credits", status: "active", detail: "Atomic internal result-credit reservation and settlement." },
      { rail: "stripe-connect", status: "setup-required", detail: "Requires provider read-back." },
      { rail: "mpp", status: "setup-required", detail: "Requires provider read-back." },
      { rail: "x402", status: "setup-required", detail: "Requires provider read-back." },
    ],
    offers: [
      { id: "pr-evidence-auditor", version: 1, name: "PR Evidence Auditor", category: "engineering", outcome: "A review-ready proof packet.", deliverable: "Requirements and validators.", authority: "Cannot merge or modify code.", resultCredits: 90, deliveryHours: 4, evidenceChecks: [{ id: "requirements-bound", label: "Requirements are mapped" }, { id: "negative-proof", label: "Negative proof exists" }, { id: "artifact-digests", label: "Artifacts are digested" }, { id: "scope-reviewed", label: "Scope is explicit" }] },
    ],
  }),
}));

test("renders transparent result pricing, machine discovery, and inactive external rails", () => {
  render(<AgentExchangePanel workspaceId={"workspace" as never} />);
  expect(screen.getByRole("heading", { name: /hire the result/i })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "PR Evidence Auditor" })).toBeInTheDocument();
  expect(screen.getByText(/90 credits on verified result/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /agent card/i })).toHaveAttribute("href", "/.well-known/agent-card.json");
  expect(screen.getByText("platform-credits")).toBeInTheDocument();
  expect(screen.getAllByText("setup-required")).toHaveLength(3);
  expect(screen.getByText(/real money stays off until provider-verified/i)).toBeInTheDocument();
});

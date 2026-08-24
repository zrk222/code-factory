import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { IntentComposer } from "./IntentComposer";

const mutate = vi.fn(async () => ({
  marker: "AGENT_INTENT_COMPILED",
  title: "Monitor GitHub pull requests",
  selectedRuntime: "langgraph",
  runtimeRationale: "Auto-selected for durable state.",
  inferenceAccess: "agent-oven-api",
  authorityPolicy: "approval-required",
  memoryPolicy: "governed",
  steps: [{ id: "verify", label: "Verify requirements and tests", kind: "validate", humanGate: true, flow: "sequential", dependsOn: [] }],
  evidenceChecks: ["Tests are digest-bound."],
  clarificationQuestions: [],
  readiness: "ready-for-draft",
  intentDigest: "a".repeat(64),
  compilerDigest: "b".repeat(64),
  draftId: "draft",
  fingerprint: "c".repeat(64),
  rawDescriptionStored: false,
}));

vi.mock("convex/react", () => ({ useMutation: () => mutate }));

test("compiles a plain-language brief into visible runtime, graph, and proof controls", async () => {
  render(<IntentComposer agentSpec={{ _id: "agent", workspaceId: "workspace" } as never} />);
  expect(screen.getByRole("heading", { name: /build an agent in plain english/i })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /review a code change/i }));
  expect((screen.getByLabelText(/what do you want your agent to do/i) as HTMLTextAreaElement).value).toContain("Review GitHub pull requests");
  const brief = "Monitor GitHub pull requests and verify requirements and tests within 10 minutes. Read the repository only, never merge code, stop on missing evidence, and escalate failed checks.";
  await userEvent.clear(screen.getByLabelText(/what do you want your agent to do/i));
  await userEvent.type(screen.getByLabelText(/what do you want your agent to do/i), brief);
  await userEvent.click(screen.getByRole("button", { name: /build my agent plan/i }));
  expect(await screen.findByText("Monitor GitHub pull requests")).toBeInTheDocument();
  expect(screen.getByText("langgraph")).toBeInTheDocument();
  expect(screen.getByText("Verify requirements and tests")).toBeInTheDocument();
  expect(screen.getByText(/what your agent will do/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /save agent draft/i })).toBeEnabled();
  expect(screen.getByText(/saving creates a draft, not a live agent/i)).toBeInTheDocument();
});

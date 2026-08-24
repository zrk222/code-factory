import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";
import axe from "axe-core";
import { ProductionActivationPanel } from "./ProductionActivationPanel";

const mocked = vi.hoisted(() => ({ query: undefined as unknown }));
vi.mock("convex/react", () => ({ useQuery: () => mocked.query }));

const controls = [
  { key: "identity", category: "foundation", label: "Identity trust", status: "ready", marker: "READINESS_CONTROL_READY", nextAction: null },
  { key: "app-endpoint", category: "foundation", label: "Application endpoint", status: "ready", marker: "READINESS_CONTROL_READY", nextAction: null },
  { key: "billing-webhook", category: "operations", label: "Billing webhook", status: "missing", marker: "READINESS_CONTROL_MISSING", nextAction: "Add an opaque secret-manager reference for signed billing events." },
  { key: "transactional-email", category: "operations", label: "Transactional email", status: "missing", marker: "READINESS_CONTROL_MISSING", nextAction: "Add an opaque secret-manager reference for the email service." },
  { key: "runtime-worker", category: "operations", label: "Runtime worker", status: "missing", marker: "READINESS_CONTROL_MISSING", nextAction: "Add an opaque secret-manager reference for the isolated runtime worker." },
  { key: "backup-storage", category: "operations", label: "Backup storage", status: "invalid", marker: "READINESS_CONTROL_INVALID", nextAction: "Add an opaque secret-manager reference for encrypted backup storage." },
  { key: "security-contact", category: "operations", label: "Security contact", status: "missing", marker: "READINESS_CONTROL_MISSING", nextAction: "Add the monitored security contact used by the incident runbook." },
];

describe("production activation cockpit", () => {
  beforeEach(() => { mocked.query = undefined; });

  test("renders a truthful pilot with seven novice-friendly controls", async () => {
    mocked.query = { marker: "PRODUCTION_READINESS_EXPLAINED", evidenceMarker: "READINESS_RESPONSE_REDACTED", phaseMarker: "PRODUCTION_PILOT_READY", status: "pilot", controlPlaneReady: true, controlPlaneMarker: "CONTROL_PLANE_READY", enterpriseReady: false, controls, summary: { ready: 2, total: 7 } };
    const { container } = render(<ProductionActivationPanel workspaceId={"workspace" as never} />);
    expect(screen.getByRole("heading", { name: /know what is live/i })).toBeInTheDocument();
    expect(screen.getByText("Pilot live")).toBeInTheDocument();
    expect(screen.getByText("Live")).toBeInTheDocument();
    expect(screen.getByText("Activation required")).toBeInTheDocument();
    expect(screen.getByText("2 of 7 controls ready")).toBeInTheDocument();
    for (const item of controls) expect(screen.getByText(item.label)).toBeInTheDocument();
    expect(screen.getByText(/no secret values or references are returned/i)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/CLERK_|AGENT_OVEN_|vault:\/\/private/);
    expect(container.querySelector('[data-control-count="7"]')).toBeInTheDocument();
    const accessibility = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(accessibility.violations).toEqual([]);
  });

  test("uses an honest loading state until the server answers", () => {
    render(<ProductionActivationPanel workspaceId={"workspace" as never} />);
    expect(screen.getByRole("heading", { name: /checking production activation/i })).toBeInTheDocument();
    expect(screen.getByText(/trusted server boundary/i)).toBeInTheDocument();
  });
});

import { render, screen } from "@testing-library/react";
import { HostedAppBoundary, isHostedConfigurationValid } from "./HostedAppBoundary";
import { PublicLanding } from "./PublicLanding";

describe("Agent Oven public launch", () => {
  test("renders the product promise without operator setup diagnostics", () => {
    render(<PublicLanding />);
    expect(screen.getByRole("heading", { name: /build the agent.*keep the control/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /build my first agent/i })).toHaveAttribute("href", "/app");
    expect(screen.queryByText(/VITE_CLERK|VITE_CONVEX|\.env\.local/i)).not.toBeInTheDocument();
  });

  test("shows the customer-safe closed state when identity is not active", () => {
    render(<HostedAppBoundary configuration={{ deploymentUrl: "https://standing-dragon-472.convex.cloud", clerkPublishableKey: undefined }} />);
    expect(screen.getByTestId("access-provisioning")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /workspace is being prepared/i })).toBeInTheDocument();
    expect(screen.queryByText(/VITE_|CLERK_FRONTEND_API_URL|PUBLISHABLE_KEY/i)).not.toBeInTheDocument();
  });

  test("rejects local, placeholder, and incomplete browser configuration", () => {
    expect(isHostedConfigurationValid({ deploymentUrl: "http://127.0.0.1:3210", clerkPublishableKey: "pk_test_abcdefghijklmnop" })).toBe(false);
    expect(isHostedConfigurationValid({ deploymentUrl: "https://your-deployment.convex.cloud", clerkPublishableKey: "pk_test_abcdefghijklmnop" })).toBe(false);
    expect(isHostedConfigurationValid({ deploymentUrl: "https://standing-dragon-472.convex.cloud", clerkPublishableKey: "not-a-clerk-key" })).toBe(false);
    expect(isHostedConfigurationValid({ deploymentUrl: "https://standing-dragon-472.convex.cloud", clerkPublishableKey: "pk_live_abcdefghijklmnop" })).toBe(true);
  });
});

import { render, screen } from "@testing-library/react";
import { vi } from "vitest";
import { HostedAppBoundary } from "./HostedAppBoundary";

vi.mock("@clerk/react", () => ({
  ClerkProvider: ({ children, publishableKey }: { children: React.ReactNode; publishableKey: string }) => <div data-testid="clerk-provider" data-key={publishableKey}>{children}</div>,
  useAuth: vi.fn(),
}));

vi.mock("convex/react", () => ({
  ConvexReactClient: class ConvexReactClient {},
}));

vi.mock("convex/react-clerk", () => ({
  ConvexProviderWithClerk: ({ children }: { children: React.ReactNode }) => <div data-testid="convex-clerk-provider">{children}</div>,
}));

vi.mock("./AuthBoundary", () => ({
  AuthBoundary: () => <div data-testid="auth-boundary" />,
}));

describe("hosted Clerk provider wiring", () => {
  test("wraps Convex inside Clerk only after public configuration validates", () => {
    render(<HostedAppBoundary configuration={{ deploymentUrl: "https://standing-dragon-472.convex.cloud", clerkPublishableKey: "pk_live_abcdefghijklmnop" }} />);
    const clerk = screen.getByTestId("clerk-provider");
    const convex = screen.getByTestId("convex-clerk-provider");
    expect(clerk).toHaveAttribute("data-key", "pk_live_abcdefghijklmnop");
    expect(clerk).toContainElement(convex);
    expect(convex).toContainElement(screen.getByTestId("auth-boundary"));
  });
});

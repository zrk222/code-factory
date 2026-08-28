import { render, screen } from "@testing-library/react";
import { vi } from "vitest";
import { SessionAction } from "./AuthBoundary";

vi.mock("@clerk/react", () => ({
  SignInButton: ({ children, mode, oauthFlow, fallbackRedirectUrl }: { children: React.ReactNode; mode: string; oauthFlow: string; fallbackRedirectUrl: string }) => (
    <div data-testid="clerk-sign-in" data-mode={mode} data-oauth-flow={oauthFlow} data-fallback={fallbackRedirectUrl}>{children}</div>
  ),
}));

describe("Clerk sign-in boundary", () => {
  test("offers one secure sign-in action and explains the authorization boundary", () => {
    render(<SessionAction />);
    const integration = screen.getByTestId("clerk-sign-in");
    expect(integration).toHaveAttribute("data-mode", "modal");
    expect(integration).toHaveAttribute("data-oauth-flow", "auto");
    expect(integration).toHaveAttribute("data-fallback", "/app");
    expect(screen.getByRole("button", { name: "Sign in securely" })).toBeInTheDocument();
    expect(screen.getByText(/identity proves who you are/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button")).toHaveLength(1);
  });
});

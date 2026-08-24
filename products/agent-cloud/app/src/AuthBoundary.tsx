import { SignInButton } from "@clerk/react";
import { Authenticated, AuthLoading, Unauthenticated } from "convex/react";
import App from "./App";

export function SessionAction() {
  return (
    <main className="setup-screen" data-testid="signed-out-screen">
      <p className="eyebrow">Identity boundary ready</p>
      <h1>Sign in to Agent Oven.</h1>
      <p>Choose an OAuth or enterprise SSO connection configured in Clerk. Convex validates the Clerk session, then resolves workspace roles again for every operation.</p>
      <SignInButton mode="modal" oauthFlow="auto" fallbackRedirectUrl="/app" signUpFallbackRedirectUrl="/app">
        <button className="button primary">Sign in securely</button>
      </SignInButton>
      <p className="access-note">Identity proves who you are. Agent Oven policy still decides what you may do.</p>
    </main>
  );
}

/** Prevents operational components from mounting until Convex validates the Clerk session. */
export function AuthBoundary() {
  return (
    <>
      <AuthLoading><main className="loading-screen"><p>Validating the Clerk session…</p></main></AuthLoading>
      <Unauthenticated><SessionAction /></Unauthenticated>
      <Authenticated><App /></Authenticated>
    </>
  );
}

import { useAuth0 } from "@auth0/auth0-react";
import { Authenticated, AuthLoading, Unauthenticated } from "convex/react";
import App from "./App";

function SessionAction() {
  const { loginWithRedirect } = useAuth0();
  return (
    <main className="setup-screen" data-testid="signed-out-screen">
      <p className="eyebrow">Identity boundary ready</p>
      <h1>Sign in to Agent Oven.</h1>
      <p>Authentication is handled by your configured OIDC tenant. Workspace roles are resolved again on the server for every operation.</p>
      <button className="button primary" onClick={() => void loginWithRedirect()}>Continue with SSO</button>
    </main>
  );
}

/** Prevents operational components from mounting until Convex validates the OIDC session. */
export function AuthBoundary() {
  return (
    <>
      <AuthLoading><main className="loading-screen"><p>Validating the OIDC session…</p></main></AuthLoading>
      <Unauthenticated><SessionAction /></Unauthenticated>
      <Authenticated><App /></Authenticated>
    </>
  );
}

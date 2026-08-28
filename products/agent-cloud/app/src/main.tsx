import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { PublicLanding } from "./PublicLanding";
import "./index.css";

const root = createRoot(document.getElementById("root")!);
const protectedRoute = window.location.pathname === "/app" || window.location.pathname.startsWith("/app/");

if (protectedRoute) {
  void import("./HostedAppBoundary").then(({ HostedAppBoundary }) => root.render(
    <StrictMode>
      <HostedAppBoundary configuration={{
        deploymentUrl: import.meta.env.VITE_CONVEX_URL,
        clerkPublishableKey: import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
      }} />
    </StrictMode>,
  ));
} else {
  root.render(<StrictMode><PublicLanding /></StrictMode>);
}

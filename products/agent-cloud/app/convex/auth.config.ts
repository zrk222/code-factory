import type { AuthConfig } from "convex/server";

declare const process: { env: Record<string, string | undefined> };

export default {
  providers: [{
    domain: process.env.CLERK_FRONTEND_API_URL!,
    applicationID: "convex",
  }],
} satisfies AuthConfig;

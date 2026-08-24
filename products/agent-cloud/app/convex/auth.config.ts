import type { AuthConfig } from "convex/server";

declare const process: { env: Record<string, string | undefined> };

const domain = process.env.AUTH0_DOMAIN;
const applicationID = process.env.AUTH0_CLIENT_ID;

export default {
  providers: domain && applicationID ? [{ domain, applicationID }] : [],
} satisfies AuthConfig;

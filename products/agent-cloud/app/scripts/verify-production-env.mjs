const required = [
  "VITE_CONVEX_URL",
  "VITE_CLERK_PUBLISHABLE_KEY",
  "CLERK_FRONTEND_API_URL",
  "AGENT_OVEN_APP_URL",
  "AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF",
  "AGENT_OVEN_EMAIL_CONNECTION_REF",
  "AGENT_OVEN_RUNTIME_WORKER_SECRET_REF",
  "AGENT_OVEN_BACKUP_STORAGE_REF",
  "AGENT_OVEN_SECURITY_CONTACT",
];

const missing = required.filter((name) => !process.env[name]?.trim());
const invalid = [];

function requireHttps(name) {
  const value = process.env[name];
  if (!value) return;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") invalid.push(`${name} must use HTTPS`);
    if (url.username || url.password) invalid.push(`${name} must not contain credentials`);
  } catch {
    invalid.push(`${name} must be a valid URL`);
  }
}

requireHttps("VITE_CONVEX_URL");
requireHttps("CLERK_FRONTEND_API_URL");
requireHttps("AGENT_OVEN_APP_URL");

const clerkKey = process.env.VITE_CLERK_PUBLISHABLE_KEY?.trim();
if (clerkKey && !/^pk_(?:test|live)_[A-Za-z0-9_-]{16,}$/.test(clerkKey)) invalid.push("VITE_CLERK_PUBLISHABLE_KEY must be a Clerk publishable key");

const clerkFrontendUrl = process.env.CLERK_FRONTEND_API_URL?.trim();
if (clerkFrontendUrl) {
  try {
    const url = new URL(clerkFrontendUrl);
    if (url.pathname !== "/" || url.search || url.hash) invalid.push("CLERK_FRONTEND_API_URL must not contain a path, query, or fragment");
  } catch {
    // requireHttps already records malformed URLs.
  }
}

for (const name of [
  "AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF",
  "AGENT_OVEN_EMAIL_CONNECTION_REF",
  "AGENT_OVEN_RUNTIME_WORKER_SECRET_REF",
  "AGENT_OVEN_BACKUP_STORAGE_REF",
]) {
  const value = process.env[name];
  if (value && (!/^(?:vault|aws-sm|azure-kv|gcp-sm):\/\/[A-Za-z0-9][A-Za-z0-9._~!$'()*+,;=:@/-]*$/.test(value) || /\s/.test(value) || /[?&](?:token|key|secret|password)=/i.test(value) || /\/\/[^/\s]+:[^/@\s]+@/i.test(value))) {
    invalid.push(`${name} must be an opaque secret-manager reference`);
  }
}

if (process.env.AGENT_OVEN_SECURITY_CONTACT && !/^\S+@\S+\.\S+$/.test(process.env.AGENT_OVEN_SECURITY_CONTACT)) {
  invalid.push("AGENT_OVEN_SECURITY_CONTACT must be an email address");
}

if (missing.length || invalid.length) {
  console.error("PRODUCTION_ENV_INVALID");
  if (missing.length) console.error(`Missing variables: ${missing.join(", ")}`);
  for (const finding of invalid) console.error(finding);
  process.exit(1);
}

console.log(`PRODUCTION_ENV_VERIFIED ${required.length} required names present; Clerk identity boundary valid; no values printed`);

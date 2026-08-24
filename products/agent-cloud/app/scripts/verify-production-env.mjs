const required = [
  "VITE_CONVEX_URL",
  "VITE_AUTH0_DOMAIN",
  "VITE_AUTH0_CLIENT_ID",
  "AUTH0_DOMAIN",
  "AUTH0_CLIENT_ID",
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
requireHttps("AGENT_OVEN_APP_URL");

function requireHostname(name) {
  const value = process.env[name]?.trim();
  if (!value) return;
  if (value.length > 253 || value.includes("://") || value.includes("/") || value.includes("@") || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)) {
    invalid.push(`${name} must be a hostname without scheme or path`);
  }
}

function requireClientIdentifier(name) {
  const value = process.env[name]?.trim();
  if (!value) return;
  if (value.length < 8 || value.length > 160 || !/^[A-Za-z0-9_-]+$/.test(value)) invalid.push(`${name} must be a valid client identifier`);
}

requireHostname("VITE_AUTH0_DOMAIN");
requireHostname("AUTH0_DOMAIN");
requireClientIdentifier("VITE_AUTH0_CLIENT_ID");
requireClientIdentifier("AUTH0_CLIENT_ID");

if (process.env.VITE_AUTH0_DOMAIN && process.env.AUTH0_DOMAIN && process.env.VITE_AUTH0_DOMAIN.trim() !== process.env.AUTH0_DOMAIN.trim()) invalid.push("Browser and server identity domains must match");
if (process.env.VITE_AUTH0_CLIENT_ID && process.env.AUTH0_CLIENT_ID && process.env.VITE_AUTH0_CLIENT_ID.trim() !== process.env.AUTH0_CLIENT_ID.trim()) invalid.push("Browser and server identity client identifiers must match");

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

console.log(`PRODUCTION_ENV_VERIFIED ${required.length} required names present; identity values match; no values printed`);

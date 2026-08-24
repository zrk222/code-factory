export type ProductionReadinessStatus = "blocked" | "pilot" | "ready";
export type ProductionControlStatus = "missing" | "invalid" | "ready";
export type ProductionControlCategory = "foundation" | "operations";

export type ProductionReadinessEnvironment = {
  CLERK_FRONTEND_API_URL?: string;
  AGENT_OVEN_APP_URL?: string;
  AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF?: string;
  AGENT_OVEN_EMAIL_CONNECTION_REF?: string;
  AGENT_OVEN_RUNTIME_WORKER_SECRET_REF?: string;
  AGENT_OVEN_BACKUP_STORAGE_REF?: string;
  AGENT_OVEN_SECURITY_CONTACT?: string;
};

export type ProductionReadinessControl = {
  key: "identity" | "app-endpoint" | "billing-webhook" | "transactional-email" | "runtime-worker" | "backup-storage" | "security-contact";
  category: ProductionControlCategory;
  label: string;
  status: ProductionControlStatus;
  marker: "READINESS_CONTROL_MISSING" | "READINESS_CONTROL_INVALID" | "READINESS_CONTROL_READY";
  nextAction: string | null;
};

export type ProductionReadiness = {
  marker: "PRODUCTION_READINESS_EXPLAINED";
  evidenceMarker: "READINESS_RESPONSE_REDACTED";
  phaseMarker: "PRODUCTION_ACTIVATION_BLOCKED" | "PRODUCTION_PILOT_READY" | "ENTERPRISE_OPERATIONS_READY";
  status: ProductionReadinessStatus;
  controlPlaneReady: boolean;
  controlPlaneMarker: "CONTROL_PLANE_READY" | "CONTROL_PLANE_BLOCKED";
  enterpriseReady: boolean;
  controls: ProductionReadinessControl[];
  summary: { ready: number; total: 7 };
};

type Validation = "missing" | "invalid" | "ready";
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function configured(value: string | undefined) {
  return value?.trim() ?? "";
}

function validateClerkFrontendUrl(value: string | undefined): Validation {
  const candidate = configured(value);
  if (!candidate) return "missing";
  try {
    const url = new URL(candidate);
    return url.protocol === "https:" && !url.username && !url.password && HOSTNAME_PATTERN.test(url.hostname) && url.pathname === "/" && !url.search && !url.hash ? "ready" : "invalid";
  } catch {
    return "invalid";
  }
}

function validateHttpsUrl(value: string | undefined): Validation {
  const candidate = configured(value);
  if (!candidate) return "missing";
  try {
    const url = new URL(candidate);
    return url.protocol === "https:" && !url.username && !url.password && Boolean(url.hostname) ? "ready" : "invalid";
  } catch {
    return "invalid";
  }
}

function validateSecretReference(value: string | undefined): Validation {
  const candidate = configured(value);
  if (!candidate) return "missing";
  if (/\s/.test(candidate) || /[?&](?:token|key|secret|password)=/i.test(candidate) || /\/\/[^/\s]+:[^/@\s]+@/i.test(candidate)) return "invalid";
  return /^(?:vault|aws-sm|azure-kv|gcp-sm):\/\/[A-Za-z0-9][A-Za-z0-9._~!$'()*+,;=:@/-]*$/.test(candidate) ? "ready" : "invalid";
}

function validateEmail(value: string | undefined): Validation {
  const candidate = configured(value);
  if (!candidate) return "missing";
  return candidate.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate) ? "ready" : "invalid";
}

function control(
  key: ProductionReadinessControl["key"],
  category: ProductionControlCategory,
  label: string,
  status: Validation,
  nextAction: string,
): ProductionReadinessControl {
  return {
    key,
    category,
    label,
    status,
    marker: status === "ready" ? "READINESS_CONTROL_READY" : status === "missing" ? "READINESS_CONTROL_MISSING" : "READINESS_CONTROL_INVALID",
    nextAction: status === "ready" ? null : nextAction,
  };
}

/** Classifies production activation from server configuration without returning configured names, references, or values. */
export function evaluateProductionReadiness(environment: ProductionReadinessEnvironment): ProductionReadiness {
  const controls: ProductionReadinessControl[] = [
    control("identity", "foundation", "Identity trust", validateClerkFrontendUrl(environment.CLERK_FRONTEND_API_URL), "Activate Clerk's Convex integration and set its Frontend API URL in the Convex deployment."),
    control("app-endpoint", "foundation", "Application endpoint", validateHttpsUrl(environment.AGENT_OVEN_APP_URL), "Publish the application at its final HTTPS address."),
    control("billing-webhook", "operations", "Billing webhook", validateSecretReference(environment.AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF), "Add an opaque secret-manager reference for signed billing events."),
    control("transactional-email", "operations", "Transactional email", validateSecretReference(environment.AGENT_OVEN_EMAIL_CONNECTION_REF), "Add an opaque secret-manager reference for the email service."),
    control("runtime-worker", "operations", "Runtime worker", validateSecretReference(environment.AGENT_OVEN_RUNTIME_WORKER_SECRET_REF), "Add an opaque secret-manager reference for the isolated runtime worker."),
    control("backup-storage", "operations", "Backup storage", validateSecretReference(environment.AGENT_OVEN_BACKUP_STORAGE_REF), "Add an opaque secret-manager reference for encrypted backup storage."),
    control("security-contact", "operations", "Security contact", validateEmail(environment.AGENT_OVEN_SECURITY_CONTACT), "Add the monitored security contact used by the incident runbook."),
  ];
  const controlPlaneReady = controls.filter((item) => item.category === "foundation").every((item) => item.status === "ready");
  const enterpriseReady = controls.every((item) => item.status === "ready");
  const status: ProductionReadinessStatus = enterpriseReady ? "ready" : controlPlaneReady ? "pilot" : "blocked";
  return {
    marker: "PRODUCTION_READINESS_EXPLAINED",
    evidenceMarker: "READINESS_RESPONSE_REDACTED",
    phaseMarker: enterpriseReady ? "ENTERPRISE_OPERATIONS_READY" : controlPlaneReady ? "PRODUCTION_PILOT_READY" : "PRODUCTION_ACTIVATION_BLOCKED",
    status,
    controlPlaneReady,
    controlPlaneMarker: controlPlaneReady ? "CONTROL_PLANE_READY" : "CONTROL_PLANE_BLOCKED",
    enterpriseReady,
    controls,
    summary: { ready: controls.filter((item) => item.status === "ready").length, total: 7 },
  };
}

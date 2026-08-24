# Spec: agent-oven-public-launch-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Publish Agent Oven as a real SaaS surface: a public, novice-friendly landing page at `/`, a protected application boundary at `/app`, one hosted Convex project shared by all customers, and strict workspace-derived authorization for every tenant resource.

### User roles
- Visitor: can understand the product and request authenticated access without seeing operator diagnostics.
- Workspace member: can access only workspaces derived from the verified OIDC subject.
- Workspace owner: can bootstrap and administer the first workspace after authentication.
- Operator: can inspect setup state through deployment tooling, never through the public home page.

### Requirements (EARS)
- While `PUBLIC_HOME_REQUESTED` means pathname `/` is requested, the browser shall return a complete Agent Oven marketing and onboarding page without initializing Auth0 or Convex.
- When `PRIMARY_CTA_SELECTED` occurs, the browser shall return pathname `/app` without returning environment-variable names or internal setup commands.
- When `HOSTED_BROWSER_CONFIGURATION_VALID` means all three browser configuration values are valid, `/app` shall return the Auth0 and Convex provider boundary before any operational component.
- If `HOSTED_IDENTITY_CONFIGURATION_INVALID` means hosted identity configuration is absent, placeholder, or invalid, `/app` shall return a customer-safe access-provisioning state without constructing an operational Convex client.
- While `HOSTED_CONVEX_CONTROL_PLANE` is active, the server shall return workspace resources only from memberships derived from the verified token identifier.
- When `SPA_ROUTE_REQUESTED` targets `/`, `/app`, or `/app?view=builder`, Netlify shall return the application shell with HTTP status `200`.
- When `PRODUCTION_PROMOTION_RUNS` completes, Netlify shall return the verified build at `https://agent-oven.netlify.app`.
- While `CUSTOMER_IDENTITY_PAGE_RENDERED` is active, Auth0 shall return the Agent Oven friendly name, Agent Oven logo, orange primary action, and dark background without presenting the tenant slug as the product name.
- While `PUBLIC_HOME_RENDERED` is evaluated at 390 CSS pixels, the page shall return exactly one primary CTA, at least 44 CSS pixel CTA height, visible keyboard focus, accurate product boundaries, and zero fabricated customer, revenue, or certification claims.
- If `FOREIGN_WORKSPACE_RESOURCE_REQUESTED` occurs, the Convex server shall reject the request before returning resource data.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Public launch works before identity activation
  Given HOSTED_IDENTITY_CONFIGURATION_INVALID
  When PUBLIC_HOME_REQUESTED occurs
  Then PUBLIC_HOME_RENDERED is returned without an environment variable name

Scenario: Protected application fails closed
  Given HOSTED_IDENTITY_CONFIGURATION_INVALID
  When SPA_ROUTE_REQUESTED targets /app
  Then a customer-safe access provisioning state is returned without an operational dashboard

Scenario: Primary action enters the protected application
  Given PUBLIC_HOME_RENDERED is returned
  When PRIMARY_CTA_SELECTED occurs
  Then pathname /app is returned without an environment variable name

Scenario: Hosted tenant boundary remains enforced
  Given HOSTED_CONVEX_CONTROL_PLANE is active
  When FOREIGN_WORKSPACE_RESOURCE_REQUESTED occurs
  Then the Convex server rejects the request before returning resource data

Scenario: Production routes resolve
  Given PRODUCTION_PROMOTION_RUNS completes
  When SPA_ROUTE_REQUESTED targets / and /app
  Then Netlify returns HTTP status 200 for both routes

Scenario: Hosted identity is customer branded
  Given CUSTOMER_IDENTITY_PAGE_RENDERED is active
  When the visitor opens login or sign-up
  Then the page returns the Agent Oven name and logo without presenting the tenant slug as the product name
```

## SHOULD - Technical/structural
- ADR references: adr/agent-cloud-convex-v1.md, adr/agent-cloud-identity-isolation-v1.md
- Data model: Convex organizations, organizationMemberships, workspaces, and workspaceMemberships; no new table is required.
- API contract: `access.myWorkspaces`, `access.readAgentSpec`, and `seed.ensureDemo` remain the authenticated tenant-entry boundary.

## SHOULD NOT - Implementation details
- The public route shall not display environment variable names, shell commands, localhost addresses, deployment identifiers, or stack traces.
- The browser shall not receive Auth0 client secrets, Convex deploy keys, provider keys, or connector credentials.
- A placeholder OIDC issuer shall not be represented as production identity activation.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `PUBLIC_HOME_REQUESTED` | return the public landing page without initializing the authenticated control plane |
| 2 | `HOSTED_BROWSER_CONFIGURATION_VALID` | return the authenticated Auth0 and Convex boundary |
| 3 | `HOSTED_IDENTITY_CONFIGURATION_INVALID` | return a customer-safe closed access state |
| 4 | `FOREIGN_WORKSPACE_RESOURCE_REQUESTED` | reject before returning resource data |
| 5 | `PRODUCTION_PROMOTION_RUNS` | return the verified build at the production alias |
| 6 | `CUSTOMER_IDENTITY_PAGE_RENDERED` | return the Agent Oven branded identity surface |

# SaaS Reality: Promise-to-Permission Proof

OAuth login is not authorization, and a successful checkout is not proof that
the right tenant received the right feature. Code Factory now joins those facts
with one provider-neutral, deterministic receipt.

```bash
factory saas verify --root . --contract saas-contract.json \
  --evidence observed-events.json --out .factory/saas-proof/latest.json --json
factory saas status --root . --json
```

The contract accepts standards-oriented `oidc` or `oauth2` providers. The
provider label is descriptive: Clerk, Auth0, Okta, Microsoft Entra ID, Amazon
Cognito, Supabase, Firebase, or another compliant provider follows the same
schema. Authorization-code clients must declare PKCE. The evidence remains
local and must contain normalized observations—not tokens, cookies, secrets,
authorization headers, or code verifiers.

The verifier checks:

- issuer, audience, active-token, and PKCE posture;
- application and non-empty build identity;
- same-subject, same-tenant, role, SKU, and entitlement binding across the
  complete journey;
- strict event order and unique local/provider event identifiers;
- verified checkout and webhook observations before access;
- pricing-promise SKU and entitlement consistency;
- cancellation, refund, or expiry followed by entitlement revocation; and
- unknown evidence as blocked, never green.

This command does not contact an identity or billing provider, settle a
payment, change an entitlement, deploy code, certify production behavior, or
provide legal compliance. Graph Ops, MCP, WebMCP, and FactoryLine for JetBrains
expose only hash-verified local receipt status.

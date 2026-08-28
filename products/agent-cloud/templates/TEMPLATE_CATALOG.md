# Post-v1 agent template research catalog

Only `b2b-pr-assurance` is committed for v1. Every other entry is an uncommitted discovery hypothesis and receives no production implementation until PR Assurance passes the commercial, safety, retention, and operating gates in the PRD.

## Template contract

Every publishable template must declare:

- target motion: B2B, B2C, or C2C;
- outcome and intended operator;
- setup questions and required connectors;
- allowed data classes and retention;
- memory mode and Trust policy;
- tool actions, side effects, idempotency, and reversibility;
- model-routing profile and hard budget defaults;
- deterministic, rubric, adversarial, privacy, and cost validators;
- minimum SaaS tier and optional metered resources;
- owner, version, maintenance status, and expiry/review date.

## Streamlined setup

All templates use the same eight-step composer: Job → Knowledge → Memory → Tools → Model → Trust → Budget → Test. A template preselects safe ingredients; the user only answers questions that change behavior or authority.

## Research portfolio

| ID | Motion | Template | Tier | Memory | Maximum authority | Core validator |
|---|---|---|---|---|---|---|
| `b2b-pr-assurance` | B2B | PR Assurance | V1 launch product | run-only or architecture history | propose merge; approval required | repository gates + evidence verification |
| `b2b-compliance-evidence` | B2B | Compliance Evidence | Business | governed organizational | collect and write packet | source coverage + policy checks |
| `b2b-customer-service` | B2B | Customer Service | Team; Business for premium | customer-scoped | draft; approval to send | policy/rubric + exact-recipient approval |
| `b2b-account-research` | B2B | Account Research | Team | account-scoped | suggest CRM changes | citation and freshness checks |
| `b2b-vendor-risk` | B2B | Vendor Risk | Business | review history | propose risk decision | required-control coverage |
| `b2b-it-service-desk` | B2B | IT Service Desk | Business | user/device scoped | bounded approved remediation | identity, policy, and postcondition checks |
| `b2c-learning-coach` | B2C | Learning Coach | Builder | user-controlled personal | content and reminders | curriculum/rubric + deletion checks |
| `b2c-purchase-research` | B2C | Purchase Research | Builder | preferences optional | read and draft | citation, price-date, disclosure checks |
| `b2c-travel-planner` | B2C | Travel Planner | Builder; premium to book | personal constraints | proposal; approval for booking | constraints + exact-action approval |
| `b2c-family-admin` | B2C | Family Admin | Team / premium | household/subject scoped | approval-gated calendar/doc actions | identity, consent, and conflict checks |
| `c2c-marketplace-listing` | C2C | Marketplace Listing | Builder | seller preferences optional | approval-gated publish/message | platform rules + preview match |
| `c2c-community-moderator` | C2C | Community Moderator | Team / premium | precedent history | propose; bounded action by policy | policy consistency + appeal receipt |
| `c2c-peer-exchange` | C2C | Peer Exchange Coordinator | Team / premium | consent-scoped multi-party | introductions and status updates | consent, scope, and disclosure checks |

## Premium classification

A future template requires the complete governance control set when it uses durable organizational/multi-party memory or consequential delegated authority. Such templates always enable both `factory-memory-core` and `factory-trust-core`; one cannot be purchased or disabled independently for that workflow.

All tiers retain tenant isolation, secret protection, budget enforcement, runtime authorization, and approval for consequential actions. Higher tiers charge for governance depth, retention, private deployment, identity administration, evidence history, and contracted operations—not for foundational safety.

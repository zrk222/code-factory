# Support SLA policy

Code Factory remains free and open source. Repository access, GitHub Issues, and
community discussion do **not** carry a guaranteed response time.

This document defines the support contract that may be offered with a future
paid enterprise service. It is a release and procurement boundary, not evidence
that staffed support or a live SLA exists today.

## Tiers

| Tier | Channel | Commitment |
| --- | --- | --- |
| Community | Public GitHub issue | Best effort; no response-time guarantee |
| Pilot | Named customer channel after acceptance | P1 acknowledgement within 30 minutes and updates every 60 minutes during an active incident; P2 within 4 business hours; P3 within 2 business days |
| Enterprise | Signed order form and monitored escalation channel | The Pilot targets plus the contracted availability, recovery, coverage hours, and service credits in the order form |

The Pilot targets are proposed operating objectives until the service has a
named support owner, monitored escalation, production telemetry, dependency
mapping, and a completed restore drill. Only a signed order form can make them
contractual.

## Severity routing

- **P1:** material outage, data-integrity risk, or security incident affecting a
  production customer. Containment and customer updates follow the incident
  runbook; the response team does not make unapproved production changes.
- **P2:** degraded or blocked supported workflow without a material integrity or
  security risk.
- **P3:** question, documentation gap, cosmetic defect, or planned improvement.

Customer-controlled model inference, credentials, quotas, connectors, networks,
and third-party provider incidents are tracked separately from platform
availability. They can change the observed outcome without being a platform
SLA breach.

## Activation gate

Before publishing or selling an SLA, the owner must attach evidence for:

1. named support and incident owners;
2. monitored escalation channel and coverage hours;
3. production availability and latency telemetry;
4. provider/dependency failure mapping;
5. tested backup and restore evidence with RTO/RPO;
6. approved security, privacy, legal, pricing, and service-credit terms; and
7. a signed customer order or equivalent acceptance record.

The machine-readable policy is [SUPPORT_SLA_POLICY.json](SUPPORT_SLA_POLICY.json).
It deliberately reports `proposed` until these gates are evidenced.

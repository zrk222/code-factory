# Service levels and objectives

## Proposed enterprise objectives

- Control-plane availability: 99.9% monthly, excluding announced maintenance.
- Hosted execution admission p95: under 1 second, measured at the public API boundary.
- Queue-start p95: under 5 minutes when customer inference and connectors are healthy.
- Priority-one acknowledgement: 30 minutes; update cadence: 60 minutes.
- Default recovery targets: RTO 60 minutes and RPO 15 minutes, overridden only by a signed order and enforced workspace policy.

These are release targets, not a current contractual SLA. GA requires production telemetry, at least one measured restore drill, staffed escalation, provider dependency mapping, and a signed order form. Customer-controlled inference keys, quotas, and third-party provider incidents are measured separately from platform availability.

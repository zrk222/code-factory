# Disaster recovery plan

Backups must be encrypted with the configured customer-managed key reference and stored in a region distinct from the primary residency failure domain. Snapshot manifests contain schema version, record count, and digest. Credentials never appear in object references.

Quarterly restore drills target an isolated `ephemeral-*` or `staging-*` environment. Passing requires row-count equality, receipt-chain verification, tenant-isolation verification, and measured RTO/RPO. A failed invariant fails the drill; it cannot be waived by the worker.

During recovery, pause runtime claims, preserve all ledgers and receipts, restore the control plane, validate organization/workspace boundaries, reconcile reservations, rotate affected credentials, then resume agents individually through the incident recovery gate.

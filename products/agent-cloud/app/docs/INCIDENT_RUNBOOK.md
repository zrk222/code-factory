# Incident runbook

## Declare and contain

1. Open an incident record with severity, affected workspaces, reporter, and timestamps.
2. Suspend affected agents and stop new runtime claims. Revoke compromised inference bindings or connector references at their source.
3. Preserve audit events, receipts, credit transactions, execution attempts, and provider logs. Do not rewrite evidence.
4. Cancel queued work and cooperatively stop running leases. Release unused credit reservations only through the ledger API.

## Investigate and recover

Use receipt IDs and idempotency keys to correlate control-plane and provider activity. Restore only into an isolated target until row counts, receipt-chain integrity, and tenant isolation pass. Recovery requires named operator approval and the existing five-check recovery gate.

## Communicate

Security contact, incident commander, legal/privacy owner, support owner, and customer-update cadence must be assigned before launch. Record decisions and timestamps in the incident ledger.

## Exit criteria

Root cause recorded; exposed credentials rotated; affected agents requalified; reservations reconciled; restore drill passed when data integrity was at risk; customer obligations completed; corrective constraints promoted into tests or policy.

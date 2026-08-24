# Release checklist

- [ ] Product version and migration notes approved.
- [ ] `npm run verify:release` passes from a clean checkout.
- [ ] `npm audit --audit-level=high` has no unresolved high/critical finding.
- [ ] Production environment-name validation passes without logging values.
- [ ] Settings shows `Control plane · Live`; `Enterprise operations · Ready` is claimed only after all seven sanitized controls pass.
- [ ] Legal entity, privacy notice, terms, security contact, and security.txt approved.
- [ ] CSP allowlist contains only exact production hosts.
- [ ] Auth0 callback/logout/origin settings verified in the production tenant.
- [ ] Billing webhook signature rejection and replay behavior exercised.
- [ ] BYOK secret references resolve only inside the runtime boundary.
- [ ] Runtime worker proves idempotent claim, heartbeat, cancellation, retry, settlement, and receipt.
- [ ] Backup object exists outside the primary failure domain; restore drill passes in an isolated target.
- [ ] Keyboard-only navigation, visible focus, zoom to 200%, and reduced-motion behavior checked.
- [ ] Owner, operator, reviewer, and revoked-member authorization tests pass.
- [ ] Rollback owner, incident commander, release owner, and customer communication owner named.
- [ ] External activation receipts prove billing delivery, outbound email, worker health, backup write, and isolated restore; configuration readiness alone is not used as runtime proof.

# Hosted adapter container

Build from the repository root:

```bash
docker build -f deploy/hosted/Dockerfile -t code-factory-hosted:0.20.0 .
```

Inject every required variable through a managed secret store. Do not commit
database credentials, webhook secrets, OIDC tokens, or the GitHub App key.
See `docs/HOSTED_PR_ASSURANCE.md` for the complete configuration contract.
See `docs/HOSTED_CONTROL_PLANE.md` for the supervised tenant onboarding order,
dynamic identity boundary, one-time GitHub installation binding, and read-only
operator console.

The web process serves authenticated ingress. Run outbox dispatch from a
separate supervised worker by constructing `HostedPRAssuranceService` with the
same configuration and invoking `dispatch(tenant_id)` on a schedule. The
adapter intentionally does not create a schedule or obtain infrastructure
credentials by itself.

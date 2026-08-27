# Enterprise Operations Golden Path

`factory ops` is the local-first operating layer for teams running AI coding
agents. It connects seven previously separate concerns without turning a local
receipt into an unsupported hosted-service claim:

1. **Evidence workspace** — tenant-bound SQLite records, content hashes,
   retention dates, an append-only audit chain, and metadata-only export.
2. **Identity lifecycle** — provision, suspend, and revoke local subjects with
   role checks and an audit event before any write. This is a local directory,
   not SSO or SCIM enrollment.
3. **Proof execution** — Docker is an explicit read-only, no-network,
   CPU/memory/pid-bounded backend. A process runner requires an explicit
   `--allow-process-boundary` and is labelled `not-isolated`; it never silently
   downgrades from Docker.
4. **SDLC checks** — changed paths are matched to verified proof receipts and
   reported as `READY_FOR_HUMAN_REVIEW` or `REVIEW_REQUIRED`. The check has no
   merge, deployment, or release authority.
5. **Outcome telemetry** — allowlisted deployment, incident, and rollback
   events are hash-linked and can be summarized or exported in an OTLP-shaped
   metadata envelope. The output is an observation, not a DORA benchmark.
6. **SLA readiness** — seven activation gates are evaluated independently. The
   result remains `PROPOSED` until explicit evidence and a signed acceptance
   digest are supplied; readiness never activates a contract.
7. **Golden path** — one compact status view reports evidence integrity,
   identity counts, runner posture, check state, outcomes, SLA state, and the
   next safe command.

## Quick start

```powershell
factory ops init --root . --tenant acme --owner owner@example.com
factory ops identity operator@example.com --root . --tenant acme --role operator --actor owner@example.com
factory ops evidence evidence.json --root . --tenant acme --subject operator@example.com
factory ops checks --root . --changed src/api.py --proof .factory/receipts/api-proof.json
factory ops status --root .
```

Run a proof with explicit posture. Docker is preferred and fails closed when
unavailable:

```powershell
factory ops run --root . --backend docker --command-json '["python","-m","pytest","-q"]'
```

For a deliberately local-only process check, make the boundary visible:

```powershell
factory ops run --root . --backend process --allow-process-boundary --command-json '["python","-m","pytest","-q"]'
```

Record outcomes and export them only after the ledger verifies:

```powershell
factory ops outcome --root . --tenant acme --subject owner@example.com --service api --environment prod --result deployed --duration-ms 420 --deployed
factory ops summary --root .
factory ops otel --root . --out .factory/ops/outcomes-otel.json
```

## Enterprise boundary

The bundle is a deployable local reference, not a managed control plane. It
does not provide SAML/OIDC enrollment, SCIM synchronization, customer-managed
KMS, HA/DR, remote private runners, billing, merge/deploy authority, or a
contractual support SLA. Those require a separately operated service with
provider, legal, security, staffing, and restore evidence. See
[`ENTERPRISE_1_0.md`](ENTERPRISE_1_0.md), [`SUPPORT_SLA.md`](SUPPORT_SLA.md),
and [`COMMERCIAL_PACKAGING.md`](COMMERCIAL_PACKAGING.md) for the exact
promotion boundary.

Every JSON result includes an authority section. A green local result means
the declared evidence and local checks passed; a human or an independently
authorized CI/SCM integration must still decide whether to merge, deploy, or
release.

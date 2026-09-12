# Runtime attestation and isolation boundary

The six runtime-assurance lanes answer whether signed application evidence
survived stateful, tenant, recovery, compatibility, migration, and performance
checks. They do not, by themselves, prove how the runner was isolated. The
runtime-boundary slice makes that distinction visible in Mission Control and in
the composite receipt.

## What is observed

`factoryline.runtime_attestation` records only bounded launcher facts: shell is
disabled, stdin is closed, output is hashed, the environment follows the
minimal allowlist, the interpreter executable is content-addressed, cleanup is
confirmed, and optional memory/latency observations are typed integers. The
local runner is returned as `SUPERVISED_ONLY`; this is process hygiene, not a
kernel, container, network, credential, or descendant-isolation guarantee.

## What is independently verifiable

An approved external collector can produce a DSSE-signed
`factory.runtime-boundary-attestation.v1` payload. It must bind the candidate,
plan, environment, executable, nonce, freshness window, and self-hash. A
requested `isolated_worker` or `hardened_vm` mode is accepted only when the
matching backend is present, `state=VERIFIED`, `proof=true`, and the collector
is not the local supervisor. Use:

```powershell
factory senior boundary boundary.json `
  --trust-root trust-root.json `
  --candidate-sha256 <candidate> `
  --plan-sha256 <plan> `
  --environment-sha256 <environment>
```

The command verifies the signed observation offline. It does not run a command,
contact a provider, read credentials, or grant release authority.

For Mission Control/Graph Ops visibility, save the returned verification object
or a locally captured attestation under `.factory/senior/`. The read-only senior
projection recognizes both schemas, recomputes `attestation_sha256` or
`verification_sha256`, and marks tampered or missing seals as review-required;
it never treats a supervised observation as independent proof.

## Six-lane join

A signed runtime-audit plan may include:

```json
"runtime_boundary": {
  "requested_isolation": "supervised_subprocess",
  "attestation_required": true
}
```

The normal local run then includes a `runtime_boundary` decision in the receipt.
Supervised-only evidence can accompany a supervised request and remains visible
as `SUPERVISED_ONLY`. If an independent mode is requested but only local
supervision is supplied, the six-lane decision is `BLOCKED` with
`E_ISOLATION_UNPROVEN`. Missing, stale, mismatched, forged, or shell-enabled
observations fail closed with a stable finding.

This boundary complements, rather than replaces, the existing signed execution
attestation. Teams that operate a hardened worker or VM must supply its own
collector, signing policy, host enforcement, and evidence; Code Factory reports
what was proven and what remains unknown.

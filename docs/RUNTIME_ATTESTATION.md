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

## Native assertion propagation probe

For a callback assertion that static analysis cannot resolve, explicitly run
one exact pytest case and challenge its assertion:

```powershell
python -m factoryline.pytest_readiness --root . `
  --nodeid 'tests/test_example.py::test_behavior' --line 18 --timeout 30
```

This executes project code locally twice in separate Python processes. First,
the baseline must pass and reach the selected assertion. The challenge then
raises a unique assertion exception at that exact source function and line.
`OBSERVED` requires that same exception to escape into the selected test's
failed call phase, with clean setup and teardown. Async callbacks and newly
created threads are traced. Skips, xfails, unreachable assertions, swallowed
failures, timeouts, missing runner results and Python source drift remain
`INCOMPLETE`. Supply an exact parametrized node ID when applicable.

The JSON records source binding, exact test identity, baseline and challenge
outcomes, hit counts and hashes of captured runner output. Raw output and local
absolute paths are omitted. The CLI exits 0 for `OBSERVED`, otherwise 2.

This establishes assertion reachability and failure propagation, **not semantic
strength**: even `assert True` can fail when forcibly challenged. It does not
automatically clear scanner findings, replace implementation mutation testing,
sign an independent evaluation, or authorize a release. Review the assertion's
meaning separately. This is supervised local execution, not an isolation boundary;
run only trusted project tests you authorize to execute. Project code shares
the observer's interpreter and can tamper with it; the report explicitly records
`observer_integrity: IN_PROCESS_NOT_ATTESTED`. It is not hostile-code evidence.
Runner output is bounded to 8 MiB per stream, observation JSON to 1 MiB, the
selected source to 4 MiB, and the Python source binding to 4,096 files / 128 MiB.

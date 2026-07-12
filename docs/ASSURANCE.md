# Assurance Plane Foundation

The assurance surface turns receipt data into deterministic release evidence:

```powershell
factory assurance graph evidence.json --tenant acme --out graph.json
factory assurance sbom components.json --out sbom.json
factory assurance vex vulnerabilities.json --out vex.json
factory assurance policy-mutate factory.policy.json
```

`graph` rejects cross-tenant records, missing parents, duplicate ids, and
cycles. `sbom` sorts components and emits a digest. `vex` accepts only the
explicit statuses `not_affected`, `affected`, `fixed`, and
`under_investigation`. `policy-mutate` deletes and inverts each explicit rule
so a caller can run its policy evaluator and reject `HOLLOW_POLICY`.

The constrained runner is available to Python callers as
`factoryline.assurance.run_constrained`. It disables shell interpretation,
contains the working directory, and allow-lists environment variables. It
reports `process-boundary` and `network: not-enforced-by-stdlib-runner`; it is
not a kernel/container sandbox and must not execute untrusted code in
production without a stronger runner.

Private challenge manifests disclose only a name, tenant, count, and digest.
The challenge payload remains caller-owned. Encryption, remote access control,
and zk privacy proofs are separate privacy-plane work.


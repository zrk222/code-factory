# Release candidate preflight

`factory release preflight` is a read-only, fail-closed identity gate for a
release candidate. It binds a workspace-contained release contract to the
current source version and Git commit, checks every supplied package filename
against the source-declared platform version, and optionally audits active
Codex metadata before any external upload step.

The receipt uses schema `factory.release-candidate-preflight.v1` and emits
`RELEASE_CANDIDATE_PREFLIGHT_PASS` only when contract, source, artifact, and
requested metadata checks pass. Authority flags are always false: the command
does not sign, publish, deploy, merge, access credentials, or contact a
provider.

CI must pass `--contract`, both core/editor artifact directories, and
`--metadata-path context/PROGRESS.md`; the protected publish job must verify the
receipt marker before uploading. A stale, missing, unreadable, mixed-version, or
metadata-invalid candidate remains blocked for human remediation.

# Plan: codex-metadata-integrity-v1
Spec: specs/codex-metadata-integrity-v1.md
Architect verdict: PASS

## Logical decomposition

1. Build a bounded, deterministic scanner for local Codex metadata with
   complete parsing, file hashes, claim-boundary findings, and no authority.
2. Expose the scanner through `factory ops metadata` with atomic read-back.
3. Add adversarial tests and a non-hollow smoke manifest for the bypass classes
   found in local Codex history: stale workspace, unbound success, contradictory
   provider state, orphan active state, self-attested or weak gates, missing
   negative proof, unbound or unclear intent, malformed metadata, and missing
   tools.
4. Document the operating boundary, run the audit against the repository's
   available metadata, then run focused and full regression gates.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/codex_metadata.py | verify=`python -m pytest -q tests/test_codex_metadata.py` | Implement hashing, complete parsing, deterministic findings, and authority boundary.
- [ ] T2 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_codex_metadata.py tests/test_policy_compiler.py` | Expose `factory ops metadata` with fail-closed exit codes.
- [ ] T3 | slice=tests | files=tests/test_codex_metadata.py | verify=`python -m pytest -q tests/test_codex_metadata.py` | Prove the hostile bypass cases and CLI read-back.
- [ ] T4 | slice=docs | files=docs/ENTERPRISE_OPERATIONS.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document scope, findings, and evidence boundary.

# Native E2E Proof Gate

Code Factory's E2E Proof Gate answers a narrower and more useful question than
"did a browser test turn green?": **can this declared check actually say no?**

It is a local, vendor-independent proof-by-sabotage gate. You supply an
approved JSON manifest with two explicit argument vectors:

- a positive command that must exit `0`; and
- a negative mutation command that must exit non-zero.

If the negative command succeeds, Code Factory records `HOLLOW_E2E_TEST` and
returns a non-zero exit code. No browser grid, hosted testing vendor, external
API, account, credential, or source-code repair is involved.

## Start with an approved manifest

Create a workspace-local manifest such as `proofs/login-e2e.json`:

```json
{
  "schema": "factory.e2e_proof_manifest.v1",
  "id": "login-e2e",
  "approval": { "state": "approved", "approved_by": "qa-owner" },
  "working_directory": ".",
  "timeout_seconds": 120,
  "network_egress": "not_granted",
  "positive": { "argv": ["python", "-m", "pytest", "tests/e2e/test_login.py"] },
  "negative": { "argv": ["python", "-m", "pytest", "tests/e2e/test_login_rejects_invalid.py"] },
  "artifact_paths": ["artifacts/login-e2e.xml"]
}
```

The human name and `approval.state: "approved"` are required before either
command can execute. Argument vectors are executed with `shell=False`; shell
strings are intentionally not accepted.

## Verify

```powershell
factory e2e verify --root . --manifest proofs/login-e2e.json --out-dir .factory/e2e/login-e2e --json
```

The command returns:

- `0` only when the positive command passes, the negative command fails, and
  every declared artifact exists;
- `1` for a failed, timed-out, hollow, or artifact-incomplete proof; and
- `2` for a malformed, unapproved, or out-of-workspace manifest.

When `--out-dir` is supplied, Code Factory writes only an explicit proof packet:
public JSON, Markdown, Mermaid, and four captured-output log files. The public
receipt is hash-bound; it never includes raw captured output.

## Markers

| Marker | Meaning |
| --- | --- |
| `E2E_PROOF_PASS` | The declared positive/negative command pair behaved as required. |
| `HOLLOW_E2E_TEST` | The negative mutation exited zero: the test did not reject the declared failure. |
| `E2E_POSITIVE_FAILED` / `E2E_POSITIVE_TIMEOUT` | The declared positive path did not establish its local baseline. |
| `E2E_NEGATIVE_TIMEOUT` | The negative mutation did not complete within the approved budget. |
| `E2E_ARTIFACT_MISSING` | A declared workspace artifact was not produced. |

## Scope boundary

This is evidence about one exact local command pair, its output digests, and
declared local artifacts. `network_egress: "not_granted"` is a required
declaration; Code Factory does **not** claim to enforce host or process network
isolation. The gate does not run a browser itself, provision infrastructure,
approve a merge, deploy, or establish production readiness. Those decisions
remain explicit human-controlled gates.

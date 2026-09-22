# CF Live and CF Fix

CF now has two short paths for the moments developers repeat most often:

* **CF Live** maps saved paths to only the checks that can be affected, reports
  the next action immediately, and can run those checks in fresh temporary
  workspaces.
* **CF Fix** packages reproduction, repair verification, and negative controls
  into one handoff so a green repair cannot hide a weakened regression test.

## CF Live

Create a `factory.live-feedback.v1` manifest. Each check declares the paths it
covers, a bounded read-only command, its expected exit code, and a timeout.
The contract digest binds the feedback request to the approved intent or test
policy.

```json
{
  "schema": "factory.live-feedback.v1",
  "live_id": "checkout-save",
  "contract_sha256": "<64-hex-contract-digest>",
  "changed_paths": ["src/checkout.py"],
  "checks": [
    {
      "id": "checkout-tests",
      "paths": ["src/checkout.py", "tests/test_checkout.py"],
      "argv": ["python", "-m", "pytest", "tests/test_checkout.py", "-q"],
      "expected_exit": 0,
      "timeout_seconds": 60,
      "max_output_bytes": 65536,
      "env": {"PYTHONIOENCODING": "utf-8"}
    }
  ]
}
```

Plan the affected checks while editing:

```powershell
factory senior live live.json --root .
```

Collect fresh evidence explicitly when ready:

```powershell
factory senior live live.json --root . --execute --out .factory/live/receipt.json
```

The command copies the workspace into a temporary replay directory, bounds the
process and output, and returns `PASS`, `FAIL`, `READY`, `SKIPPED`, or
`BLOCKED` per check. It never modifies the source workspace or grants release
authority. Use `--changed path/to/file.py` to inspect a proposed editor delta
without rewriting the manifest.

## CF Fix

CF Fix accepts the existing `factory.repair-comparison.v1` manifest used by
`factory senior repair`. It gives that contract a single developer handoff:

```powershell
factory senior fix repair.json --root . --execute --out .factory/fix/receipt.json
```

The result records the original failure reproduction, repaired candidate,
negative-control outcomes, a failure brief when the comparison fails, and the
next human action. A repair passes only when the original failure reproduces,
the candidate passes, and every negative control still fails as expected.

Both surfaces are advisory and local. They do not create patches, apply code,
approve exceptions, merge, publish, deploy, sign, or use credentials.

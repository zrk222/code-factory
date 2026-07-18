"""Auditable, expiring gate overrides. Overrides are evidence, never silence."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import uuid

from .contract import Receipt


def record_override(root: Path, issue: str, *, reason: str, approved_by: str, expires: str | None = None) -> dict:
    """Record a named, accountable override with its approver and optional expiry."""
    if not reason.strip() or not approved_by.strip():
        raise ValueError("reason and approved_by are required for an auditable override")
    created = datetime.now(timezone.utc).isoformat()
    payload = {"schema": "factory.override.v1", "id": uuid.uuid4().hex, "issue": issue,
               "reason": reason, "approved_by": approved_by, "expires": expires, "created_at": created,
               "scope_limits": ["Override records an exception; it does not turn a failed gate into a pass.", "Review expiry and ownership before release."]}
    directory = Path(root) / ".factory" / "overrides"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{issue.replace(':', '-')}-{payload['id'][:12]}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    receipt = Receipt("factoryline", "override", issue.replace(":", "-"), True,
                      outputs={"paths": [str(path)]},
                      inputs={"issue": issue, "approved_by": approved_by}).write(root)
    return payload | {"path": str(path), "receipt_path": str(receipt)}


def ci_template(feature: str) -> str:
    """Return a CI workflow template that verifies the named feature's evidence."""
    return f"""name: factory-proof
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  proof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: '3.12'
      - run: pip install factoryline-code-factory code-factory-1-spec code-factory-2-forge code-factory-3-compile code-factory-4-design
      - id: verify
        continue-on-error: true
        run: factory verify {feature} --root . --json > factory-verify.json
      - if: always()
        run: gh pr comment ${{{{ github.event.pull_request.number }}}} --body-file factory-verify.json
        env:
          GH_TOKEN: ${{{{ github.token }}}}
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: factory-proof
          path: factory-verify.json
      - if: steps.verify.outcome == 'failure'
        run: exit 1
"""

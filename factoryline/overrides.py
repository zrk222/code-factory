"""Auditable, expiring gate overrides. Overrides are evidence, never silence."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import uuid


def record_override(root: Path, issue: str, *, reason: str, approved_by: str, expires: str | None = None) -> dict:
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
    return payload | {"path": str(path)}


def ci_template(feature: str) -> str:
    return f"""name: factory-proof\non: [pull_request]\npermissions:\n  contents: read\n  pull-requests: write\njobs:\n  proof:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v5\n      - uses: actions/setup-python@v6\n        with: {{ python-version: '3.12' }}\n      - run: pip install factoryline-code-factory code-factory-1-spec code-factory-2-forge code-factory-3-compile code-factory-4-design\n      - run: factory verify {feature} --root . --json > factory-verify.json || true\n      - run: gh pr comment ${{{{ github.event.pull_request.number }}}} --body-file factory-verify.json\n        env:\n          GH_TOKEN: ${{{{ github.token }}}}\n      - uses: actions/upload-artifact@v4\n        with: {{ name: factory-proof, path: factory-verify.json }}\n"""

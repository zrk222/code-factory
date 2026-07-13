"""Example policy evaluator. Exit zero only for the intended release policy."""
from __future__ import annotations

import json
from pathlib import Path
import sys


def main(policy_path: str) -> int:
    policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    checks = {
        "release.require_ci": policy.get("release", {}).get("require_ci") is True,
        "quality.require_hollow_tests": policy.get("quality", {}).get("require_hollow_tests") is True,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        print("policy rejected: " + ", ".join(failed))
        return 1
    print("policy accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))

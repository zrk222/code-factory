"""Exercise an installed wheel outside the source checkout using a real bypass."""
import json
from pathlib import Path
import tempfile

import factoryline.review_audits as audits
from factoryline.github_proof_review import render_github_proof_review
from factoryline.change_review import review_change


def main() -> None:
    """Require a site-packages import, detect a bypass, and render its review."""
    module_path = Path(audits.__file__).as_posix()
    assert "/site-packages/" in module_path, module_path
    with tempfile.TemporaryDirectory(prefix="cf-wheel-audit-") as folder:
        root = Path(folder)
        (root / "app.py").write_text(
            "def safe():\n    authorize()\n    delete()\n"
            "def candidate():\n    if allowed:\n        authorize()\n    delete()\n",
            encoding="utf-8",
        )
        targets = [{"path": "app.py", "symbol": name} for name in ("safe", "candidate")]
        policy = {"schema": audits.SCHEMA,
            "pattern_groups": [{"id": "peers", "origin": "agent_proposed", "members": targets, "required_calls": ["authorize", "delete"]}],
            "effect_rules": [{"id": "guard", "origin": "agent_proposed", "target": targets[1], "guard_call": "authorize", "effect_call": "delete"}]}
        (root / ".factory").mkdir()
        (root / ".factory/review-audits.json").write_text(json.dumps(policy), encoding="utf-8")
        report = audits.audit_code(root)
        assert report["results"][0]["state"] == "no_structural_findings"
        assert report["findings"][0]["code"] == "GUARD_PATH_BYPASS"
        review = render_github_proof_review(review_change(root, changed=["app.py"]), "a" * 40)
        assert review["check"]["conclusion"] == "neutral"
        assert "GUARD_PATH_BYPASS" in review["github_comment"]
        print(json.dumps({"installed_module": module_path, "state": report["state"],
                          "detected": report["findings"][0]["code"], "github_delivery": "neutral"}))


if __name__ == "__main__":
    main()

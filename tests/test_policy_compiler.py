from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.policy_compiler import PolicyCompileError, compile_policy, write_compiled_policy


def _policy() -> dict:
    return {
        "schema": "factory.policy.v1",
        "risk": {
            "default": "supervised",
            "require_human_approval_for": ["production-deploy", "security"],
        },
        "quality": {
            "require_hollow_tests": True,
            "require_hollow_validators": True,
            "min_goldens": 1,
            "max_complexity_delta": 10,
        },
        "tokens": {"require_meter": True, "max_estimated_cost_usd": 5.0},
        "design": {"purpose_profile": "developer", "require_prestige_audit": True},
        "release": {"require_clean_install": True, "require_license": True, "require_ci": True},
    }


def test_compiler_is_key_order_invariant_and_hash_bound(tmp_path: Path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(_policy(), indent=2), encoding="utf-8")
    reordered = {
        "release": _policy()["release"],
        "design": _policy()["design"],
        "schema": "factory.policy.v1",
        "tokens": _policy()["tokens"],
        "quality": _policy()["quality"],
        "risk": _policy()["risk"],
    }
    second.write_text(json.dumps(reordered, indent=2), encoding="utf-8")

    left = compile_policy(tmp_path, first)
    right = compile_policy(tmp_path, second)

    assert left["status"] == "COMPILED"
    assert left["policy_sha256"] == right["policy_sha256"]
    assert left["manifest_sha256"] == right["manifest_sha256"]
    assert [item["id"] for item in left["checks"]] == sorted(item["id"] for item in left["checks"])
    assert {item["action_class"] for item in left["human_gates"] if "action_class" in item} == {"production-deploy", "security"}
    assert left["authority"] == {"execute": False, "merge": False, "deploy": False, "release": False, "billing": False}


def test_unknown_rules_are_visible_and_fail_closed(tmp_path: Path):
    path = tmp_path / "policy.json"
    payload = _policy()
    payload["quality"]["require_magic"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = compile_policy(tmp_path, path)

    assert result["status"] == "REVIEW_REQUIRED"
    assert {item["path"] for item in result["review_required"]} == {"quality.require_magic"}


@pytest.mark.parametrize(
    ("path", "value"),
    [("quality", {"require_hollow_tests": "yes"}), ("risk", {"default": "magic"}), ("tokens", {"max_estimated_cost_usd": -1})],
)
def test_malformed_rules_are_visible(tmp_path: Path, path: str, value: dict):
    policy = {"schema": "factory.policy.v1", path: value}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    result = compile_policy(tmp_path, policy_path)

    assert result["status"] == "REVIEW_REQUIRED"
    assert result["review_required"]


def test_wrong_schema_and_workspace_escape_are_rejected(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "factory.policy.v0"}), encoding="utf-8")
    with pytest.raises(PolicyCompileError, match="schema"):
        compile_policy(tmp_path, bad)
    with pytest.raises(PolicyCompileError, match="inside the workspace"):
        compile_policy(tmp_path, Path("..") / "outside.json")


def test_write_and_cli_emit_the_same_manifest(tmp_path: Path, capsys):
    policy_path = tmp_path / "factory.policy.json"
    out = tmp_path / ".factory" / "ops" / "policy-checks.json"
    policy_path.write_text(json.dumps(_policy()), encoding="utf-8")

    expected = write_compiled_policy(tmp_path, policy_path, out)
    assert out.exists()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["manifest_sha256"] == expected["manifest_sha256"]
    assert written["marker"] == "POLICY_CLI_WRITTEN"

    assert main(["ops", "policy", "factory.policy.json", "--root", str(tmp_path), "--json"]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["status"] == "COMPILED"
    assert emitted["policy_sha256"] == expected["policy_sha256"]

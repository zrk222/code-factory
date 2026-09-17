from __future__ import annotations

import json
from pathlib import Path
import textwrap

import pytest

from factoryline.review_audits import ReviewAuditError, audit_code, audit_fingerprint, security_scan
from factoryline.change_review import ChangeReviewError, review_change
from factoryline.cli import main


def workspace(root: Path, body: str = "require_auth()\nstore.delete()") -> Path:
    source = "def safe():\n    require_auth()\n    store.delete()\n\ndef candidate():\n" + textwrap.indent(body, "    ") + "\n"
    (root / "app.py").write_text(source, encoding="utf-8")
    policy = {
        "schema": "factory.review-audit-policy.v1",
        "pattern_groups": [{"id": "peer-guards", "origin": "agent_proposed",
            "members": [{"path": "app.py", "symbol": "safe"}, {"path": "app.py", "symbol": "candidate"}],
            "required_calls": ["require_auth", "store.delete"]}],
        "effect_rules": [{"id": "delete-guard", "origin": "human_confirmed", "target": {"path": "app.py", "symbol": "candidate"},
            "guard_call": "require_auth", "effect_call": "store.delete"}]}
    folder = root / ".factory"
    folder.mkdir(exist_ok=True)
    path = folder / "review-audits.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_missing_peer_call_has_exact_peer_evidence(tmp_path):
    workspace(tmp_path, "store.delete()")
    result = audit_code(tmp_path, tool="patterns")
    assert result["state"] == "findings"
    finding, = result["findings"]
    assert finding["code"] == "PATTERN_REQUIRED_CALL_MISSING"
    assert finding["target"]["symbol"] == "candidate"
    assert finding["facts"]["missing_call"] == "require_auth"
    assert finding["facts"]["peers_with_call"] == [{"path": "app.py", "symbol": "safe"}]
    assert finding["declared_origin"] == "agent_proposed"


def test_guard_audit_catches_what_pattern_presence_misses(tmp_path):
    workspace(tmp_path, "if permitted:\n    require_auth()\nstore.delete()")
    result = audit_code(tmp_path)
    assert result["results"][0]["state"] == "no_structural_findings"
    finding, = result["findings"]
    assert finding["code"] == "GUARD_PATH_BYPASS"
    assert finding["facts"]["structural_witness"] == ["line 6: condition false"]
    assert finding["facts"]["effect_line"] == 8


@pytest.mark.parametrize("body", [
    "require_auth()\nstore.delete()",
    "if permitted:\n    require_auth()\nelse:\n    require_auth()\nstore.delete()",
    "if not permitted:\n    return\nrequire_auth()\nstore.delete()",
    "if not permitted:\n    raise ValueError()\nrequire_auth()\nstore.delete()",
])
def test_supported_guarded_paths_have_no_structural_findings(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path)
    assert result["state"] == "no_structural_findings"
    assert not any(result["authority"].values())
    assert result["governance"] == "human_controlled"


@pytest.mark.parametrize("body", [
    "store.delete()\nrequire_auth()",
    "require_auth(store.delete())",
    "return store.delete()",
    "if require_auth():\n    store.delete()",
    "allowed = require_auth()\nstore.delete()",
])
def test_non_dominating_guards_never_hide_effect(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path, tool="guard-paths")
    assert any(f["code"] == "GUARD_PATH_BYPASS" for f in result["findings"])


@pytest.mark.parametrize("body", [
    "for x in values:\n    require_auth()\nstore.delete()",
    "try:\n    require_auth()\nexcept Exception:\n    pass\nstore.delete()",
    "with lock:\n    require_auth()\nstore.delete()",
    "require_auth() or store.delete()",
    "require_auth()\nstore.delete = fake\nstore.delete()",
    "require_auth()",  # absent effect cannot validate the declared release path
    "def child():\n    require_auth()\nstore.delete()",
])
def test_unknown_semantics_never_receive_clean_state(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path, tool="guard-paths")
    assert result["state"] == "incomplete"
    assert result["results"][0]["analysis_gaps"]


def test_nested_guard_does_not_count_as_peer_pattern(tmp_path):
    workspace(tmp_path, "def child():\n    require_auth()\nstore.delete()")
    assert audit_code(tmp_path, tool="patterns")["findings"][0]["facts"]["missing_call"] == "require_auth"


def test_explicit_scope_hashes_no_execution_or_writes(tmp_path):
    workspace(tmp_path)
    with (tmp_path / "app.py").open("a") as stream:
        stream.write("\nraise RuntimeError('this module must never be imported')\n")
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    first = audit_code(tmp_path)
    assert len(first["sources"]) == 1
    assert len(first["policy"]["sha256"]) == 64
    assert audit_code(tmp_path) == first
    assert before == {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with (tmp_path / "app.py").open("a") as stream:
        stream.write("# changed\n")
    assert audit_code(tmp_path)["audit_sha256"] != first["audit_sha256"]


@pytest.mark.parametrize("path", ["../app.py", "/app.py", "C:/app.py", "C:app.py", "missing.py"])
def test_invalid_source_path_rejected(tmp_path, path):
    policy_path = workspace(tmp_path)
    policy = json.loads(policy_path.read_text())
    policy["effect_rules"][0]["target"]["path"] = path
    policy_path.write_text(json.dumps(policy))
    with pytest.raises(ReviewAuditError):
        audit_code(tmp_path)


@pytest.mark.parametrize("mutation", ["duplicate", "extra", "symbol", "empty", "origin", "same-call", "missing-tool"])
def test_policy_validation_and_missing_lane(tmp_path, mutation):
    path = workspace(tmp_path)
    policy = json.loads(path.read_text())
    if mutation == "duplicate":
        policy["effect_rules"][0]["id"] = "peer-guards"
    elif mutation == "extra":
        policy["execute"] = True
    elif mutation == "symbol":
        policy["effect_rules"][0]["target"]["symbol"] = "absent"
    elif mutation == "empty":
        policy["pattern_groups"] = policy["effect_rules"] = []
    elif mutation == "origin":
        policy["effect_rules"][0]["origin"] = ["human_confirmed"]
    elif mutation == "same-call":
        policy["effect_rules"][0]["guard_call"] = "store.delete"
    else:
        policy["effect_rules"] = []
    path.write_text(json.dumps(policy))
    if mutation == "missing-tool":
        assert audit_code(tmp_path)["state"] == "incomplete"
    else:
        with pytest.raises(ReviewAuditError):
            audit_code(tmp_path)


def test_path_explosion_is_explicit(tmp_path):
    workspace(tmp_path, "\n".join(f"if condition{i}:\n    pass" for i in range(8)) + "\nrequire_auth()\nstore.delete()")
    result = audit_code(tmp_path, tool="guard-paths")
    assert result["state"] == "incomplete"
    assert "path exploration limit" in result["results"][0]["analysis_gaps"]


def test_cli_and_change_review_integration(tmp_path, capsys):
    workspace(tmp_path, "if permitted:\n    require_auth()\nstore.delete()")
    assert main(["audit", "all", "--root", str(tmp_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["findings"][0]["code"] == "GUARD_PATH_BYPASS"
    review = review_change(tmp_path, changed=["app.py"])
    assert review["findings"][0]["kind"] == "unmatched_changed_path"
    assert any(f["kind"] == "GUARD_PATH_BYPASS" for f in review["findings"])
    assert "GUARD_PATH_BYPASS" in review["review_markdown"]
    assert "GUARD_PATH_BYPASS" in review["mermaid"]
    assert review["code_audits"] == result


def test_audit_fingerprint_is_self_hash_bound_and_reusable(tmp_path):
    workspace(tmp_path)
    out = tmp_path / ".factory" / "fingerprint.json"
    first = audit_fingerprint(tmp_path, out_path=out)
    assert first["state"] == "CURRENT"
    assert first["reusable"] is True
    assert first["receipt_sha256"] == __import__("hashlib").sha256(
        __import__("json").dumps({k: v for k, v in first.items() if k != "receipt_sha256"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    second = audit_fingerprint(tmp_path, baseline_path=out)
    assert second["state"] == "CURRENT"
    assert second["changes"]["policy"] is False


def test_audit_fingerprint_blocks_stale_baseline_and_reports_added_finding(tmp_path):
    workspace(tmp_path)
    baseline = tmp_path / ".factory" / "fingerprint.json"
    audit_fingerprint(tmp_path, out_path=baseline)
    (tmp_path / "app.py").write_text(
        "def safe():\n    require_auth()\n    store.delete()\n\ndef candidate():\n    store.delete()\n",
        encoding="utf-8",
    )
    result = audit_fingerprint(tmp_path, baseline_path=baseline)
    assert result["state"] == "DRIFT_DETECTED"
    assert result["code"] == "E_AUDIT_FINGERPRINT_STALE"
    assert result["reusable"] is False
    assert result["changes"]["sources"] is True


def test_audit_fingerprint_rejects_tampered_baseline(tmp_path):
    workspace(tmp_path)
    baseline = tmp_path / ".factory" / "fingerprint.json"
    audit_fingerprint(tmp_path, out_path=baseline)
    value = json.loads(baseline.read_text(encoding="utf-8"))
    value["fingerprint"]["state"] = "findings"
    baseline.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ReviewAuditError, match="digest is invalid"):
        audit_fingerprint(tmp_path, baseline_path=baseline)


def test_audit_fingerprint_cli_emits_actionable_json(tmp_path, capsys):
    workspace(tmp_path)
    assert main(["audit", "fingerprint", "--root", str(tmp_path), "--out", ".factory/fingerprint.json", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "AUDIT_FINGERPRINT_READY"
    assert result["authority"]["approval"] is False


def test_security_scan_blocks_dynamic_execution_and_shell(tmp_path):
    (tmp_path / "unsafe.py").write_text(
        "import os\nimport subprocess\ndef run(value):\n    eval(value)\n    os.system(value)\n    subprocess.run(value, shell=True)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert {item["code"] for item in result["findings"]} == {"SECURITY_DYNAMIC_EXECUTION", "SECURITY_OS_COMMAND", "SECURITY_SHELL_COMMAND"}
    assert all(item["path"] == "unsafe.py" for item in result["findings"])
    assert result["authority"] == {"execution": False, "approval": False, "publication": False, "deployment": False}


def test_security_scan_accepts_reviewed_loaders_and_argv_bound_processes(tmp_path):
    (tmp_path / "safe.py").write_text(
        "import subprocess\nimport yaml\ndef run(value):\n    yaml.load(value, Loader=yaml.SafeLoader)\n    subprocess.run([\"tool\", value], shell=False, check=True)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "CLEAN"
    assert result["parse_errors"] == 0


def test_security_scan_reports_parse_errors_fail_closed(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"] == {"QUALITY_SYNTAX_ERROR": 1}


def test_security_scan_rejects_concurrent_source_mutation(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def ok():\n    return 1\n", encoding="utf-8")
    import factoryline.review_audits as module
    original = module._security_scan_tree

    def mutate(*args):
        result = original(*args)
        source.write_text("def ok():\n    return 2\n", encoding="utf-8")
        return result

    monkeypatch.setattr(module, "_security_scan_tree", mutate)
    with pytest.raises(ReviewAuditError, match="Evidence changed during security scan"):
        security_scan(tmp_path)


def test_no_policy_is_not_a_pass_and_invalid_policy_fails_closed(tmp_path, capsys):
    assert review_change(tmp_path, changed=["app.py"])["code_audits"]["state"] == "not_configured"
    assert main(["audit", "all", "--root", str(tmp_path), "--json"]) == 2
    assert json.loads(capsys.readouterr().err)["state"] == "invalid"
    path = workspace(tmp_path)
    path.write_text("{}")
    with pytest.raises(ChangeReviewError):
        review_change(tmp_path, changed=["app.py"])


def test_evidence_race_rejected(tmp_path, monkeypatch):
    import factoryline.review_audits as module
    workspace(tmp_path)
    original = module._patterns
    def mutate(*args):
        result = original(*args)
        (tmp_path / "app.py").write_text("# changed during audit")
        return result
    monkeypatch.setattr(module, "_patterns", mutate)
    with pytest.raises(ReviewAuditError, match="Evidence changed"):
        audit_code(tmp_path)


def test_malformed_and_oversized_source(tmp_path):
    workspace(tmp_path)
    for source in ["def (", "x" * 1_000_001]:
        (tmp_path / "app.py").write_text(source)
        with pytest.raises(ReviewAuditError):
            audit_code(tmp_path)


def test_documented_example_is_executable(tmp_path):
    import re
    doc = (Path(__file__).resolve().parents[1] / "docs/CODE_REVIEW_AUDITS.md").read_text(encoding="utf-8")
    (tmp_path / "app.py").write_text(re.search(r"```python\n(.*?)```", doc, re.S)[1], encoding="utf-8")
    (tmp_path / "policy.json").write_text(re.search(r"```json\n(.*?)```", doc, re.S)[1], encoding="utf-8")
    result = audit_code(tmp_path, "policy.json")
    assert result["results"][0]["state"] == "no_structural_findings"
    assert result["findings"][0]["code"] == "GUARD_PATH_BYPASS"


def test_duplicate_json_fields_rejected(tmp_path):
    path = workspace(tmp_path)
    path.write_text(path.read_text().replace('"origin": "human_confirmed"', '"origin": "human_confirmed", "origin": "agent_proposed"'))
    with pytest.raises(ReviewAuditError, match="Duplicate JSON"):
        audit_code(tmp_path)


def test_duplicate_peer_alias_rejected(tmp_path):
    path = workspace(tmp_path)
    policy = json.loads(path.read_text())
    policy["pattern_groups"][0]["members"][1] = {"path": "./app.py", "symbol": "safe"}
    path.write_text(json.dumps(policy))
    with pytest.raises(ReviewAuditError, match="Duplicate peer"):
        audit_code(tmp_path)


def test_async_guard_and_effect(tmp_path):
    workspace(tmp_path, "await require_auth()\nawait store.delete()")
    source = tmp_path / "app.py"
    source.write_text(source.read_text().replace("def candidate", "async def candidate"))
    assert audit_code(tmp_path)["state"] == "no_structural_findings"


def test_dynamic_execution_is_incomplete(tmp_path):
    workspace(tmp_path, "require_auth()\nexec(payload)\nstore.delete()")
    assert audit_code(tmp_path)["state"] == "incomplete"


def test_github_delivery_preserves_findings_and_rejects_tampering(tmp_path):
    from factoryline.github_proof_review import GitHubProofReviewError, render_github_proof_review
    workspace(tmp_path, "store.delete()")
    review = review_change(tmp_path, changed=["app.py"])
    payload = render_github_proof_review(review, "a" * 40)
    assert payload["check"]["conclusion"] == "neutral"
    assert "GUARD_PATH_BYPASS" in payload["github_comment"]
    review["code_audits"]["authority"]["approval"] = True
    with pytest.raises(GitHubProofReviewError):
        render_github_proof_review(review, "a" * 40)


def test_expressions_do_not_treat_argument_guards_as_prior_authorization(tmp_path):
    import ast
    from factoryline.review_audits import _GuardPaths, _Path
    policy = json.loads(workspace(tmp_path).read_text())
    rule = policy["effect_rules"][0]
    engine = _GuardPaths(rule, rule["target"])
    engine.expressions(ast.parse("store.delete(require_auth())").body[0], [_Path()])
    assert engine.findings[0]["code"] == "GUARD_PATH_BYPASS"
    assert engine.effects == 1


def test_simple_statement_checks_effect_arguments_before_guard(tmp_path):
    import ast
    from factoryline.review_audits import _GuardPaths, _Path
    rule = json.loads(workspace(tmp_path).read_text())["effect_rules"][0]
    engine = _GuardPaths(rule, rule["target"])
    paths = engine.simple_statement(ast.parse("require_auth(store.delete())").body[0], [_Path()])
    assert paths[0].guarded is True
    assert len(engine.findings) == 1  # invocation arguments run before the guard


def test_rebinds_identity_distinguishes_local_data_from_guard_alias_changes(tmp_path):
    import ast
    from factoryline.review_audits import _GuardPaths
    rule = json.loads(workspace(tmp_path).read_text())["effect_rules"][0]
    engine = _GuardPaths(rule, rule["target"])
    assert engine.rebinds_identity(ast.parse("require_auth = noop").body[0])
    assert engine.rebinds_identity(ast.parse("store.delete = noop").body[0])
    assert not engine.rebinds_identity(ast.parse("count = 4").body[0])
    assert not engine.rebinds_identity(ast.parse("require_auth()").body[0])

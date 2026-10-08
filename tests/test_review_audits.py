from __future__ import annotations

import json
from pathlib import Path
import textwrap

import pytest

from factoryline.review_audits import (
    ReviewAuditError,
    audit_code,
    audit_fingerprint,
    load_tenant_read_contract,
    security_evals,
    security_scan,
)
from factoryline.change_review import ChangeReviewError, review_change
from factoryline.cli import main


def test_security_scan_rejects_external_source_link(tmp_path):
    outside = tmp_path.parent / "external-source.txt"
    outside.write_text("PRIVATE_SOURCE = 1\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("source symlinks require OS permission")
    result = security_scan(tmp_path)
    assert result["unreadable_sources"] == 1
    assert result["audit_coverage"]["complete"] is False
    assert "PRIVATE_SOURCE" not in json.dumps(result)


def test_security_source_rejects_linked_parent(tmp_path):
    from factoryline.review_audits import _security_source_bytes
    from factoryline.runtime_audit_common import RuntimeAuditError

    outside = tmp_path.parent / "external-sources"
    outside.mkdir(exist_ok=True)
    (outside / "source.py").write_text("PRIVATE_SOURCE = 1\n", encoding="utf-8")
    try:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks require OS permission")
    with pytest.raises(RuntimeAuditError, match="linked evidence"):
        _security_source_bytes(tmp_path, "linked/source.py")


def test_security_binding_recheck_rejects_link_swap(tmp_path):
    from factoryline.review_audits import _verify_security_bindings
    from hashlib import sha256

    source = tmp_path / "source.py"
    raw = b"VALUE = 1\n"
    source.write_bytes(raw)
    binding = {
        "path": "source.py",
        "sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    outside = tmp_path.parent / "external-binding.txt"
    outside.write_bytes(raw)
    source.unlink()
    try:
        source.symlink_to(outside)
    except OSError:
        pytest.skip("source symlinks require OS permission")
    with pytest.raises(ReviewAuditError, match="Evidence changed"):
        _verify_security_bindings(tmp_path, [binding])


def test_security_syntax_diagnostic_omits_source_and_absolute_path(tmp_path):
    (tmp_path / "source.py").write_text("PRIVATE_SOURCE = (\n", encoding="utf-8")
    result = security_scan(tmp_path)
    details = [finding["facts"].get("detail") for finding in result["findings"]]
    assert details == ["invalid Python syntax"]


def test_audit_command_boundary_is_lazily_loaded() -> None:
    import factoryline.cli as cli
    from factoryline import cli_audit

    assert not hasattr(cli, "audit_code")
    assert cli_audit.COMMAND_GROUP == "audit"
    assert cli_audit.OWNER == "quality-security"


def test_audit_agent_context_cli_routes_specialist_domains(capsys) -> None:
    assert (
        main(
            [
                "audit",
                "agent-context",
                "--role",
                "specialty_ai_security_reviewer",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.audit-agent-context.v1"
    assert result["role_resolution_state"] == "RESOLVED_FROM_CANONICAL_REGISTRY"
    assert (
        result["specialist_roles"][0]["specialist_role"]
        == "specialty_ai_security_reviewer"
    )
    assert result["domains"]
    assert all(
        row["specialist_role"] == "specialty_ai_security_reviewer"
        for row in result["domains"]
    )


def test_audit_cli_private_handlers_stay_bounded():
    import ast
    import inspect
    from factoryline import cli_audit

    for name, function in vars(cli_audit).items():
        if name != "run" and not name.startswith("_run_"):
            continue
        count = 1
        for node in ast.walk(ast.parse(inspect.getsource(function))):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (name, count)


def test_security_scan_orchestration_stays_within_complexity_budget():
    import ast
    import inspect

    import factoryline.review_audits as module

    for name in (
        "security_scan",
        "_tenant_contract_bindings",
        "_tenant_binding_entry",
        "_tenant_binding_parts",
        "_normalize_tenant_selector",
    ):
        count = 1
        tree = ast.parse(inspect.getsource(getattr(module, name)))
        for node in ast.walk(tree):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (name, count)


def workspace(root: Path, body: str = "require_auth()\nstore.delete()") -> Path:
    source = (
        "def safe():\n    require_auth()\n    store.delete()\n\ndef candidate():\n"
        + textwrap.indent(body, "    ")
        + "\n"
    )
    (root / "app.py").write_text(source, encoding="utf-8")
    policy = {
        "schema": "factory.review-audit-policy.v1",
        "pattern_groups": [
            {
                "id": "peer-guards",
                "origin": "agent_proposed",
                "members": [
                    {"path": "app.py", "symbol": "safe"},
                    {"path": "app.py", "symbol": "candidate"},
                ],
                "required_calls": ["require_auth", "store.delete"],
            }
        ],
        "effect_rules": [
            {
                "id": "delete-guard",
                "origin": "human_confirmed",
                "target": {"path": "app.py", "symbol": "candidate"},
                "guard_call": "require_auth",
                "effect_call": "store.delete",
            }
        ],
    }
    folder = root / ".factory"
    folder.mkdir(exist_ok=True)
    path = folder / "review-audits.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_missing_peer_call_has_exact_peer_evidence(tmp_path):
    workspace(tmp_path, "store.delete()")
    result = audit_code(tmp_path, tool="patterns")
    assert result["state"] == "findings"
    (finding,) = result["findings"]
    assert finding["code"] == "PATTERN_REQUIRED_CALL_MISSING"
    assert finding["target"]["symbol"] == "candidate"
    assert finding["facts"]["missing_call"] == "require_auth"
    assert finding["facts"]["peers_with_call"] == [{"path": "app.py", "symbol": "safe"}]
    assert finding["declared_origin"] == "agent_proposed"


def test_guard_audit_catches_what_pattern_presence_misses(tmp_path):
    workspace(tmp_path, "if permitted:\n    require_auth()\nstore.delete()")
    result = audit_code(tmp_path)
    assert result["results"][0]["state"] == "no_structural_findings"
    (finding,) = result["findings"]
    assert finding["code"] == "GUARD_PATH_BYPASS"
    assert finding["facts"]["structural_witness"] == ["line 6: condition false"]
    assert finding["facts"]["effect_line"] == 8


@pytest.mark.parametrize(
    "body",
    [
        "require_auth()\nstore.delete()",
        "if permitted:\n    require_auth()\nelse:\n    require_auth()\nstore.delete()",
        "if not permitted:\n    return\nrequire_auth()\nstore.delete()",
        "if not permitted:\n    raise ValueError()\nrequire_auth()\nstore.delete()",
    ],
)
def test_supported_guarded_paths_have_no_structural_findings(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path)
    assert result["state"] == "no_structural_findings"
    assert not any(result["authority"].values())
    assert result["governance"] == "human_controlled"


@pytest.mark.parametrize(
    "body",
    [
        "store.delete()\nrequire_auth()",
        "require_auth(store.delete())",
        "return store.delete()",
        "if require_auth():\n    store.delete()",
        "allowed = require_auth()\nstore.delete()",
    ],
)
def test_non_dominating_guards_never_hide_effect(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path, tool="guard-paths")
    assert any(f["code"] == "GUARD_PATH_BYPASS" for f in result["findings"])


@pytest.mark.parametrize(
    "body",
    [
        "for x in values:\n    require_auth()\nstore.delete()",
        "try:\n    require_auth()\nexcept Exception:\n    pass\nstore.delete()",
        "with lock:\n    require_auth()\nstore.delete()",
        "require_auth() or store.delete()",
        "require_auth()\nstore.delete = fake\nstore.delete()",
        "require_auth()",  # absent effect cannot validate the declared release path
        "def child():\n    require_auth()\nstore.delete()",
    ],
)
def test_unknown_semantics_never_receive_clean_state(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path, tool="guard-paths")
    assert result["state"] == "incomplete"
    assert result["results"][0]["analysis_gaps"]


def test_nested_guard_does_not_count_as_peer_pattern(tmp_path):
    workspace(tmp_path, "def child():\n    require_auth()\nstore.delete()")
    assert (
        audit_code(tmp_path, tool="patterns")["findings"][0]["facts"]["missing_call"]
        == "require_auth"
    )


def test_explicit_scope_hashes_no_execution_or_writes(tmp_path):
    workspace(tmp_path)
    with (tmp_path / "app.py").open("a") as stream:
        stream.write("\nraise RuntimeError('this module must never be imported')\n")
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    first = audit_code(tmp_path)
    assert len(first["sources"]) == 1
    assert len(first["policy"]["sha256"]) == 64
    assert audit_code(tmp_path) == first
    assert before == {
        str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    with (tmp_path / "app.py").open("a") as stream:
        stream.write("# changed\n")
    assert audit_code(tmp_path)["audit_sha256"] != first["audit_sha256"]


@pytest.mark.parametrize(
    "path", ["../app.py", "/app.py", "C:/app.py", "C:app.py", "missing.py"]
)
def test_invalid_source_path_rejected(tmp_path, path):
    policy_path = workspace(tmp_path)
    policy = json.loads(policy_path.read_text())
    policy["effect_rules"][0]["target"]["path"] = path
    policy_path.write_text(json.dumps(policy))
    with pytest.raises(ReviewAuditError):
        audit_code(tmp_path)


@pytest.mark.parametrize(
    "mutation",
    ["duplicate", "extra", "symbol", "empty", "origin", "same-call", "missing-tool"],
)
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
    workspace(
        tmp_path,
        "\n".join(f"if condition{i}:\n    pass" for i in range(8))
        + "\nrequire_auth()\nstore.delete()",
    )
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
    assert (
        first["receipt_sha256"]
        == __import__("hashlib")
        .sha256(
            __import__("json")
            .dumps(
                {k: v for k, v in first.items() if k != "receipt_sha256"},
                sort_keys=True,
                separators=(",", ":"),
            )
            .encode()
        )
        .hexdigest()
    )
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
    assert (
        main(
            [
                "audit",
                "fingerprint",
                "--root",
                str(tmp_path),
                "--out",
                ".factory/fingerprint.json",
                "--json",
            ]
        )
        == 0
    )
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
    assert {item["code"] for item in result["findings"]} == {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
    }
    assert all(item["path"] == "unsafe.py" for item in result["findings"])
    assert result["authority"] == {
        "execution": False,
        "approval": False,
        "publication": False,
        "deployment": False,
    }


def test_security_scan_accepts_reviewed_loaders_and_argv_bound_processes(tmp_path):
    (tmp_path / "safe.py").write_text(
        'import subprocess\nimport yaml\ndef run(value):\n    yaml.load(value, Loader=yaml.SafeLoader)\n    subprocess.run(["tool", value], shell=False, check=True)\n',
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "CLEAN"
    assert result["parse_errors"] == 0


def test_security_scan_receipt_measures_complete_supported_source_coverage(tmp_path):
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    generated = tmp_path / ".venv" / "ignored.py"
    generated.parent.mkdir()
    generated.write_text("not scanned", encoding="utf-8")
    coverage = security_scan(tmp_path)["audit_coverage"]
    assert coverage == {
        "language": "Python",
        "files_discovered": 1,
        "files_attempted": 1,
        "files_audited": 1,
        "audit_rate": 1.0,
        "rate_defined": True,
        "inventory_complete": True,
        "measurement_state": "complete",
        "complete": True,
        "limit": 460,
    }


def test_security_cli_displays_measured_source_audit_rate(tmp_path, capsys):
    (tmp_path / "app.py").write_text("answer = 42\n", encoding="utf-8")
    factory_dir = tmp_path / ".factory"
    factory_dir.mkdir()
    (factory_dir / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )

    assert main(["audit", "security", "--root", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "Coverage: 100.0% (1/1 Python sources; complete)" in output


def test_security_scan_does_not_report_vacuous_full_coverage(tmp_path):
    result = security_scan(tmp_path)
    coverage = result["audit_coverage"]

    assert result["state"] == "NO_SOURCES"
    assert coverage["files_discovered"] == 0
    assert coverage["files_attempted"] == 0
    assert coverage["files_audited"] == 0
    assert coverage["audit_rate"] is None
    assert coverage["rate_defined"] is False
    assert coverage["measurement_state"] == "no_eligible_sources"
    assert coverage["inventory_complete"] is True
    assert coverage["complete"] is False


def test_security_cli_returns_indeterminate_for_empty_inventory(tmp_path, capsys):
    exit_code = main(["audit", "security", "--root", str(tmp_path), "--json"])

    result = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert result["state"] == "NO_SOURCES"
    assert result["audit_coverage"]["audit_rate"] is None


def test_security_scan_blocks_instead_of_truncating_over_limit_inventory(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    assert module.MAX_SECURITY_SOURCE_FILES == 460
    monkeypatch.setattr(module, "MAX_SECURITY_SOURCE_FILES", 2)
    for index in range(3):
        (tmp_path / f"module_{index}.py").write_text("value = 1\n", encoding="utf-8")
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["audit_coverage"]["files_discovered"] == 3
    assert result["audit_coverage"]["files_attempted"] == 0
    assert result["audit_coverage"]["files_audited"] == 0
    assert result["audit_coverage"]["audit_rate"] == 0.0
    assert result["audit_coverage"]["inventory_complete"] is True
    assert result["audit_coverage"]["complete"] is False
    assert result["audit_coverage"]["measurement_state"] == "blocked"
    assert result["finding_counts"] == {"SECURITY_AUDIT_INCOMPLETE": 1}


def test_security_scan_tracks_import_aliases_and_unsafe_yaml_loaders(tmp_path):
    (tmp_path / "aliases.py").write_text(
        "from subprocess import run as launch\nimport yaml as y\n"
        "def run(value):\n    launch(value, shell=True)\n    y.load(value, Loader=y.UnsafeLoader)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert {item["code"] for item in result["findings"]} == {
        "SECURITY_SHELL_COMMAND",
        "SECURITY_UNSAFE_YAML",
    }


def test_security_tree_scan_reuses_one_ast_inventory_for_alias_and_tenant_checks(
    tmp_path, monkeypatch
):
    import ast

    import factoryline.review_audits as module

    source = (
        "import subprocess as sp\n"
        "def fetch(tenant_id):\n    return store.fetch(tenant_id=tenant_id)\n"
        "def run():\n    sp.run('cmd', shell=True)\n"
    )
    tree = ast.parse(source)
    path = tmp_path / "service.py"
    path.write_text(source, encoding="utf-8")
    original_walk = ast.walk
    calls = 0

    def counted_walk(node):
        nonlocal calls
        calls += 1
        return original_walk(node)

    monkeypatch.setattr(module.ast, "walk", counted_walk)
    findings = module._security_scan_tree(tmp_path, path, tree, ("store.fetch",), {})

    assert calls == 1
    assert [finding["code"] for finding in findings] == ["SECURITY_SHELL_COMMAND"]


def test_security_scan_reports_parse_errors_fail_closed(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"] == {"QUALITY_SYNTAX_ERROR": 1}
    assert result["audit_coverage"]["audit_rate"] == 0.0
    assert result["audit_coverage"]["complete"] is False
    assert result["audit_coverage"]["measurement_state"] == "incomplete"


def test_security_scan_separates_unreadable_sources_from_parse_errors(
    tmp_path, monkeypatch
):
    from pathlib import Path

    import factoryline.review_audits as module

    readable = tmp_path / "readable.py"
    unreadable = tmp_path / "unreadable.py"
    readable.write_text("value = 1\n", encoding="utf-8")
    unreadable.write_text("value = 2\n", encoding="utf-8")
    original_open = module.os.open

    def open_path(path, *args, **kwargs):
        if Path(path).resolve() == unreadable.resolve():
            raise PermissionError("denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", open_path)

    result = module.security_scan(tmp_path)

    assert result["state"] == "BLOCKED"
    assert result["parse_errors"] == 0
    assert result["unreadable_sources"] == 1
    assert result["oversized_sources"] == 0
    assert result["audit_coverage"] == {
        "language": "Python",
        "files_discovered": 2,
        "files_attempted": 2,
        "files_audited": 1,
        "audit_rate": 0.5,
        "rate_defined": True,
        "inventory_complete": True,
        "measurement_state": "incomplete",
        "complete": False,
        "limit": 460,
    }
    assert result["finding_counts"] == {"SECURITY_SOURCE_UNREADABLE": 1}


def test_security_scan_counts_oversized_source_as_attempted_but_unaudited(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    monkeypatch.setattr(module, "MAX_BYTES", 4)
    (tmp_path / "large.py").write_text("value = 123\n", encoding="utf-8")

    result = security_scan(tmp_path)

    assert result["state"] == "BLOCKED"
    assert result["oversized_sources"] == 1
    assert result["unreadable_sources"] == 0
    assert result["parse_errors"] == 0
    assert result["audit_coverage"]["files_discovered"] == 1
    assert result["audit_coverage"]["files_attempted"] == 1
    assert result["audit_coverage"]["files_audited"] == 0
    assert result["audit_coverage"]["audit_rate"] == 0.0
    assert result["audit_coverage"]["complete"] is False
    assert result["finding_counts"] == {"SECURITY_SOURCE_TOO_LARGE": 1}


def test_security_scan_rejects_large_file_without_unbounded_read(tmp_path, monkeypatch):
    from pathlib import Path

    import factoryline.review_audits as module

    monkeypatch.setattr(module, "MAX_BYTES", 4)
    (tmp_path / "large.py").write_text("value = 123\n", encoding="utf-8")

    def reject_unbounded_read(_path):
        raise AssertionError("security scan must not call read_bytes")

    monkeypatch.setattr(Path, "read_bytes", reject_unbounded_read)

    result = module.security_scan(tmp_path)

    assert result["finding_counts"] == {"SECURITY_SOURCE_TOO_LARGE": 1}
    assert result["audit_coverage"]["files_audited"] == 0


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


def test_security_evals_kill_all_adversarial_fixtures_and_keep_safe_control_clean():
    result = security_evals()
    assert result["marker"] == "SECURITY_EVALS_COMPLETE"
    assert result["state"] == "PASS"
    assert result["mutation_coverage"] == {"attempted": 14, "caught": 14, "rate": 1.0}
    assert result["safe_controls"] == {"attempted": 4, "passed": 4}
    assert result["authority"]["approval"] is False


@pytest.mark.parametrize(
    "body",
    [
        "assert True",
        "compute_value()",
        "actual = compute_value()\n    assert actual == actual",
        "assert len(result) >= 0",
    ],
)
def test_security_scan_detects_local_hollow_test_oracles(tmp_path, body):
    (tmp_path / "case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["findings"][0]["facts"]["symbol"] == "test_behavior"


@pytest.mark.parametrize(
    "body",
    [
        "expected = 3\n    alias = expected\n    assert alias == expected",
        "value = value\n    assert value == value",
        "result = 3\n    assert result == 3",
        "x = 5\n    x = x + 1\n    assert x == 6",
        "assert result or True",
    ],
)
def test_security_scan_detects_constant_and_boolean_tautologies(tmp_path, body):
    (tmp_path / "case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "body",
    [
        "assert compute_value() == 1",
        "self.assertEqual(compute_value(), 1)",
        "with pytest.raises(ValueError):\n        compute_value()",
    ],
)
def test_security_scan_preserves_real_assertions_and_exception_controls(tmp_path, body):
    if body.startswith("self.assert"):
        source = (
            "import unittest\n"
            "class Checks(unittest.TestCase):\n"
            "    def test_behavior(self):\n"
            f"        {body}\n"
        )
    else:
        source = "def test_behavior():\n    " + body + "\n"
    (tmp_path / "case.py").write_text(source)
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "body",
    [
        "argument = 5\n    result = compute(argument)\n    assert result == 6",
        "cases = [(2, 4)]\n    for value, expected in cases:\n        assert compute(value) == expected",
        "result = compute_value()\n    assert result == 6",
        "result = 0\n    if condition:\n        result = compute_value()\n    assert result == 6",
        "result = 0\n    try:\n        result = compute_value()\n    except ValueError:\n        result = fallback()\n    assert result == 6",
        "result = 0\n    with resource() as result:\n        pass\n    assert result == 6",
    ],
)
def test_security_scan_preserves_runtime_and_branch_rebound_oracles(tmp_path, body):
    (tmp_path / "case.py").write_text("def test_behavior():\n    " + body + "\n")
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_use_a_constant_reassigned_after_assertion(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    result = 3\n"
        "    assert result == 3\n"
        "    result = compute_value()\n"
        "    assert result == 3\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["findings"] == []


@pytest.mark.parametrize(
    ("body", "finding"),
    [
        ("result = compute_value()\n    assert (result or 1) == 1", False),
        ("value = compute_value() or 1\n    assert value == 1", False),
        ("value = True or compute_value()\n    assert value", True),
        ("value = False and compute_value()\n    assert not value", True),
        ("result = 2\n    assert (result or 1) == 1", False),
        ("result = 0\n    assert (result or 1) == 1", True),
        ("result = 3\n    assert (result or 1) == 1", False),
    ],
)
def test_security_scan_preserves_python_boolean_operand_semantics(
    tmp_path, body, finding
):
    (tmp_path / "case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert bool(result["findings"]) is finding


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (
            "assert value is not None",
            "non-null assertion does not verify the expected behavior",
        ),
        (
            "operation()\n    assert operation_mock.called",
            "mock invocation state does not verify its result or arguments",
        ),
        (
            "assert next_value() == next_value()",
            "repeated invocation compares a result to itself",
        ),
    ],
)
def test_security_scan_reports_weak_only_test_oracles(tmp_path, body, reason):
    (tmp_path / "case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}
    assert reason in result["findings"][0]["message"]


def test_security_scan_accepts_local_helper_with_independent_assertion(tmp_path):
    (tmp_path / "case.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    assert actual == expected\n\n"
        "def test_behavior():\n"
        "    assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_imported_helper_with_independent_assertion(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n"
        "    assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["findings"] == []
    assert result["oracle_context"]["edge_count"] == 1
    assert result["oracle_context"]["resolved_edges"][0]["kind"] == "assertion_helper"


def test_security_scan_rejects_imported_helper_that_swallows_assertion(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    try:\n        assert actual == expected\n"
        "    except AssertionError:\n        return\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n    assert_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_recognizes_test_named_assertion_helper(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_expected(actual, expected):\n    assert actual == expected\n\n"
        "def test_behavior():\n    test_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_recognizes_imported_test_named_assertion_helper(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def test_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import test_expected\n"
        "def test_behavior():\n    test_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_recognizes_assertion_hidden_by_warning_policy(tmp_path):
    (tmp_path / "case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', UserWarning)\n"
        "        emit_user_warning()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "filters",
    [
        "warnings.simplefilter('error', UserWarning)\n"
        "warnings.simplefilter('ignore', UserWarning)\n"
        "emit_user_warning()",
        "warnings.simplefilter('error', UserWarning)",
    ],
)
def test_security_scan_does_not_trust_inactive_warning_filter(tmp_path, filters):
    (tmp_path / "case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        + "\n".join("        " + line for line in filters.splitlines())
        + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_credit_unrelated_call_after_swallowed_warning(tmp_path):
    (tmp_path / "case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', UserWarning)\n"
        "        try:\n"
        "            warnings.warn('expected', UserWarning)\n"
        "        except UserWarning:\n"
        "            pass\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_ignores_manual_raise_after_unconditional_return(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n    return\n    raise AssertionError('unreachable')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "hidden_filter",
    [
        "if False:\n            warnings.simplefilter('error')",
        "def configure():\n            warnings.simplefilter('error')",
    ],
)
def test_security_scan_does_not_execute_nested_warning_filter_syntax(
    tmp_path, hidden_filter
):
    (tmp_path / "case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        + "\n".join("        " + line for line in hidden_filter.splitlines())
        + "\n        perform()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize("handler", ["Exception", "(AssertionError, ValueError)"])
def test_security_scan_rejects_helper_swallowing_broad_assertion(tmp_path, handler):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    try:\n        assert actual == expected\n"
        f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n    assert_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_accepts_assertion_reraised_from_handler(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    except Exception:\n        raise\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "imports,handler",
    [
        ("from builtins import BaseException as Ignore\n", "Ignore"),
        ("from builtins import Exception as Ignore\n", "Ignore"),
        ("import builtins as bi\n", "bi.BaseException"),
    ],
)
def test_security_scan_detects_aliased_exception_catch(tmp_path, imports, handler):
    (tmp_path / "case.py").write_text(
        imports
        + "def test_behavior():\n"
        + "    try:\n        assert compute() == 4\n"
        + f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "imports,suppress",
    [
        ("from contextlib import suppress as ignore\n", "ignore"),
        ("import contextlib as context\n", "context.suppress"),
    ],
)
def test_security_scan_detects_suppress_context_for_assertion(
    tmp_path, imports, suppress
):
    (tmp_path / "case.py").write_text(
        imports
        + "def test_behavior():\n"
        + f"    with {suppress}(AssertionError):\n"
        + "        assert compute() == 4\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_detects_assertion_suppressed_in_finally(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    finally:\n        return None\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_accepts_tuple_handler_with_named_reraise(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    except (AssertionError, ValueError) as error:\n        raise error\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_rejects_assertion_swallowed_by_finally_return(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    try:\n        assert actual == expected\n"
        "    except AssertionError:\n"
        "        try:\n            pass\n"
        "        finally:\n            return\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n    assert_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "body",
    [
        "if compute() != 4:\n        raise AssertionError('wrong value')",
        "if not compute():\n        raise AssertionError('empty result')",
    ],
)
def test_security_scan_recognizes_conditional_manual_assertion(tmp_path, body):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n    " + body + "\n", encoding="utf-8"
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_finds_hollow_inherited_test_in_helper_module(tmp_path):
    (tmp_path / "base.py").write_text(
        "class SharedCases:\n    def test_inherited(self):\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from base import SharedCases\nclass ConcreteCases(SharedCases):\n    pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    finding = next(
        item for item in result["findings"] if item["code"] == "QUALITY_HOLLOW_TEST"
    )
    assert finding["path"] == "base.py"
    assert finding["facts"]["symbol"] == "test_inherited"


def test_security_scan_does_not_trust_assertion_caught_in_nested_try(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    try:\n"
        "        if condition:\n            assert compute() == 4\n"
        "    except Exception:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_rejects_builtin_exception_alias_and_finally_return(tmp_path):
    (tmp_path / "case.py").write_text(
        "from builtins import Exception as Ignore\n"
        "def test_alias():\n"
        "    try:\n        assert compute() == 4\n"
        "    except Ignore:\n        pass\n\n"
        "def test_finally():\n"
        "    try:\n        assert compute() == 4\n"
        "    finally:\n        return\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 2}


def test_security_scan_rejects_contextlib_suppress_and_unreachable_manual_raise(
    tmp_path,
):
    (tmp_path / "case.py").write_text(
        "from contextlib import suppress\n"
        "def test_suppress():\n"
        "    with suppress(AssertionError):\n        assert compute() == 4\n\n"
        "def test_unreachable():\n"
        "    if False:\n        raise AssertionError('wrong')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 2}


def test_security_scan_does_not_trust_imported_production_function(tmp_path):
    (tmp_path / "library.py").write_text(
        "def render(value):\n    assert value is not None\n    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from library import render\n"
        "def test_behavior():\n"
        "    render(compute_value())\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_imported_noop_helper(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n"
        "    assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_accepts_testcase_mixin_assertions(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "class SharedMixin:\n"
        "    def test_shared(self):\n"
        "        self.assertEqual(compute_value(), 4)\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "import unittest\n"
        "from helpers import SharedMixin\n"
        "class Case(unittest.TestCase, SharedMixin):\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_aliased_indirect_testcase_mixin(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "class SharedMixin:\n"
        "    def test_shared(self):\n"
        "        self.assertEqual(compute_value(), 4)\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "import unittest as ut\n"
        "from helpers import SharedMixin\n"
        "class Base(ut.TestCase):\n"
        "    pass\n"
        "class Case(Base, SharedMixin):\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_resolves_assertion_submodule_imports(tmp_path):
    package = tmp_path / "checks"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "assertions.py").write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from checks import assertions\n"
        "def test_behavior():\n"
        "    assertions.assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_resolves_relative_assertion_submodule_imports(tmp_path):
    package = tmp_path / "suite"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "assertions.py").write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (package / "case.py").write_text(
        "from . import assertions\n"
        "def test_behavior():\n"
        "    assertions.assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_trust_imported_weak_helper(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_present(value):\n    assert value is not None\n",
        encoding="utf-8",
    )
    (tmp_path / "case.py").write_text(
        "from helpers import assert_present\n"
        "def test_behavior():\n"
        "    assert_present(compute_value())\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}


def test_security_scan_ignores_performance_benchmark_oracles(tmp_path):
    (tmp_path / "case.py").write_text(
        "from pytest_codspeed import BenchmarkFixture\n"
        "def test_speed(benchmark: BenchmarkFixture):\n"
        "    benchmark(compute_value)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_skip_untyped_benchmark_named_security_test(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_security_invariant(benchmark):\n"
        "    benchmark(lambda: dangerous_operation())\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_rejects_noop_assertion_named_helper(tmp_path):
    (tmp_path / "case.py").write_text(
        "def assert_nothing():\n"
        "    pass\n\n"
        "def test_behavior():\n"
        "    assert_nothing()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_local_noop_unittest_named_method(tmp_path):
    (tmp_path / "case.py").write_text(
        "class NoOp:\n"
        "    def assertEqual(self, actual, expected):\n"
        "        pass\n\n"
        "def test_behavior():\n"
        "    NoOp().assertEqual(load_value(), 4)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_reports_unittest_non_null_only_oracle(tmp_path):
    (tmp_path / "case.py").write_text(
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertIsNotNone(load_value())\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}


def test_security_scan_accepts_unittest_isinstance_assertion(tmp_path):
    (tmp_path / "case.py").write_text(
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertIsInstance(load_value(), Result)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_inherited_unittest_case_assertions(tmp_path):
    (tmp_path / "case.py").write_text(
        "import unittest\n"
        "class ProjectTestCase(unittest.TestCase):\n"
        "    pass\n\n"
        "class Checks(ProjectTestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertEqual(load_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_ignores_explicitly_skipped_hollow_test(tmp_path):
    (tmp_path / "case.py").write_text(
        "import pytest\n"
        "@pytest.mark.skip(reason='requires external service')\n"
        "def test_behavior():\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_keeps_strong_oracle_when_weak_assertion_is_also_present(
    tmp_path,
):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    assert result is not None\n"
        "    assert result == expected\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_tenant_contract_is_explicit_and_hash_bound(tmp_path):
    path = tmp_path / "service.py"
    path.write_text(
        "async def fetch(record_id):\n    return await store.fetch(record_id)\n"
    )
    assert security_scan(tmp_path)["findings"] == []
    missing = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert missing["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}
    assert missing["tenant_read_contract"]["calls"] == ["store.fetch"]
    assert missing["tenant_read_contract"]["keyword"] == "tenant_id"
    assert missing["audit_sha256"] != security_scan(tmp_path)["audit_sha256"]
    path.write_text(
        "async def fetch(record_id, tenant_id):\n    return await store.fetch(record_id, tenant_id=tenant_id)\n"
    )
    assert security_scan(tmp_path, tenant_read_calls=("store.fetch",))["findings"] == []
    path.write_text(
        "def fetch(record_id):\n    return store.fetch(record_id, tenant_id=record_id)\n"
    )
    assert (
        security_scan(tmp_path, tenant_read_calls=("store.fetch",))["state"]
        == "BLOCKED"
    )


def test_security_scan_rejects_invalid_tenant_contract(tmp_path):
    with pytest.raises(ReviewAuditError, match="qualified"):
        security_scan(tmp_path, tenant_read_calls=("invalid.call()",))


@pytest.mark.parametrize(
    ("source", "binding"),
    [
        (
            "async def fetch(record_id, org_scope):\n"
            "    return await store.fetch(record_id, tenant_id=org_scope)\n",
            "store.fetch=keyword:tenant_id:org_scope",
        ),
        (
            "def fetch(record_id, workspace_key):\n"
            "    return store.fetch(record_id, workspace_key)\n",
            "store.fetch=position:1:workspace_key",
        ),
    ],
)
def test_security_scan_accepts_declared_tenant_argument_bindings(
    tmp_path, source, binding
):
    (tmp_path / "service.py").write_text(source, encoding="utf-8")
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=(binding,),
    )
    assert result["state"] == "CLEAN"
    assert result["tenant_read_contract"]["argument_bindings"] == {
        "store.fetch": [binding.split("=", 1)[1]]
    }


def test_security_scan_accepts_tenant_parameter_copied_to_local_alias(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id):\n"
        "    scope = tenant_id\n"
        "    return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["state"] == "CLEAN"


def test_security_scan_rejects_tenant_alias_rebound_before_read(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id):\n"
        "    scope = tenant_id\n"
        "    scope = request.args['tenant']\n"
        "    return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_tenant_alias_shadowed_by_match_capture(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id, event):\n"
        "    scope = tenant_id\n"
        "    match event:\n"
        "        case {'scope': scope}:\n"
        "            pass\n"
        "    return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_tenant_alias_shadowed_by_exception_capture(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id):\n"
        "    scope = tenant_id\n"
        "    try:\n"
        "        risky_operation()\n"
        "    except ValueError as scope:\n"
        "        return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_blocks_uncontracted_sqlalchemy_reads(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def fetch_user(user_id):\n"
        "    return session.query(User).filter_by(id=user_id).first()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] >= 1


def test_security_scan_blocks_uncontracted_django_exclude_read(tmp_path):
    (tmp_path / "service.py").write_text(
        "from django.db import models\n"
        "def list_users():\n"
        "    return User.objects.exclude(is_active=False)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] >= 1


def test_security_scan_blocks_uncontracted_sqlmodel_exec_read(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlmodel import Session, select\n"
        "def list_users(session: Session):\n"
        "    return session.exec(select(User))\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] >= 1


def test_security_scan_rejects_declared_binding_to_wrong_function_parameter(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, workspace_key):\n"
        "    return store.fetch(record_id, record_id)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=position:1:workspace_key",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_rebound_tenant_parameter(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, org_scope):\n"
        "    org_scope = 'another-tenant'\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=keyword:tenant_id:org_scope",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


@pytest.mark.parametrize(
    "comprehension",
    [
        "[scope for scope in ids]",
        "{scope for scope in ids}",
        "{scope: value for scope, value in pairs}",
        "(scope for scope in ids)",
    ],
)
def test_security_scan_allows_comprehension_target_shadowing(tmp_path, comprehension):
    (tmp_path / "service.py").write_text(
        "def fetch(scope, ids):\n"
        f"    cached = {comprehension}\n"
        "    return store.fetch(id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=keyword:tenant_id:scope",),
    )
    assert result["state"] == "CLEAN"


def test_security_scan_rejects_outer_parameter_rebound_by_comprehension_walrus(
    tmp_path,
):
    (tmp_path / "service.py").write_text(
        "def fetch(scope, ids):\n"
        "    cached = [scope := value for value in ids]\n"
        "    return store.fetch(id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=keyword:tenant_id:scope",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_multiple_bindings_for_one_read_call(tmp_path):
    with pytest.raises(ReviewAuditError, match="only one tenant argument binding"):
        security_scan(
            tmp_path,
            tenant_read_calls=("store.fetch",),
            tenant_read_bindings=(
                "store.fetch=position:1:workspace_key",
                "store.fetch=position:0:record_id",
            ),
        )


def test_security_scan_rejects_optional_tenant_parameter(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, org_scope=None):\n"
        "    return store.fetch(record_id, org_scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=position:1:org_scope",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_unlisted_or_malformed_tenant_binding(tmp_path):
    with pytest.raises(ReviewAuditError, match="declared qualified read call"):
        security_scan(
            tmp_path,
            tenant_read_calls=("store.fetch",),
            tenant_read_bindings=("db.get=position:1:tenant_id",),
        )
    with pytest.raises(ReviewAuditError, match="position:INDEX:PARAMETER"):
        security_scan(
            tmp_path,
            tenant_read_calls=("store.fetch",),
            tenant_read_bindings=("store.fetch=position:tenant_id",),
        )


def test_security_scan_keeps_negative_callback_and_import_alias_controls(tmp_path):
    path = tmp_path / "test_controls.py"
    path.write_text(
        "from pytest import raises as expect_error\n"
        "def test_error():\n"
        "    with expect_error(ValueError):\n"
        "        compute()\n"
        "def test_no_read(monkeypatch):\n"
        "    def fail_on_read(*args):\n"
        "        raise AssertionError('unexpected read')\n"
        "    monkeypatch.setattr(store, 'fetch', fail_on_read)\n"
        "    compute()\n"
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["findings"][0]["facts"]["symbol"] == "test_no_read"


def test_security_scan_accepts_test_scoped_pytest_raises_import(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_expected_error():\n"
        "    from pytest import raises as expect_error\n"
        "    with expect_error(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_restores_module_alias_after_later_pytest_import(tmp_path):
    (tmp_path / "case.py").write_text(
        "import contextlib\n"
        "raises = contextlib.nullcontext\n"
        "from pytest import raises\n"
        "def test_expected_error():\n"
        "    with raises(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_restores_local_alias_after_later_pytest_import(tmp_path):
    (tmp_path / "case.py").write_text(
        "from contextlib import nullcontext as expect_error\n"
        "def test_expected_error():\n"
        "    expect_error = nullcontext\n"
        "    from pytest import raises as expect_error\n"
        "    with expect_error(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_trust_helper_with_rebound_assertion_alias(tmp_path):
    (tmp_path / "case.py").write_text(
        "from pytest import raises as expect_error\n"
        "import contextlib\n"
        "def assert_expected():\n"
        "    expect_error = contextlib.nullcontext\n"
        "    with expect_error(ValueError):\n"
        "        pass\n"
        "def test_behavior():\n"
        "    assert_expected()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_keeps_pytest_alias_across_nested_local_bindings(tmp_path):
    (tmp_path / "case.py").write_text(
        "from pytest import raises\n"
        "def test_expected_error():\n"
        "    def helper():\n"
        "        raises = None\n"
        "    values = [raises() for raises in callables]\n"
        "    with raises(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_trust_assertion_alias_call_inside_comprehension(
    tmp_path,
):
    (tmp_path / "case.py").write_text(
        "from pytest import raises\n"
        "def test_behavior():\n"
        "    results = [raises(ValueError) for raises in factories]\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_rebound_pytest_raises_alias(tmp_path):
    (tmp_path / "case.py").write_text(
        "from pytest import raises as expect_error\n"
        "import contextlib\n"
        "def test_behavior():\n"
        "    expect_error = contextlib.nullcontext\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_module_rebound_pytest_alias(tmp_path):
    (tmp_path / "case.py").write_text(
        "from pytest import raises as expect_error\n"
        "import contextlib\n"
        "expect_error = contextlib.nullcontext\n"
        "def test_behavior():\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_imports_from_other_scopes(tmp_path):
    (tmp_path / "case.py").write_text(
        "from contextlib import nullcontext as expect_error\n"
        "def unrelated():\n"
        "    from pytest import raises as expect_error\n"
        "def test_behavior():\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_invalidates_oracle_alias_after_module_star_import(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "from contextlib import nullcontext as raises\n", encoding="utf-8"
    )
    (tmp_path / "case.py").write_text(
        "from pytest import raises\n"
        "from helpers import *\n"
        "def test_behavior():\n"
        "    with raises(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_invalidates_oracle_alias_after_branch_star_import(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "from contextlib import nullcontext as raises\n", encoding="utf-8"
    )
    (tmp_path / "case.py").write_text(
        "from pytest import raises\n"
        "if USE_HELPERS:\n"
        "    from helpers import *\n"
        "def test_behavior():\n"
        "    with raises(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "binding",
    [
        "try:\n    compute_value()\nexcept Exception as expect_error:\n    pass",
        "match event:\n    case {'error': expect_error}:\n        pass",
    ],
)
def test_security_scan_does_not_trust_captured_pytest_raises_alias(tmp_path, binding):
    (tmp_path / "case.py").write_text(
        "from pytest import raises as expect_error\n"
        "def test_behavior(event):\n"
        f"    {binding.replace(chr(10), chr(10) + '    ')}\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_unused_assertion_callback(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n"
        "    def fail_on_read(*args):\n"
        "        raise AssertionError('unexpected read')\n"
        "    compute_value()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_cli_applies_explicit_tenant_contract(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "def fetch(record_id):\n    return store.fetch(record_id)\n"
    )
    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 1
    missing_contract = json.loads(capsys.readouterr().out)
    assert missing_contract["state"] == "INCOMPLETE"
    assert missing_contract["tenant_read_contract"]["configuration"]["state"] == (
        "missing"
    )
    assert "Tenant isolation remains unassessed" in missing_contract["action_summary"]
    assert (
        main(
            [
                "audit",
                "security",
                "--root",
                str(tmp_path),
                "--tenant-read-call",
                "store.fetch",
                "--json",
            ]
        )
        == 2
    )
    result = json.loads(capsys.readouterr().out)
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "def fetch(record_id, organization_scope):\n"
        "    return store.fetch(record_id, organization_scope)\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "audit",
                "security",
                "--root",
                str(tmp_path),
                "--tenant-read-call",
                "store.fetch",
                "--tenant-read-binding",
                "store.fetch=position:1:organization_scope",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["state"] == "CLEAN"


def test_security_cli_loads_project_contract_for_original_tenant_cases(
    tmp_path, capsys
):
    factory_dir = tmp_path / ".factory"
    factory_dir.mkdir()
    contract_path = factory_dir / "tenant-read-contract.json"
    contract_path.write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v1",
                "reads": [
                    {
                        "call": "store.fetch",
                        "binding": "keyword:tenant_id:org_scope",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    source_path = tmp_path / "app.py"
    source_path.write_text(
        "def unscoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=record_id)\n\n"
        "def scoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n",
        encoding="utf-8",
    )

    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}
    assert result["tenant_read_contract"]["configuration"]["state"] == "loaded"
    assert result["tenant_read_contract"]["configuration"]["sha256"]

    source_path.write_text(
        "def unscoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n\n"
        "def scoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n",
        encoding="utf-8",
    )
    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "CLEAN"
    assert result["tenant_read_contract"]["configuration"]["path"] == (
        ".factory/tenant-read-contract.json"
    )


def test_tenant_read_contract_rejects_unknown_fields_and_duplicate_calls(tmp_path):
    folder = tmp_path / ".factory"
    folder.mkdir()
    path = folder / "tenant-read-contract.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v1",
                "reads": [{"call": "store.fetch", "extra": True}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="Each tenant read requires"):
        load_tenant_read_contract(tmp_path)

    path.write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v1",
                "reads": [
                    {"call": "store.fetch"},
                    {"call": "store.fetch"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="calls must be unique"):
        load_tenant_read_contract(tmp_path)


def test_security_evals_cli_reports_fail_closed_contract(tmp_path, capsys):
    assert main(["audit", "evals", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "PASS"
    assert result["claim_boundary"].startswith("Fixed local AST evaluation")


def test_no_policy_is_not_a_pass_and_invalid_policy_fails_closed(tmp_path, capsys):
    assert (
        review_change(tmp_path, changed=["app.py"])["code_audits"]["state"]
        == "not_configured"
    )
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

    doc = (
        Path(__file__).resolve().parents[1] / "docs/CODE_REVIEW_AUDITS.md"
    ).read_text(encoding="utf-8")
    (tmp_path / "app.py").write_text(
        re.search(r"```python\n(.*?)```", doc, re.S)[1], encoding="utf-8"
    )
    (tmp_path / "policy.json").write_text(
        re.search(r"```json\n(.*?)```", doc, re.S)[1], encoding="utf-8"
    )
    result = audit_code(tmp_path, "policy.json")
    assert result["results"][0]["state"] == "no_structural_findings"
    assert result["findings"][0]["code"] == "GUARD_PATH_BYPASS"


def test_duplicate_json_fields_rejected(tmp_path):
    path = workspace(tmp_path)
    path.write_text(
        path.read_text().replace(
            '"origin": "human_confirmed"',
            '"origin": "human_confirmed", "origin": "agent_proposed"',
        )
    )
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
    source.write_text(
        source.read_text().replace("def candidate", "async def candidate")
    )
    assert audit_code(tmp_path)["state"] == "no_structural_findings"


def test_dynamic_execution_is_incomplete(tmp_path):
    workspace(tmp_path, "require_auth()\nexec(payload)\nstore.delete()")
    assert audit_code(tmp_path)["state"] == "incomplete"


def test_github_delivery_preserves_findings_and_rejects_tampering(tmp_path):
    from factoryline.github_proof_review import (
        GitHubProofReviewError,
        render_github_proof_review,
    )

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
    paths = engine.simple_statement(
        ast.parse("require_auth(store.delete())").body[0], [_Path()]
    )
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


@pytest.mark.parametrize(
    "body",
    [
        "errors = []; errors.append(compute()); assert errors == []",
        "errors = []; alias = errors; alias.append(compute()); assert errors == []",
        "errors = []\n    for item in inputs:\n        errors.append(item)\n    assert errors == []",
        "errors = []; mutate(errors); assert errors == []",
    ],
)
def test_mutable_test_state_is_not_folded_across_calls(tmp_path, body):
    (tmp_path / "case.py").write_text("def test_behavior():\n    " + body + "\n")
    assert security_scan(tmp_path)["findings"] == []


def test_unmodified_container_constant_assertion_remains_hollow(tmp_path):
    (tmp_path / "case.py").write_text(
        "def test_behavior():\n    errors = []\n    assert errors == []\n"
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "before,argument,expected",
    [
        ("", "principal.tenant_id", False),
        ("scope = principal.tenant_id", "scope", False),
        ("alias = principal", "alias.tenant_id", False),
        ("principal = other", "principal.tenant_id", True),
        ("principal.tenant_id = other", "principal.tenant_id", True),
        ("alias = principal\nalias.tenant_id = other", "principal.tenant_id", True),
        ("if ready:\n    principal = other", "principal.tenant_id", True),
        ("if ready:\n    principal.tenant_id = other", "principal.tenant_id", True),
        ("setattr(principal, 'tenant_id', other)", "principal.tenant_id", True),
        ("principal.tenant_id[0] = other", "principal.tenant_id", True),
        (
            "alias = principal\nsetattr(alias, 'tenant_id', other)",
            "principal.tenant_id",
            True,
        ),
        ("", "other.tenant_id", True),
        ("", "principal.organization_id", True),
        ("", "principal.tenant_id()", True),
        ("", "principal[tenant_id]", True),
    ],
)
def test_tenant_attribute_binding_rejects_rebinding_and_wrong_scope(
    tmp_path, before, argument, expected
):
    body = "\n".join("    " + line for line in before.splitlines())
    (tmp_path / "app.py").write_text(
        f"def read(principal, other, ready):\n{body}\n    return store.fetch({argument})\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=position:0:principal.tenant_id",),
    )
    assert bool(result["findings"]) is expected
    assert all(
        item["code"] == "SECURITY_MISSING_TENANT_ISOLATION"
        for item in result["findings"]
    )


def test_scoped_tenant_contract_keeps_other_files_in_security_scan(tmp_path):
    from factoryline.review_audits import load_tenant_read_contract

    (tmp_path / "app.py").write_text(
        "def read(principal):\n    return store.fetch(principal.tenant_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "other.py").write_text(
        "def test_hollow():\n    assert True\n", encoding="utf-8"
    )
    path = tmp_path / ".factory"
    path.mkdir()
    (path / "tenant-read-contract.json").write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v2",
                "reads": [
                    {
                        "path": "app.py",
                        "reads": [
                            {
                                "call": "store.fetch",
                                "binding": "position:0:principal.tenant_id",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    calls, bindings, evidence = load_tenant_read_contract(tmp_path)
    result = security_scan(
        tmp_path,
        tenant_read_calls=calls,
        tenant_read_bindings=bindings,
        tenant_read_scopes=evidence["scoped_reads"],
    )
    assert result["files_scanned"] == 2
    assert [item["code"] for item in result["findings"]] == ["QUALITY_HOLLOW_TEST"]
    assert evidence["state"] == "loaded"


@pytest.mark.parametrize(
    "path,call", [("missing.py", "store.fetch"), ("app.py", "store.typo")]
)
def test_scoped_tenant_contract_rejects_missing_source_or_read(tmp_path, path, call):
    from factoryline.review_audits import load_tenant_read_contract

    (tmp_path / "app.py").write_text(
        "def read(tenant_id):\n    return store.fetch(tenant_id)\n", encoding="utf-8"
    )
    folder = tmp_path / ".factory"
    folder.mkdir()
    (folder / "tenant-read-contract.json").write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v2",
                "reads": [
                    {
                        "path": path,
                        "reads": [{"call": call, "binding": "position:0:tenant_id"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="unique existing|absent from"):
        load_tenant_read_contract(tmp_path)

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

import pytest

from factoryline.deep_audit_contract import (
    PLAN_SCHEMA,
    PLAN_TYPE,
    verify_deep_audit_plan,
)
from factoryline.deep_audit_io import digest
from factoryline.enterprise_receipts import (
    generate_key_material,
    sign_payload,
    EnterpriseReceiptError,
)
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes


def fixture(tmp_path, mutate=lambda p: None):
    bindings = {}
    for name, raw in (
        ("app.py", b"one\ntwo"),
        ("scan.json", b'{"scan":1}'),
        ("canary.json", b'{"scan":2}'),
    ):
        (tmp_path / name).write_bytes(raw)
        bindings[name] = {"path": name, "sha256": sha256_bytes(raw)}
    sources = [{**bindings["app.py"], "bytes": 7}]
    now = datetime.now(timezone.utc)
    plan = {
        "schema": PLAN_SCHEMA,
        "id": "audit",
        "candidate_sha256": digest(sources),
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "sources": sources,
        "analyzers": [
            {
                "id": "s",
                "driver": "Example",
                "version": "1",
                "report": bindings["scan.json"],
                "canary_report": bindings["canary.json"],
            }
        ],
        "rules": [
            {
                "id": "r",
                "obligation_id": "no-leak",
                "category": "memory",
                "severity": "high",
                "aliases": [{"analyzer_id": "s", "rule_id": "leak"}],
                "max_new": 0,
                "max_total": 0,
                "min_trace_steps": 2,
                "require_source_sink": True,
                "allowed_suppressions": [],
                "origin": "human_confirmed",
                "remediation": "Close owned resources",
                "consequence": "Retained memory",
            }
        ],
        "canaries": [
            {
                "id": "c",
                "analyzer_id": "s",
                "rule_id": "leak",
                "fingerprint_sha256": "a" * 64,
            }
        ],
    }
    mutate(plan)
    material = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="owner",
        identity="owner@example.test",
        issuer="https://issuer.example.test",
    )
    envelope = sign_payload(
        plan,
        payload_type=PLAN_TYPE,
        private_key_path=Path(material["private_key"]),
        keyid=material["keyid"],
        identity=material["identity"],
        issuer=material["issuer"],
    )
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    trust = Path(material["trust_root"])
    return path, trust, sha256_bytes(trust.read_bytes()), tmp_path


def test_signature_sources_and_policy_are_bound(tmp_path):
    args = fixture(tmp_path)
    checked = verify_deep_audit_plan(*args)
    assert checked["authority"] == "none"
    assert len(checked["ruleset_sha256"]) == 64
    assert checked["source_hashes"]["app.py"] == sha256_bytes(b"one\ntwo")
    (tmp_path / "scan.json").write_text("tampered")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        verify_deep_audit_plan(*args)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda p: p["rules"][0].update(origin="agent_proposed"), "E_RULE_AUTHORITY"),
        (
            lambda p: p["rules"][0].update(origin="observed_production"),
            "E_RULE_AUTHORITY",
        ),
        (lambda p: p["rules"][0].update(max_new=True), "E_FIELD"),
        (lambda p: p.update(candidate_sha256="b" * 64), "E_CANDIDATE_DRIFT"),
        (lambda p: p.update(canaries=[]), "E_PLAN_FIELDS"),
        (lambda p: p["canaries"][0].update(rule_id="unknown"), "E_CANARY_POLICY"),
        (
            lambda p: p["analyzers"][0].update(
                canary_report=p["analyzers"][0]["report"]
            ),
            "E_DUPLICATE_ID",
        ),
        (lambda p: p.update(expires_at="2000-01-01T00:00:00+00:00"), "E_PLAN_EXPIRED"),
        (lambda p: p.update(issued_at="2020-01-01T00:00:00"), "E_TIME"),
        (lambda p: p.update(unapproved_exception=True), "E_PLAN_FIELDS"),
    ],
)
def test_signed_bad_contract_is_rejected(tmp_path, mutate, code):
    args = fixture(tmp_path, mutate)
    with pytest.raises(RuntimeAuditError, match=code):
        verify_deep_audit_plan(*args)


def test_wrong_pin_and_forged_signature(tmp_path):
    path, trust, pin, root = fixture(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_TRUST_ROOT_DRIFT"):
        verify_deep_audit_plan(path, trust, "0" * 64, root)
    envelope = json.loads(path.read_text())
    envelope["signatures"][0]["sig"] = "AAAA"
    path.write_text(json.dumps(envelope))
    with pytest.raises((EnterpriseReceiptError, RuntimeAuditError)):
        verify_deep_audit_plan(path, trust, pin, root)


def test_verified_contract_drives_real_report_normalization(tmp_path):
    from test_deep_audit_sarif import report
    from factoryline.deep_audit_sarif import normalize_sarif

    def bind_reports(plan):
        for key, name in (("report", "scan.json"), ("canary_report", "canary.json")):
            payload = report()
            result = payload["runs"][0]["results"][0]
            result["ruleId"] = "leak"
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "leak"
            result["partialFingerprints"]["primary/v1"] = key
            raw = json.dumps(payload).encode()
            (tmp_path / name).write_bytes(raw)
            plan["analyzers"][0][key]["sha256"] = sha256_bytes(raw)
        plan["canaries"][0]["fingerprint_sha256"] = digest(
            {"partialFingerprints:primary/v1": "canary_report"}
        )

    verified = verify_deep_audit_plan(*fixture(tmp_path, bind_reports))
    analyzer = verified["plan"]["analyzers"][0]
    target = normalize_sarif(
        tmp_path, analyzer["report"], analyzer, verified["source_hashes"]
    )
    canary = normalize_sarif(
        tmp_path, analyzer["canary_report"], analyzer, verified["source_hashes"]
    )
    assert target["findings"][0]["rule_id"] == "leak"
    assert (
        canary["findings"][0]["native_fingerprint_sha256"]
        == verified["plan"]["canaries"][0]["fingerprint_sha256"]
    )
    assert target["authority"] == "none"


# Execution fixtures deliberately use local test keys and synthetic scanner output.
# They test orchestration and rejection behavior, never real security coverage.
def execution_fixture(tmp_path):
    import subprocess
    from factoryline.deep_audit_io import inventory_candidate

    root = tmp_path / "workspace"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "app.py").write_text("print(1)\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    control = tmp_path / "control"
    control.mkdir()
    material = {}
    keys = []
    for role in ("implementer", "reviewer", "coordinator"):
        entry = generate_key_material(
            out_dir=control / role,
            keyid=role,
            identity=f"{role}@example.test",
            issuer="https://test.invalid",
        )
        material[role] = entry
        key = json.loads(Path(entry["trust_root"]).read_text())["keys"][0]
        key["roles"] = [role]
        keys.append(key)
    trust = control / "trust.json"
    template = json.loads(Path(material["coordinator"]["trust_root"]).read_text())
    template["keys"] = keys
    trust.write_text(json.dumps(template), encoding="utf-8")
    (root / "clean.py").write_text("print('clean')\n", encoding="utf-8")
    inventory = inventory_candidate(root)
    assert inventory["state"] == "COMPLETE"
    families = {
        "codeql": "static",
        "syft": "dependencies",
        "osv": "dependencies",
        "gitleaks": "secrets",
        "trivy": "configuration",
        "runtime": "runtime",
        "atheris": "fuzz",
    }
    lanes = []
    for engine, family in families.items():
        mode = "interprocedural-full" if family == "static" else "full"
        lanes.append(
            {
                "id": engine,
                "engine": engine,
                "family": family,
                "image": f"example.test/{engine}@sha256:" + "a" * 64,
                "argv": ["/opt/factory/bin/audit-adapter", engine, "--mode", mode],
                "report": "report.json",
                "coverage": "coverage.json",
                "challenge_report": "challenges.json",
                "languages": ["python"],
                "mode": mode,
                "timeout_seconds": 10,
                "memory_mib": 128,
                "tool_version": "1.0",
                "ruleset_sha256": "b" * 64,
            }
        )
    plan = {
        "schema": "factory.deep-execution.v1",
        "candidate_sha256": inventory["candidate_sha256"],
        "implementer_id": "implementer@example.test",
        "implementer_keyid": "implementer",
        "reviewer_identity": "reviewer@example.test",
        "reviewer_keyid": "reviewer",
        "coordinator_identity": "coordinator@example.test",
        "coordinator_keyid": "coordinator",
        "trust_root_sha256": sha256_bytes(trust.read_bytes()),
        "lanes": lanes,
        "obligations": [
            {
                "id": engine,
                "engine": engine,
                "detector_rule_id": "fixture-detection",
                "family": family,
                "paths": ["app.py", "clean.py"],
                "requirements": ["app.py"],
                "remediation": "Exercise and verify the boundary.",
            }
            for engine, family in families.items()
        ],
    }
    for obligation in plan["obligations"]:
        lane = next(item for item in lanes if item["engine"] == obligation["engine"])
        obligation["challenges"] = []
        for kind in ("positive", "negative", "mutation"):
            report = execution_challenge(lane, inventory, kind)
            obligation["challenges"].append(
                {
                    "kind": kind,
                    "fixture_path": "clean.py" if kind == "negative" else "app.py",
                    "fixture_sha256": report["fixture_sha256"],
                    "expected_report_sha256": digest(report),
                    "expected_exit_code": 0,
                }
            )
    manifest = control / "manifest.json"
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    pin = sha256_bytes(manifest.read_bytes())
    now = datetime.now(timezone.utc)
    payload = {
        "schema": "factory.deep-execution-authorization.v1",
        "manifest_sha256": pin,
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_content_sha256": digest(plan),
        "adapter_images": {lane["id"]: lane["image"] for lane in lanes},
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=50)).isoformat(),
        "authority": "none",
    }
    authorization = execution_sign(
        control / "authorization.json", payload, material["coordinator"]
    )
    return root, manifest, pin, authorization, trust, plan, inventory, material


def execution_sign(path, payload, key):
    envelope = sign_payload(
        payload,
        payload_type=f"application/vnd.{payload['schema']}+json",
        private_key_path=Path(key["private_key"]),
        keyid=key["keyid"],
        identity=key["identity"],
        issuer=key["issuer"],
    )
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return path


def execution_native(lane, inventory, detected=False):
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    rule = "fixture-detection"
    if lane["engine"] in {"codeql", "gitleaks", "trivy", "semgrep"}:
        result = {
            "ruleId": rule,
            "level": "error",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": lane["engine"],
                            "version": lane["tool_version"],
                        }
                    },
                    "invocations": [{"executionSuccessful": True}],
                    "results": [result] if detected else [],
                }
            ],
        }
    if lane["engine"] == "syft":
        return {
            "artifacts": [
                {
                    "id": rule if detected else "ordinary-component",
                    "name": "fixture",
                    "version": "1.0",
                    "type": "python",
                    "locations": [{"path": "/src/" + path} for path in sources],
                }
            ],
            "descriptor": {"name": "syft", "version": "1.0"},
            "schema": {"version": "16.0.0"},
            "source": {"type": "directory", "target": "/src"},
        }
    if lane["engine"] == "osv":
        return {
            "results": [
                {
                    "source": {"path": path},
                    "packages": [
                        {
                            "package": {
                                "name": "fixture",
                                "version": "1.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [{"id": rule}] if detected else [],
                        }
                    ],
                }
                for path in sources
            ]
        }
    return {
        "schema": f"factory.deep-{lane['engine']}-observations.v1",
        "engine": lane["engine"],
        "tool_version": lane["tool_version"],
        "completed": True,
        "errors": [],
        "harness": {"path": "app.py", "sha256": sources["app.py"]},
        "metrics": {
            "tests": 1,
            "requests": 1,
            "executions": 1000,
            "coverage_edges": 10,
            "corpus_size": 5,
        },
        "source_coverage": {
            path: {
                "sha256": value,
                "lines_total": 1,
                "lines_covered": 1,
                "branches_total": 0,
                "branches_covered": 0,
            }
            for path, value in sources.items()
        },
        "findings": [{"rule_id": rule, "path": "app.py", "line": 1, "severity": "high"}]
        if detected
        else [],
    }


def execution_challenge(lane, inventory, kind):
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    return {
        "schema": "factory.deep-challenge-observation.v1",
        "engine": lane["engine"],
        "fixture_sha256": sources["clean.py" if kind == "negative" else "app.py"],
        "detector_rule_id": "fixture-detection",
        "detector_enabled": kind != "mutation",
        "native_report": execution_native(lane, inventory, detected=kind == "positive"),
    }


def execution_bundle(lane, inventory, run_id):
    report = execution_native(lane, inventory)
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": {item["path"]: item["sha256"] for item in inventory["files"]},
        "complete": True,
        "errors": [],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "tool_version": lane["tool_version"],
        "ruleset_sha256": lane["ruleset_sha256"],
        "invocation_sha256": "d" * 64,
        "obligations": [lane["engine"]],
    }
    observations = []
    for kind in ("positive", "negative", "mutation"):
        challenge = execution_challenge(lane, inventory, kind)
        observations.append(
            {
                "obligation_id": lane["engine"],
                "kind": kind,
                "fixture_sha256": challenge["fixture_sha256"],
                "observation_sha256": digest(challenge),
                "report": challenge,
                "exit_code": 0,
            }
        )
    return {
        "schema": "factory.deep-worker.v1",
        "candidate_sha256": inventory["candidate_sha256"],
        "run_id": run_id,
        "artifacts": {
            "report.json": report,
            "coverage.json": coverage,
            "challenges.json": {
                "schema": "factory.deep-challenges.v1",
                "observations": observations,
            },
        },
    }


def test_execution_manifest_and_signed_authorization(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest
    from factoryline.deep_audit_attestation import verify_execution_authorization

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    assert load_execution_manifest(manifest, pin) == plan
    assert (
        verify_execution_authorization(
            plan, pin, authorization, trust, plan["trust_root_sha256"]
        )["candidate_sha256"]
        == plan["candidate_sha256"]
    )
    with pytest.raises(RuntimeAuditError):
        verify_execution_authorization(
            plan, "0" * 64, authorization, trust, plan["trust_root_sha256"]
        )
    plan["lanes"][0]["argv"] = ["sh", "-c", "true"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TEMPLATE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def test_inventory_accounts_ignored_deleted_unknown_and_dirty_inputs(tmp_path):
    from factoryline.deep_audit_io import inventory_candidate

    root, *rest = execution_fixture(tmp_path)
    original = inventory_candidate(root)
    (root / "app.py").write_text("print(2)\n", encoding="utf-8")
    assert inventory_candidate(root)["candidate_sha256"] != original["candidate_sha256"]
    (root / ".gitignore").write_text("hidden.py\n", encoding="utf-8")
    (root / "hidden.py").write_text("secret=1", encoding="utf-8")
    (root / "unknown.xyz").write_text("code", encoding="utf-8")
    (root / "app.py").unlink()
    result = inventory_candidate(root)
    assert result["state"] == "INCOMPLETE"
    assert "hidden.py" in result["ignored_paths"]
    assert {item["code"] for item in result["gaps"]} >= {
        "IGNORED_INPUT_SCOPE",
        "E_SOURCE_MISSING",
        "UNCLASSIFIED_INPUT",
    }


def test_snapshot_rejects_inside_source_and_detects_capture_drift(
    tmp_path, monkeypatch
):
    import factoryline.deep_audit_io as module

    root, *rest = execution_fixture(tmp_path)
    inside = root / "snapshot"
    inside.mkdir()
    with pytest.raises(RuntimeAuditError, match="E_SNAPSHOT_PATH"):
        module.inventory_candidate(root, inside)
    inside.rmdir()
    original = module._source_bytes
    calls = 0

    def changing(root, name):
        nonlocal calls
        raw, mode = original(root, name)
        calls += 1
        if calls == 1:
            (root / name).write_bytes(b"print(3)\n")
        return raw, mode

    monkeypatch.setattr(module, "_source_bytes", changing)
    result = module.inventory_candidate(root)
    assert "SOURCE_DRIFT" in {gap["code"] for gap in result["gaps"]}


def test_execution_rejects_parser_downgrade_and_missing_mutations(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = plan["lanes"][0]
    bundle = execution_bundle(lane, inventory, "0" * 32)
    assert (
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )["state"]
        == "OBSERVED"
    )
    bundle["artifacts"]["coverage.json"]["fallback"] = True
    bundle["artifacts"]["challenges.json"]["observations"].pop()
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert set(result["gaps"]) >= {
        "ANALYSIS_MODE_DOWNGRADE",
        "CHALLENGE_COVERAGE_MISSING",
    }
    bundle["candidate_sha256"] = "0" * 64
    with pytest.raises(RuntimeAuditError, match="E_WORKER_BINDING"):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


def test_scan_missing_engine_is_incomplete_with_durable_progress(tmp_path, monkeypatch):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)

    def unavailable():
        raise RuntimeAuditError("E_DOCKER_UNAVAILABLE", "fixture unavailable")

    monkeypatch.setattr(module, "_docker_base", unavailable)
    events = []
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
        emit=events.append,
    )
    assert result["state"] == "INCOMPLETE"
    assert not result["analysis_complete"]
    assert len(result["lanes"]) == 7
    assert events[0]["kind"] == "run_started"
    assert events[-1]["kind"] == "run_completed"
    assert all(lane["gaps"] == ["E_DOCKER_UNAVAILABLE"] for lane in result["lanes"])
    assert module.deep_run_status(root, result["run_id"])["state"] == "INCOMPLETE"
    assert len(module.execution_repairs(root, result["run_id"])["coverage_tasks"]) == 7


def test_scan_never_executes_with_different_candidate(tmp_path, monkeypatch):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    (root / "app.py").write_text("print(4)\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "_docker_base",
        lambda: pytest.fail("execution before candidate binding"),
    )
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert "CANDIDATE_DRIFT" in {gap["code"] for gap in result["gaps"]}
    assert result["lanes"] == []


def test_container_contract_removes_privileges_and_host_execution(tmp_path):
    from factoryline.deep_audit import _container_argv

    _, _, _, _, _, plan, _, _ = execution_fixture(tmp_path)
    command = _container_argv(
        ["docker"], plan["lanes"][0], tmp_path, "test", "0" * 32, "1" * 64
    )
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pull=never",
    ):
        assert flag in command
    assert not any(
        "docker.sock" in value or value == "--privileged" for value in command
    )


@pytest.mark.parametrize("engine", ["codeql", "syft", "osv"])
def test_execution_native_errors_cannot_pass(tmp_path, engine):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert result["state"] == "OBSERVED"
    assert result["obligations"] == [lane["engine"]]
    report = bundle["artifacts"]["report.json"]
    if engine == "codeql":
        report["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": "partial"}}
        ]
    else:
        report["errors"] = ["partial"]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    with pytest.raises(RuntimeAuditError):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


@pytest.mark.parametrize("change", ["golden", "fixture", "exit", "boolean"])
def test_execution_challenges_require_bound_evidence(tmp_path, change):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = plan["lanes"][0]
    bundle = execution_bundle(lane, inventory, "0" * 32)
    challenge = bundle["artifacts"]["challenges.json"]["observations"][0]
    if change == "golden":
        challenge["report"] = {"result": "made up"}
        challenge["observation_sha256"] = digest(challenge["report"])
    elif change == "fixture":
        challenge["fixture_sha256"] = "0" * 64
    elif change == "exit":
        challenge["exit_code"] = True
    else:
        challenge.pop("report")
        challenge["passed"] = True
    try:
        result = normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )
    except RuntimeAuditError:
        assert change in {"boolean", "golden"}
    else:
        assert result["state"] == "INCOMPLETE"
        assert "CHALLENGE_FAILED" in result["gaps"]


def synthetic_execution(tmp_path, monkeypatch):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import write_run_json
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    args = execution_fixture(tmp_path)
    root, manifest, pin, authorization, trust, plan, _, _ = args

    def execute(root, directory, state, snapshot, lane, inventory, plan, emit):
        bundle = execution_bundle(lane, inventory, state["run_id"])
        result = normalize_execution_bundle(
            bundle, lane, inventory, state["run_id"], plan["obligations"]
        )
        write_run_json(directory, f"bundle-{lane['id']}.json", bundle)
        result.update(
            bundle_sha256=digest(bundle),
            execution={
                "exit_code": 0,
                "cleanup_confirmed": True,
                "timed_out": False,
                "output_limit_exceeded": False,
                "launch_error": False,
                "cancelled": False,
            },
        )
        return result

    monkeypatch.setattr(module, "_execute_lane", execute)
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert result["analysis_complete"], result["gaps"]
    assert (
        result["state"] == "INCOMPLETE"
    )  # Synthetic observations alone never approve.
    return args, result


def review_documents(tmp_path, args, evidence, findings=None, gaps=None):
    root, _, pin, _, _, plan, inventory, material = args
    now = datetime.now(timezone.utc)
    common = {
        "run_id": evidence["run_id"],
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_sha256": pin,
        "evidence_sha256": digest(evidence),
        "read_set_sha256": digest(inventory["files"]),
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=40)).isoformat(),
        "authority": "none",
        "provider": "fixture-only",
        "model": "synthetic",
        "invocation_id": "fixture",
        "specialty": "security",
        "prompt_sha256": "1" * 64,
        "response_sha256": "2" * 64,
    }
    review = {
        **common,
        "schema": "factory.deep-specialty-review.v1",
        "decision": "ACCEPT",
        "findings": findings or [],
        "coverage_gaps": gaps or [],
    }
    invocation = {
        **common,
        "schema": "factory.deep-review-invocation.v1",
        "read_only": True,
        "review_payload_sha256": digest(review),
    }
    return (
        execution_sign(tmp_path / "review.json", review, material["reviewer"]),
        execution_sign(
            tmp_path / "invocation.json", invocation, material["coordinator"]
        ),
    )


@pytest.mark.parametrize("disposition", ["accept", "high", "gap"])
def test_specialty_review_reconciles_its_own_findings(
    tmp_path, monkeypatch, disposition
):
    from factoryline.deep_audit_attestation import verify_execution_review

    args, result = synthetic_execution(tmp_path, monkeypatch)
    findings = (
        [
            {
                "id": "review-1",
                "severity": "high",
                "path": "app.py",
                "evidence": "fixture",
                "remediation": "repair",
            }
        ]
        if disposition == "high"
        else []
    )
    gaps = ["missing runtime observation"] if disposition == "gap" else []
    attestation, invocation = review_documents(tmp_path, args, result, findings, gaps)
    reviewed = verify_execution_review(
        args[0],
        result["run_id"],
        attestation,
        invocation,
        args[4],
        args[5]["trust_root_sha256"],
    )
    assert (
        reviewed["state"]
        == {"accept": "READY_FOR_HUMAN_REVIEW", "high": "BLOCKED", "gap": "INCOMPLETE"}[
            disposition
        ]
    )
    assert reviewed["specialty_ai_review"] == "COORDINATOR_ATTESTED"
    assert reviewed["authority"] == "none" and not reviewed["release_approval"]


def test_progress_detects_earlier_event_tamper(tmp_path, monkeypatch):
    from factoryline.deep_audit import deep_run_status
    from factoryline.deep_audit_io import read_run_json, write_run_json, run_directory

    args, result = synthetic_execution(tmp_path, monkeypatch)
    directory = run_directory(args[0], result["run_id"])
    event = read_run_json(directory, "event-00001.json")
    event["details"] = {"changed": True}
    write_run_json(directory, "event-00001.json", event)
    with pytest.raises(RuntimeAuditError, match="E_EVENT_INTEGRITY"):
        deep_run_status(args[0], result["run_id"])


def test_execution_role_trust_cannot_be_self_declared(tmp_path):
    from factoryline.deep_audit_attestation import _execution_keys

    _, _, _, _, trust, plan, _, _ = execution_fixture(tmp_path)
    value = json.loads(trust.read_text())
    value["keys"][1]["roles"] = ["implementer"]
    trust.write_text(json.dumps(value))
    with pytest.raises(RuntimeAuditError, match="E_REVIEW_TRUST"):
        _execution_keys(plan, trust)


@pytest.mark.parametrize("engine", ["syft", "osv"])
def test_native_dependency_reports_cannot_omit_declared_input(tmp_path, engine):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    if engine == "syft":
        report["artifacts"][0]["locations"].pop()
    else:
        report["results"].pop()
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    with pytest.raises(RuntimeAuditError, match="E_DEPENDENCY_COVERAGE"):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


@pytest.mark.parametrize("engine", ["runtime", "atheris"])
@pytest.mark.parametrize("failure", ["generic", "zero", "coverage"])
def test_runtime_evidence_requires_engine_execution_and_source_depth(
    tmp_path, engine, failure
):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    if failure == "generic":
        report["schema"] = "factory.runtime-observations.v1"
    elif failure == "zero":
        report["metrics"] = {key: 0 for key in report["metrics"]}
    else:
        report["source_coverage"]["app.py"]["lines_covered"] = 0
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    with pytest.raises(RuntimeAuditError):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


def test_signed_golden_cannot_replace_positive_detection_semantics(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = plan["lanes"][0]
    bundle = execution_bundle(lane, inventory, "0" * 32)
    challenge = bundle["artifacts"]["challenges.json"]["observations"][0]
    challenge["report"]["native_report"]["runs"][0]["results"] = []
    challenge["observation_sha256"] = digest(challenge["report"])
    plan["obligations"][0]["challenges"][0]["expected_report_sha256"] = challenge[
        "observation_sha256"
    ]
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_SEMANTICS"):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )

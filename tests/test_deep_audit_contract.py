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


@pytest.mark.parametrize("prefix", ["", "example/adapter@"])
def test_full_local_image_id_and_repository_digest_are_immutable_pins(prefix):
    from factoryline.deep_audit_contract import _validate_lane_image

    assert _validate_lane_image({"image": prefix + "sha256:" + "a" * 64}) is None


@pytest.mark.parametrize(
    "image",
    [
        "example/adapter:latest",
        "example/adapter:v1",
        "sha256:" + "a" * 63,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 64 + ":tag",
        "sha256:" + "a" * 64 + "\n",
        "a" * 64,
    ],
)
def test_mutable_or_ambiguous_image_references_are_rejected(image):
    from factoryline.deep_audit_contract import _validate_lane_image

    code = "E_FIELD" if "\n" in image else "E_IMAGE_PIN"
    with pytest.raises(RuntimeAuditError, match=code):
        _validate_lane_image({"image": image})


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
    "revocation", [{"revoked": True}, {"revoked_at": "2026-01-01T00:00:00Z"}]
)
def test_plan_rejects_revoked_signer(tmp_path, revocation):
    path, trust, _, root = fixture(tmp_path)
    value = json.loads(trust.read_text())
    value["keys"][0].update(revocation)
    trust.write_text(json.dumps(value))
    with pytest.raises(RuntimeAuditError, match="E_PLAN_SIGNER_REVOKED"):
        verify_deep_audit_plan(path, trust, sha256_bytes(trust.read_bytes()), root)


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
                **({"rule_ids": ["fixture-detection"]} if engine == "gitleaks" else {}),
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


def test_osv_coordinator_recomputes_native_accounting_and_rejects_drift():
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [],
                    },
                    {
                        "package": {
                            "name": "werkzeug",
                            "version": "0.1",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [],
                    },
                ],
            }
        ]
    }
    required = {"requirements.txt": "a" * 64}
    lane = {"engine": "osv", "mode": "offline-pypi-snapshot"}
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": required,
        "complete": True,
        "errors": [],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "source_accounting": _osv_source_accounting(report, required, lane["mode"]),
    }
    assert "OSV_SOURCE_ACCOUNTING_DRIFT" not in _coverage_source_gaps(
        report, coverage, lane, required
    )

    sabotages = []
    forged = json.loads(json.dumps(coverage))
    forged["source_accounting"]["state"] = "COMPLETE_WITH_AUTHORITY"
    sabotages.append((report, forged, required))
    reordered = json.loads(json.dumps(coverage))
    reordered["source_accounting"]["sources"]["requirements.txt"]["packages"].reverse()
    sabotages.append((report, reordered, required))
    count_changed = json.loads(json.dumps(coverage))
    count_changed["source_accounting"]["sources"]["requirements.txt"][
        "package_count"
    ] += 1
    sabotages.append((report, count_changed, required))
    identity_report = json.loads(json.dumps(report))
    identity_report["results"][0]["packages"][0]["package"]["version"] = "9.9"
    identity_coverage = json.loads(json.dumps(coverage))
    identity_coverage["report_sha256"] = digest(identity_report)
    sabotages.append((identity_report, identity_coverage, required))
    changed_required = {"requirements.txt": "b" * 64}
    hash_coverage = json.loads(json.dumps(coverage))
    hash_coverage["sources"] = changed_required
    hash_coverage["report_sha256"] = digest(report)
    sabotages.append((report, hash_coverage, changed_required))

    for altered_report, altered_coverage, altered_required in sabotages:
        gaps = _coverage_source_gaps(
            altered_report, altered_coverage, lane, altered_required
        )
        assert "OSV_SOURCE_ACCOUNTING_DRIFT" in gaps


def test_osv_coordinator_keeps_synthetic_empty_result_incomplete():
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = {"results": []}
    required = {"requirements.txt": "a" * 64}
    lane = {"engine": "osv", "mode": "offline-pypi-snapshot"}
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": required,
        "complete": False,
        "errors": [
            "NATIVE_SOURCE_ACCOUNTING_REQUIRED",
            "NATIVE_CHALLENGES_REQUIRED",
        ],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "source_accounting": _osv_source_accounting(report, required, lane["mode"]),
    }
    gaps = _coverage_source_gaps(report, coverage, lane, required)
    assert "OSV_SOURCE_ACCOUNTING_DRIFT" not in gaps
    assert "ANALYZER_INCOMPLETE" in gaps
    assert coverage["source_accounting"]["state"] == "UNAVAILABLE"


def test_osv_coordinator_rejects_boolean_and_float_package_counts():
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [],
                    }
                ],
            }
        ]
    }
    required = {"requirements.txt": "a" * 64}
    lane = {"engine": "osv", "mode": "offline-pypi-snapshot"}
    account = _osv_source_accounting(report, required, lane["mode"])
    for forged_count in (True, 1.0):
        forged = json.loads(json.dumps(account))
        forged["sources"]["requirements.txt"]["package_count"] = forged_count
        coverage = {
            "schema": "factory.deep-coverage.v1",
            "sources": required,
            "complete": True,
            "errors": [],
            "mode": lane["mode"],
            "fallback": False,
            "report_sha256": digest(report),
            "source_accounting": forged,
        }
        assert "OSV_SOURCE_ACCOUNTING_DRIFT" in _coverage_source_gaps(
            report, coverage, lane, required
        )


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
    _, envelope_hash = verify_execution_authorization(
        plan,
        pin,
        authorization,
        trust,
        plan["trust_root_sha256"],
        return_envelope_sha256=True,
    )
    assert envelope_hash == digest(json.loads(authorization.read_text("utf-8")))
    with pytest.raises(RuntimeAuditError):
        verify_execution_authorization(
            plan, "0" * 64, authorization, trust, plan["trust_root_sha256"]
        )
    plan["lanes"][0]["argv"] = ["sh", "-c", "true"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TEMPLATE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def _v2_execution_plan(plan, inventory):
    from factoryline.deep_audit_contract import V2_NATIVE_ROLES

    plan["schema"] = "factory.deep-execution.v2"
    for lane in plan["lanes"]:
        lane["native_artifact_roles"] = sorted(V2_NATIVE_ROLES[lane["engine"]])
        if lane["engine"] != "syft":
            lane["rule_ids"] = ["fixture-detection"]
            lane["mutation_config_sha256"] = {"fixture-detection": "c" * 64}
    plan["obligations"] = [
        item for item in plan["obligations"] if item["engine"] != "syft"
    ]
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    for obligation in plan["obligations"]:
        for challenge in obligation["challenges"]:
            path = challenge["fixture_path"]
            challenge["fixture_sha256"] = sources[path]
            challenge["fixture_manifest"] = {path: sources[path]}
            challenge["fixture_manifest_sha256"] = digest({path: sources[path]})
    return plan


def test_execution_manifest_v2_binds_roles_and_fixture_manifest(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    pin = sha256_bytes(manifest.read_bytes())
    assert load_execution_manifest(manifest, pin) == plan

    plan["lanes"][0]["native_artifact_roles"] = ["sarif_report"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_NATIVE_ROLE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def test_v2_trivy_native_policy_identity_is_optional_and_strict(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    trivy = next(lane for lane in plan["lanes"] if lane["engine"] == "trivy")
    original_ruleset = trivy["ruleset_sha256"]
    policy = {"config_sha256": "e" * 64, "baseline_ignore_sha256": "f" * 64}
    trivy["native_policy"] = policy
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    assert (
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes())) == plan
    )
    assert trivy["ruleset_sha256"] == original_ruleset

    del trivy["native_policy"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    assert (
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes())) == plan
    )

    invalid_policies = [
        {"config_sha256": "e" * 64},
        {"config_sha256": "e" * 64, "baseline_ignore_sha256": "f" * 64, "extra": "x"},
        {"config_sha256": "bad", "baseline_ignore_sha256": "f" * 64},
        {"config_sha256": None, "baseline_ignore_sha256": "f" * 64},
    ]
    for invalid_policy in invalid_policies:
        candidate = deepcopy(plan)
        next(lane for lane in candidate["lanes"] if lane["engine"] == "trivy")[
            "native_policy"
        ] = invalid_policy
        manifest.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(RuntimeAuditError):
            load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))

    for schema, engine in (
        ("factory.deep-execution.v2", "codeql"),
        ("factory.deep-execution.v1", "trivy"),
    ):
        candidate = deepcopy(plan)
        candidate["schema"] = schema
        next(lane for lane in candidate["lanes"] if lane["engine"] == engine)[
            "native_policy"
        ] = policy
        manifest.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(RuntimeAuditError):
            load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def _signed_osv_v2_plan(tmp_path):
    from factoryline.deep_audit_contract import _osv_suppression_bytes

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    lane["mode"] = "offline-pypi-snapshot"
    lane["argv"] = [
        "/opt/factory/bin/audit-adapter",
        "osv",
        "--mode",
        "offline-pypi-snapshot",
    ]
    detector = lane["rule_ids"][0]
    aliases = sorted([detector, "CVE-2026-0001", "GHSA-abcd-1234-efgh"])
    lane["native_policy"] = {
        "database_path": "/opt/factory/osv-db/osv-scanner/PyPI/all.zip",
        "database_sha256": lane["ruleset_sha256"],
        "baseline_config_sha256": sha256_bytes(b"\n"),
        "advisory_aliases": {detector: aliases},
    }
    lane["mutation_config_sha256"] = {
        detector: sha256_bytes(_osv_suppression_bytes(aliases))
    }
    target = {
        "package": "werkzeug",
        "ecosystem": "PyPI",
        "vulnerable_version": "0.16.1",
        "fixed_version": "0.16.2",
        "aliases": aliases,
    }
    next(item for item in plan["obligations"] if item["engine"] == "osv")[
        "osv_target"
    ] = target
    return manifest, plan, lane, target


def _write_and_load_signed_osv_plan(manifest, plan):
    from factoryline.deep_audit_contract import load_execution_manifest

    manifest.write_text(json.dumps(plan), encoding="utf-8")
    return load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def test_v2_signed_osv_policy_and_target_load_from_pinned_manifest(tmp_path):
    from factoryline.deep_audit_contract import _osv_suppression_bytes

    manifest, plan, lane, target = _signed_osv_v2_plan(tmp_path)
    loaded = _write_and_load_signed_osv_plan(manifest, plan)
    loaded_lane = next(item for item in loaded["lanes"] if item["engine"] == "osv")
    loaded_obligation = next(
        item for item in loaded["obligations"] if item["engine"] == "osv"
    )
    assert loaded_lane["native_policy"] == lane["native_policy"]
    assert loaded_lane["mutation_config_sha256"] == lane["mutation_config_sha256"]
    assert loaded_obligation["osv_target"] == target
    assert _osv_suppression_bytes(target["aliases"]) == (
        b'[[IgnoredVulns]]\nid = "CVE-2026-0001"\n\n'
        b'[[IgnoredVulns]]\nid = "GHSA-abcd-1234-efgh"\n\n'
        b'[[IgnoredVulns]]\nid = "fixture-detection"\n\n'
    )


def test_v1_osv_manifest_remains_valid_without_native_policy_or_target(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, _, _ = execution_fixture(tmp_path)
    osv = next(item for item in plan["lanes"] if item["engine"] == "osv")
    obligation = next(item for item in plan["obligations"] if item["engine"] == "osv")
    assert "native_policy" not in osv
    assert "osv_target" not in obligation
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    loaded = load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))
    assert loaded == plan


def test_v2_osv_policy_rejects_native_policy_and_target_sabotage(tmp_path):
    from copy import deepcopy

    from factoryline.deep_audit_contract import _osv_suppression_bytes

    manifest, plan, lane, target = _signed_osv_v2_plan(tmp_path)
    detector = lane["rule_ids"][0]

    mutations = []
    malformed_keys = deepcopy(plan)
    malformed_keys["lanes"][[item["engine"] for item in plan["lanes"]].index("osv")][
        "native_policy"
    ]["unexpected"] = True
    mutations.append(malformed_keys)

    for key, invalid in (
        ("database_path", "/src/osv-db/all.zip"),
        ("database_sha256", "0" * 64),
        ("baseline_config_sha256", "0" * 64),
    ):
        candidate = deepcopy(plan)
        osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
        osv["native_policy"][key] = invalid
        mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["native_policy"].pop("database_path")
    mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["native_policy"].pop("baseline_config_sha256")
    mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["native_policy"]["advisory_aliases"] = {"another-rule": ["another-rule"]}
    mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["mode"] = "online-pypi"
    mutations.append(candidate)

    target_mutations = []
    target_missing = deepcopy(plan)
    next(item for item in target_missing["obligations"] if item["engine"] == "osv").pop(
        "osv_target"
    )
    target_mutations.append(target_missing)
    policy_missing = deepcopy(plan)
    next(item for item in policy_missing["lanes"] if item["engine"] == "osv").pop(
        "native_policy"
    )
    target_mutations.append(policy_missing)

    for field, invalid in (
        ("ecosystem", "npm"),
        ("package", "Werkzeug"),
        ("package", "a--b"),
        ("package", "../werkzeug"),
        ("vulnerable_version", "0.16.1\n--config"),
        ("fixed_version", "0.16.1"),
        ("aliases", sorted(["CVE-2026-0002", detector, "GHSA-abcd-1234-efgh"])),
    ):
        candidate = deepcopy(plan)
        osv_target = next(
            item for item in candidate["obligations"] if item["engine"] == "osv"
        )["osv_target"]
        osv_target[field] = invalid
        target_mutations.append(candidate)

    for candidate in mutations + target_mutations:
        with pytest.raises(RuntimeAuditError):
            _write_and_load_signed_osv_plan(manifest, candidate)

    # Recomputed suppression hashes are required for every exact alias set.
    for aliases in (
        ["CVE-2026-0001", detector, "GHSA-abcd-1234-efgh"],
        ["CVE-2026-0001", "CVE-2026-0001", detector],
        ["CVE-2026-0001", "GHSA-abcd-1234-efgh"],
    ):
        candidate = deepcopy(plan)
        osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
        osv["native_policy"]["advisory_aliases"][detector] = aliases
        with pytest.raises(RuntimeAuditError):
            _write_and_load_signed_osv_plan(manifest, candidate)

    for mutation in (
        {},
        {"another-rule": "a" * 64},
        {detector: sha256_bytes(_osv_suppression_bytes(["CVE-2026-0002", detector]))},
        {detector: "not-a-digest"},
    ):
        candidate = deepcopy(plan)
        osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
        osv["mutation_config_sha256"] = mutation
        with pytest.raises(RuntimeAuditError):
            _write_and_load_signed_osv_plan(manifest, candidate)


def test_v2_osv_policy_rejects_cross_target_advisory_alias_overlap(tmp_path):
    from copy import deepcopy

    from factoryline.deep_audit_contract import _osv_suppression_bytes

    manifest, plan, _, _ = _signed_osv_v2_plan(tmp_path)
    candidate = deepcopy(plan)
    lane = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    first, second = sorted(["fixture-detection", "osv-secondary"])
    aliases_one = sorted([first, "CVE-2026-0001"])
    aliases_two = sorted([second, "CVE-2026-0001"])
    lane["rule_ids"] = [first, second]
    lane["native_policy"]["advisory_aliases"] = {
        first: aliases_one,
        second: aliases_two,
    }
    lane["mutation_config_sha256"] = {
        first: sha256_bytes(_osv_suppression_bytes(aliases_one)),
        second: sha256_bytes(_osv_suppression_bytes(aliases_two)),
    }
    target_obligation = next(
        item for item in candidate["obligations"] if item["engine"] == "osv"
    )
    target_obligation["detector_rule_id"] = first
    target_obligation["osv_target"]["aliases"] = aliases_one
    with pytest.raises(RuntimeAuditError, match="E_OSV_TARGET"):
        _write_and_load_signed_osv_plan(manifest, candidate)


@pytest.mark.parametrize("malformed", [None, [], 7])
def test_v2_osv_manifest_rejects_malformed_obligation_without_crashing(
    tmp_path, malformed
):
    from copy import deepcopy

    manifest, plan, _, _ = _signed_osv_v2_plan(tmp_path)
    candidate = deepcopy(plan)
    index = next(
        index
        for index, item in enumerate(candidate["obligations"])
        if item["engine"] == "osv"
    )
    candidate["obligations"][index] = malformed
    with pytest.raises(RuntimeAuditError):
        _write_and_load_signed_osv_plan(manifest, candidate)


@pytest.mark.parametrize("policy_enabled", [False, True])
def test_v2_osv_signed_policy_metadata_never_verifies_native_challenge(
    policy_enabled,
):
    from factoryline.deep_audit_sarif import _challenge_execution_v2_valid

    lane = {"engine": "osv"}
    if policy_enabled:
        lane["native_policy"] = {"database_path": "pinned"}
    assert not _challenge_execution_v2_valid(
        {"status": "VERIFIED", "native_artifacts": {}},
        {"report": {"native_report": {}}},
        {},
        {},
        ("obligation-osv", "positive"),
        lane,
        {"source_accounting": {"state": "COMPLETE"}},
        "a" * 64,
    )


def test_v2_role_tables_match_native_helper_and_report_roles():
    from factoryline.deep_audit_contract import V2_NATIVE_ROLES
    from factoryline.deep_audit_sarif import _NATIVE_REPORT_ROLES
    from factoryline.runtime_audit_common import (
        NATIVE_ARTIFACT_ROLES,
        NATIVE_REPORT_ROLE,
    )

    assert V2_NATIVE_ROLES == NATIVE_ARTIFACT_ROLES
    assert _NATIVE_REPORT_ROLES == NATIVE_REPORT_ROLE


def test_semgrep_pattern_limited_is_supplemental_to_full_static_lane(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _execution_lanes

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    supplemental = deepcopy(plan["lanes"][0])
    supplemental.update(
        id="semgrep",
        engine="semgrep",
        mode="pattern-limited",
        argv=[
            "/opt/factory/bin/audit-adapter",
            "semgrep",
            "--mode",
            "pattern-limited",
        ],
    )
    plan["lanes"].append(supplemental)
    _v2_execution_plan(plan, inventory)

    accepted = _execution_lanes(plan["lanes"], 2)

    assert any(
        lane["engine"] == "semgrep" and lane["mode"] == "pattern-limited"
        for lane in accepted
    )
    assert any(
        lane["family"] == "static" and lane["mode"] == "interprocedural-full"
        for lane in accepted
    )


def test_semgrep_pattern_limited_cannot_replace_full_static_lane(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _execution_lanes

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    supplemental = deepcopy(plan["lanes"][0])
    supplemental.update(
        id="semgrep",
        engine="semgrep",
        mode="pattern-limited",
        argv=[
            "/opt/factory/bin/audit-adapter",
            "semgrep",
            "--mode",
            "pattern-limited",
        ],
    )
    plan["lanes"].append(supplemental)
    _v2_execution_plan(plan, inventory)
    plan["lanes"] = [lane for lane in plan["lanes"] if lane["engine"] != "codeql"]

    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_DEPTH"):
        _execution_lanes(plan["lanes"], 2)


def test_pattern_limited_mode_remains_rejected_for_other_static_engines():
    from factoryline.deep_audit_contract import _validate_lane_mode

    lane = {
        "engine": "codeql",
        "family": "static",
        "mode": "pattern-limited",
        "argv": [
            "/opt/factory/bin/audit-adapter",
            "codeql",
            "--mode",
            "pattern-limited",
        ],
    }
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_MODE"):
        _validate_lane_mode(lane)


def test_execution_manifest_v2_rejects_fixture_drift_and_syft_detector(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    challenge = plan["obligations"][0]["challenges"][0]
    challenge["fixture_manifest_sha256"] = "0" * 64
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_MANIFEST"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))

    _v2_execution_plan(plan, inventory)
    plan["obligations"].append(
        {
            "id": "syft-detector",
            "engine": "syft",
            "family": "dependencies",
            "detector_rule_id": "fixture-detection",
            "paths": ["app.py"],
            "requirements": ["app.py"],
            "remediation": "Inventory only.",
            "challenges": [],
        }
    )
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_ENGINE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def test_scan_rejects_authorization_changed_after_signature_verification(
    tmp_path, monkeypatch
):
    import factoryline.deep_audit as module
    import factoryline.deep_audit_attestation as attestation

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    original = attestation.verify_execution_authorization

    def verify_then_change(*args, **kwargs):
        result = original(*args, **kwargs)
        document = json.loads(authorization.read_text("utf-8"))
        document["payload"] = (
            "A" if document["payload"][0] != "A" else "B"
        ) + document["payload"][1:]
        authorization.write_text(json.dumps(document), encoding="utf-8")
        return result

    monkeypatch.setattr(
        attestation, "verify_execution_authorization", verify_then_change
    )
    monkeypatch.setattr(module, "_docker_base", lambda: pytest.fail("must not launch"))
    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_AUTHORIZATION_DRIFT"):
        module.scan_deep_audit(
            root,
            manifest,
            pin,
            authorization=authorization,
            trust_root=trust,
            trust_root_sha256=plan["trust_root_sha256"],
        )


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
    initial = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert initial["state"] == "INCOMPLETE"
    assert initial["gaps"] == ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
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


@pytest.mark.parametrize("linked_temp", [False, True])
def test_scan_missing_engine_is_incomplete_with_durable_progress(
    tmp_path, monkeypatch, linked_temp
):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    if linked_temp:
        from contextlib import contextmanager

        target = tmp_path / "system-temp"
        target.mkdir()
        alias = tmp_path / "temp-alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlinks unavailable")
        original = module.tempfile.TemporaryDirectory

        @contextmanager
        def temporary_directory(*args, **kwargs):
            with original(*args, dir=alias, **kwargs) as directory:
                yield directory

        monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary_directory)

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
    if engine == "codeql":
        assert result["state"] == "INCOMPLETE"
        assert result["gaps"] == ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
    elif engine == "osv":
        assert result["state"] == "INCOMPLETE"
        assert "OSV_NATIVE_ARTIFACTS_UNVERIFIED" in result["gaps"]
    else:
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


def _execute_lane_replay_case(
    tmp_path,
    monkeypatch,
    *,
    replay_action=None,
    cleanup_succeeds=True,
    engine="codeql",
    gaps=None,
    worker_replay_claim=False,
):
    import factoryline.deep_audit as module
    import factoryline.deep_audit_sarif as sarif

    from factoryline.runtime_audit_common import canonical_bytes

    root, _, pin, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    run_id = "b" * 32
    bundle = execution_bundle(lane, inventory, run_id)
    if worker_replay_claim:
        bundle["artifacts"][lane["coverage"]]["native_replay"] = {
            "state": "VERIFIED",
            "authority": "worker-claim",
        }
    raw = canonical_bytes(bundle)
    events, replay_calls = [], []
    directory = root / ".factory" / "test-run"
    directory.mkdir(parents=True)
    state = {
        "run_id": run_id,
        "manifest_sha256": pin,
        "active_lane": lane["id"],
    }

    monkeypatch.setattr(module, "_docker_base", lambda: ["docker"])
    monkeypatch.setattr(module, "_docker_preflight", lambda base, item: None)
    monkeypatch.setattr(module, "_container_argv", lambda *args: ["docker", "run"])
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)

    def cleanup(base, name):
        events.append("cleanup")
        return cleanup_succeeds

    monkeypatch.setattr(module, "_container_cleanup", cleanup)

    def run(argv, cwd, timeout, scratch, *, stdout_path, cancelled):
        stdout_path.write_bytes(raw)
        return {
            "exit_code": 0,
            "timed_out": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "cancelled": False,
        }

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    monkeypatch.setattr(
        sarif,
        "normalize_execution_bundle",
        lambda *args: {
            "lane_id": lane["id"],
            "state": "INCOMPLETE" if gaps else "OBSERVED",
            "findings": [],
            "gaps": list(gaps or []),
        },
    )

    def replay(*args, **kwargs):
        events.append("replay")
        replay_calls.append((args, kwargs))
        if isinstance(replay_action, BaseException):
            raise replay_action
        if callable(replay_action):
            return replay_action(*args, **kwargs)
        return replay_action or {"state": "VERIFIED", "authority": "host"}

    monkeypatch.setattr(module, "_replay_codeql_lane", replay, raising=False)
    result = module._execute_lane(
        root,
        directory,
        state,
        root,
        lane,
        inventory,
        {"obligations": plan["obligations"]},
        lambda event: None,
    )
    return result, events, replay_calls, bundle


def test_execute_lane_replays_codeql_only_after_container_cleanup(
    tmp_path, monkeypatch
):
    result, events, calls, _ = _execute_lane_replay_case(
        tmp_path,
        monkeypatch,
        gaps=["CODEQL_NATIVE_REPLAY_REQUIRED", "UNRELATED_GAP"],
    )
    assert events == ["cleanup", "replay"]
    assert len(calls) == 1
    assert result["gaps"] == ["UNRELATED_GAP"]
    assert result["state"] == "INCOMPLETE"
    assert result["codeql_replay"] == {"state": "VERIFIED", "authority": "host"}


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeAuditError("E_CODEQL_REPLAY_UNAVAILABLE", "missing"),
        RuntimeAuditError("E_CODEQL_REPLAY_MALFORMED", "invalid output"),
        RuntimeAuditError("E_ADAPTER_TIMEOUT", "expired"),
        RuntimeAuditError("E_CODEQL_REPLAY_CLEANUP", "uncertain cleanup"),
        {"state": "MALFORMED"},
    ],
)
def test_execute_lane_replay_failure_keeps_codeql_incomplete(
    tmp_path, monkeypatch, failure
):
    result, events, calls, _ = _execute_lane_replay_case(
        tmp_path,
        monkeypatch,
        replay_action=failure,
        gaps=["CODEQL_NATIVE_REPLAY_REQUIRED"],
    )
    assert events == ["cleanup", "replay"]
    assert len(calls) == 1
    assert result["state"] == "INCOMPLETE"
    assert "CODEQL_NATIVE_REPLAY_FAILED" in result["gaps"]
    assert result["codeql_replay"]["state"] == "INCOMPLETE"
    assert result["codeql_replay"]["diagnostic_code"]


@pytest.mark.parametrize(
    "failure_kind,exit_code,cleanup_succeeds",
    [("native_exit", 7, True), ("docker_cleanup", 0, False)],
)
def test_replay_failure_retains_safe_execution_receipt(
    tmp_path, monkeypatch, failure_kind, exit_code, cleanup_succeeds
):
    import threading
    import time

    import factoryline.deep_audit as module

    lane = {
        "id": "codeql-replay-test",
        "engine": "codeql",
        "coverage": "coverage.json",
        "report": "report.sarif",
        "timeout_seconds": 30,
        "image": "sha256:" + "a" * 64,
    }
    inventory = {"candidate_sha256": "b" * 64}
    bundle = {"artifacts": {"coverage.json": {}, "report.sarif": {}}}
    snapshot = tmp_path / "source snapshot private path"
    snapshot.mkdir()
    runtime = tmp_path / "trusted runtime"
    runtime.mkdir()
    stdout = b"private replay stdout"
    stderr = b"private replay stderr"
    facts = {
        "exit_code": exit_code,
        "timed_out": False,
        "timeout_seconds": 30,
        "duration_ms": 12,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "cancelled": False,
    }
    monkeypatch.setattr(module, "_docker_preflight", lambda *args: None)
    monkeypatch.setattr(
        module, "_codeql_replay_runtime", lambda scratch: (runtime, "c" * 64)
    )
    monkeypatch.setattr(
        module, "_codeql_replay_argv", lambda *args: ["docker", "run", str(snapshot)]
    )
    monkeypatch.setattr(
        module,
        "_container_cleanup",
        lambda *args: cleanup_succeeds,
    )

    def run(argv, cwd, timeout, scratch, *, stdout_path, cancelled):
        stdout_path.write_bytes(stdout)
        return facts

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    with pytest.raises(RuntimeAuditError) as caught:
        module._replay_codeql_lane(
            ["docker"],
            lane,
            snapshot,
            bundle,
            inventory,
            "d" * 32,
            threading.Event(),
        )

    error = caught.value
    evidence = error.replay_evidence
    assert evidence["image"] == lane["image"]
    assert evidence["runtime_sha256"] == "c" * 64
    assert len(evidence["command_sha256"]) == 64
    assert evidence["execution"] == facts
    assert evidence["cleanup_confirmed"] is cleanup_succeeds
    rendered = repr(evidence)
    assert "private replay stdout" not in rendered
    assert "private replay stderr" not in rendered
    assert str(snapshot) not in rendered
    assert str(runtime) not in rendered

    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    result = {
        "gaps": ["CODEQL_NATIVE_REPLAY_REQUIRED"],
        "state": "INCOMPLETE",
    }
    monkeypatch.setattr(
        module,
        "_replay_codeql_lane",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    directory = tmp_path / "run"
    directory.mkdir()
    module._codeql_replay_result(
        result,
        ["docker"],
        lane,
        snapshot,
        bundle,
        inventory,
        "d" * 32,
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": lane["id"]}, lambda event: None),
    )
    assert result["state"] == "INCOMPLETE"
    assert "CODEQL_NATIVE_REPLAY_REQUIRED" in result["gaps"]
    assert "CODEQL_NATIVE_REPLAY_FAILED" in result["gaps"]
    assert result["codeql_replay"]["evidence"] == evidence
    rendered_result = repr(result)
    assert "private replay stdout" not in rendered_result
    assert "private replay stderr" not in rendered_result
    assert str(snapshot) not in rendered_result
    assert str(runtime) not in rendered_result


def test_execute_lane_cleanup_failure_skips_codeql_replay(tmp_path, monkeypatch):
    replayed = []
    with pytest.raises(RuntimeAuditError, match="E_CONTAINER_CLEANUP"):
        _execute_lane_replay_case(
            tmp_path,
            monkeypatch,
            cleanup_succeeds=False,
            gaps=["CODEQL_NATIVE_REPLAY_REQUIRED"],
            replay_action=lambda *args: replayed.append(args),
        )
    assert replayed == []


def test_execute_lane_ignores_worker_replay_claim_and_requires_host_replay(
    tmp_path, monkeypatch
):
    result, events, calls, bundle = _execute_lane_replay_case(
        tmp_path,
        monkeypatch,
        gaps=["CODEQL_NATIVE_REPLAY_REQUIRED"],
        worker_replay_claim=True,
    )
    assert bundle["artifacts"]["coverage.json"]["native_replay"]["authority"] == (
        "worker-claim"
    )
    assert events == ["cleanup", "replay"]
    assert len(calls) == 1
    assert "CODEQL_NATIVE_REPLAY_REQUIRED" not in result["gaps"]
    assert result["codeql_replay"]["authority"] == "host"


@pytest.mark.parametrize("engine,gaps", [("syft", ["OTHER_GAP"]), ("codeql", [])])
def test_execute_lane_skips_replay_when_not_required(
    tmp_path, monkeypatch, engine, gaps
):
    result, events, calls, _ = _execute_lane_replay_case(
        tmp_path, monkeypatch, engine=engine, gaps=gaps
    )
    assert events == ["cleanup"]
    assert calls == []
    assert result["gaps"] == gaps


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
    assert not result["analysis_complete"]
    assert any(
        "SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE" in lane["gaps"]
        for lane in result["lanes"]
    )
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
    with pytest.raises(RuntimeAuditError, match="E_REVIEW_NORMALIZATION"):
        verify_execution_review(
            args[0],
            result["run_id"],
            attestation,
            invocation,
            args[4],
            args[5]["trust_root_sha256"],
        )
    # Isolate disposition/signature reconciliation after proving the real native
    # gate rejects incomplete secrets coverage. This is not an integration pass.
    monkeypatch.setattr(
        "factoryline.deep_audit_attestation._review_native_lanes", lambda *args: None
    )
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
        == {"accept": "INCOMPLETE", "high": "BLOCKED", "gap": "INCOMPLETE"}[disposition]
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
    from factoryline.deep_audit_sarif import (
        _osv_source_accounting,
        normalize_execution_bundle,
    )

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    if engine == "syft":
        report["artifacts"][0]["locations"].pop()
    else:
        report["results"].pop()
        lane["mode"] = "offline-pypi-snapshot"
        coverage = bundle["artifacts"]["coverage.json"]
        coverage["mode"] = lane["mode"]
        coverage["complete"] = False
        coverage["errors"] = ["NATIVE_SOURCE_ACCOUNTING_REQUIRED"]
        coverage["report_sha256"] = digest(report)
        expected_accounting = _osv_source_accounting(
            report,
            {item["path"]: item["sha256"] for item in inventory["files"]},
            lane["mode"],
        )
        coverage["source_accounting"] = expected_accounting
    if engine == "syft":
        bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
        with pytest.raises(RuntimeAuditError, match="E_DEPENDENCY_COVERAGE"):
            normalize_execution_bundle(
                bundle, lane, inventory, "0" * 32, plan["obligations"]
            )
    else:
        observed = normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )
        assert observed["state"] == "INCOMPLETE"
        assert "OSV_SOURCE_ACCOUNTING_INCOMPLETE" in observed["gaps"]
        assert observed["covered_paths"] == expected_accounting["measured_paths"]
        assert observed["covered_paths"] != sorted(
            item["path"] for item in inventory["files"]
        )
        assert observed["source_accounting"] == expected_accounting


def test_osv_normalization_exposes_empty_packages_despite_forged_complete_flag(
    tmp_path,
):
    from factoryline.deep_audit_sarif import (
        _osv_source_accounting,
        normalize_execution_bundle,
    )

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    lane["mode"] = "offline-pypi-snapshot"
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    report["results"][0]["packages"] = []
    required = {item["path"]: item["sha256"] for item in inventory["files"]}
    account = _osv_source_accounting(report, required, lane["mode"])
    coverage = bundle["artifacts"]["coverage.json"]
    coverage.update(
        {
            "complete": True,
            "errors": [],
            "mode": lane["mode"],
            "report_sha256": digest(report),
            "source_accounting": account,
        }
    )

    observed = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert observed["state"] == "INCOMPLETE"
    assert "OSV_SOURCE_ACCOUNTING_INCOMPLETE" in observed["gaps"]
    assert observed["source_accounting"] == account
    assert observed["covered_paths"] == account["measured_paths"]
    assert observed["findings"] == []


def test_execution_osv_preserves_package_advisory_and_fixed_version(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    package = report["results"][0]["packages"][0]
    package["vulnerabilities"] = [
        {
            "id": "OSV-TEST-1",
            "affected": [
                {
                    "package": {"name": "fixture", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.4.6"}]}],
                }
            ],
        }
    ]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)

    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )

    finding = result["findings"][0]
    assert finding["dependency"] == {
        "package": {"name": "fixture", "version": "1.0", "ecosystem": "PyPI"},
        "advisory_id": "OSV-TEST-1",
        "fixed_versions": ["2.4.6"],
        "aliases": [],
    }
    assert "2.4.6" in finding["remediation"]
    assert result["authority"] == "none"


@pytest.mark.parametrize(
    "bad_affected", ["not-a-list", [{"ranges": [{"events": [{"fixed": 42}]}]}]]
)
def test_execution_osv_rejects_malformed_fixed_version_evidence(tmp_path, bad_affected):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    package = report["results"][0]["packages"][0]
    package["vulnerabilities"] = [{"id": "OSV-TEST-1", "affected": bad_affected}]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)

    with pytest.raises(RuntimeAuditError):
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


@pytest.mark.parametrize(
    "engine, expected_metrics",
    [
        ("runtime", {"tests": 1}),
        ("atheris", {"executions": 1000, "coverage_edges": 10, "corpus_size": 5}),
    ],
)
def test_runtime_and_fuzz_metrics_survive_normalized_projection(
    tmp_path, engine, expected_metrics
):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)

    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )

    assert result["state"] == "OBSERVED"
    assert result["metrics"] == expected_metrics
    assert result["authority"] == "none"


def test_execution_sarif_trace_details_survive_projection(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "codeql")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    report["runs"][0]["results"] = execution_native(lane, inventory, detected=True)[
        "runs"
    ][0]["results"]
    report["runs"][0]["results"][0]["codeFlows"] = [
        {
            "threadFlows": [
                {
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {
                                        "startLine": 2,
                                        "endLine": 2,
                                        "startColumn": 4,
                                        "endColumn": 9,
                                    },
                                }
                            },
                            "kinds": ["source"],
                        }
                    ]
                }
            ]
        }
    ]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    source_hash = next(
        item["sha256"] for item in inventory["files"] if item["path"] == "app.py"
    )

    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )

    assert result["findings"][0]["flows"] == [
        [
            {
                "path": "app.py",
                "source_sha256": source_hash,
                "start_line": 2,
                "end_line": 2,
                "start_column": 4,
                "end_column": 9,
                "kinds": ["source"],
            }
        ]
    ]
    assert result["findings"][0]["trace_depth"] == 1
    assert len(result["findings"][0]["trace_sha256"]) == 64
    assert result["findings"][0]["native_identity_state"] == "NOT_MEASURED"
    assert result["authority"] == "none"


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


def test_specialty_review_stages_do_not_hide_complexity():
    import ast
    import inspect
    import textwrap
    import factoryline.deep_audit_attestation as module

    stages = (
        "verify_execution_review",
        "_review_candidate",
        "_review_native_lanes",
        "_review_dispositions",
        "_review_finding",
        "_review_provenance",
        "_execution_document",
        "_execution_freshness",
        "_execution_signer",
    )
    for name in stages:
        tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(module, name))))
        complexity = 1
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
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
        assert complexity <= 10, (name, complexity)


@pytest.mark.parametrize("surface", ["primary", "challenge"])
def test_execution_sarif_defaults_preserve_original_hashes(tmp_path, surface):
    from copy import deepcopy
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "codeql")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    if surface == "primary":
        report = execution_native(lane, inventory, detected=True)
        bundle["artifacts"]["report.json"] = report
    else:
        observation = bundle["artifacts"]["challenges.json"]["observations"][0]
        report = observation["report"]["native_report"]
    run = report["runs"][0]
    run["results"][0].pop("level")
    run["tool"]["driver"]["rules"] = [
        {"id": "fixture-detection", "defaultConfiguration": {"level": "error"}}
    ]
    if surface == "primary":
        bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    else:
        observation["observation_sha256"] = digest(observation["report"])
        obligation = next(
            item for item in plan["obligations"] if item["engine"] == "codeql"
        )
        obligation["challenges"][0]["expected_report_sha256"] = digest(
            observation["report"]
        )
    original = deepcopy(bundle)
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert result["gaps"] == ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
    assert bundle == original


def test_secrets_sidecar_cannot_claim_native_scan_coverage(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "gitleaks")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert result["state"] == "INCOMPLETE"
    assert "SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE" in result["gaps"]


def test_failure_playback_is_paged_and_tamper_checked(tmp_path, monkeypatch):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import read_run_json, run_directory, write_run_json

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)

    def unavailable():
        raise RuntimeAuditError("E_DOCKER_UNAVAILABLE", "private diagnostic")

    monkeypatch.setattr(module, "_docker_base", unavailable)
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    page = module.playback_deep_run(root, result["run_id"], limit=3)
    assert len(page["events"]) == 3 and page["has_more"]
    events = module.playback_deep_run(root, result["run_id"], limit=500)["events"]
    failures = [
        event["details"] for event in events if event["kind"] == "failure_recorded"
    ]
    assert len(failures) == 7
    assert all(item["code"] == "E_DOCKER_UNAVAILABLE" for item in failures)
    assert all(
        item["candidate_sha256"] == plan["candidate_sha256"] for item in failures
    )
    assert "private diagnostic" not in json.dumps(events)
    directory = run_directory(root, result["run_id"])
    event = read_run_json(directory, "event-00001.json")
    event["details"] = {}
    write_run_json(directory, "event-00001.json", event)
    with pytest.raises(RuntimeAuditError, match="E_EVENT_INTEGRITY"):
        module.playback_deep_run(root, result["run_id"])


def test_pause_stops_between_lanes_and_resume_revalidates(tmp_path, monkeypatch):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    calls = []

    def lane(*args):
        state, definition = args[2], args[4]
        calls.append(definition["id"])
        request = module.pause_deep_run(root, state["run_id"])
        assert request["state"] == "PAUSE_REQUESTED"
        return {
            "lane_id": definition["id"],
            "state": "INCOMPLETE",
            "findings": [],
            "gaps": ["WORKER_FAILED"],
            "execution": {"cancelled": True},
        }

    monkeypatch.setattr(module, "_execute_lane", lane)
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert result["state"] == "PAUSED" and not result["analysis_complete"]
    assert result["lanes"][0]["family"] == plan["lanes"][0]["family"]
    assert result["lanes"][0]["engine"] == plan["lanes"][0]["engine"]
    assert len(calls) == 1
    assert (
        module.playback_deep_run(root, result["run_id"])["events"][-1]["kind"]
        == "run_paused"
    )
    assert module.pause_deep_run(root, result["run_id"])["state"] == "ALREADY_STOPPED"
    retried = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
        resume=result["run_id"],
    )
    assert retried["parent_run"] == result["run_id"]
    assert retried["run_id"] != result["run_id"] and len(calls) == 2
    with pytest.raises(RuntimeAuditError, match="E_RESUME_DRIFT"):
        from factoryline.deep_audit_io import read_run_json, run_directory

        module._check_resume(
            root,
            result["run_id"],
            "0" * 64,
            plan,
            None,
            read_run_json,
            run_directory,
        )


@pytest.mark.parametrize("after,limit", [(-1, 100), (True, 100), (0, 0), (0, 501)])
def test_playback_rejects_invalid_bounds(tmp_path, after, limit):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import run_directory

    run_id = "a" * 32
    state = {"schema": "factory.deep-run.v1", "run_id": run_id, "state": "PAUSED"}
    module._event(
        run_directory(tmp_path, run_id, create=True), state, "run_started", {}
    )
    with pytest.raises(RuntimeAuditError, match="E_PLAYBACK_RANGE"):
        module.playback_deep_run(tmp_path, run_id, after=after, limit=limit)


def test_osv_fixed_versions_do_not_cross_package_boundaries():
    from factoryline.deep_audit_sarif import _osv_fixed_versions

    identity = {"name": "target", "ecosystem": "PyPI"}
    vulnerability = {
        "affected": [
            {
                "package": {"name": "other", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"fixed": "9"}]}],
            },
            {"ranges": [{"events": [{"fixed": "8"}]}]},
            {"package": identity, "ranges": [{"events": [{"fixed": "2"}]}]},
        ]
    }
    assert _osv_fixed_versions(vulnerability, identity) == ["2"]

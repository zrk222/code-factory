from copy import deepcopy
import json
from pathlib import Path

import pytest

from test_deep_audit_contract import fixture
from test_deep_audit_sarif import report
from factoryline.deep_audit import (
    execute_deep_audit,
    evaluate_deep_audit,
    deep_audit_status,
)
from factoryline.deep_audit_contract import verify_deep_audit_plan
from factoryline.deep_audit_sarif import normalize_sarif
from factoryline.deep_audit_io import digest
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes


def adapter_inputs(tmp_path):
    import sys

    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    (source / "app.txt").write_bytes(b"candidate")
    lane = {
        "engine": "runtime",
        "mode": "native",
        "tool_version": "test-harness-1",
        "ruleset_sha256": "a" * 64,
        "timeout_seconds": 5,
        "report": "report.json",
        "coverage": "coverage.json",
        "challenge_report": "challenges.json",
    }
    script = (
        "import json; from pathlib import Path; "
        f"root=Path({str(output)!r}); "
        "[(root/name).write_text(json.dumps({'observed': name})) "
        "for name in ('report.json','coverage.json','challenges.json')]"
    )
    profile = {
        "schema": "factory.adapter-profile.v1",
        **{
            key: lane[key]
            for key in ("engine", "mode", "tool_version", "ruleset_sha256")
        },
        "commands": [
            {"argv": [sys.executable, "-c", script], "accepted_exit_codes": [0]}
        ],
    }
    contract = {
        "schema": "factory.deep-adapter-input.v1",
        "run_id": "test",
        "manifest_sha256": "b" * 64,
        "inventory": {
            "candidate_sha256": "c" * 64,
            "files": [{"path": "app.txt", "sha256": sha256_bytes(b"candidate")}],
        },
        "lane": lane,
        "obligations": [],
    }
    return profile, contract, source, output


@pytest.mark.parametrize(
    "engine", ["codeql", "osv", "gitleaks", "trivy", "runtime", "atheris"]
)
def test_adapter_joins_actual_artifacts_without_inventing_coverage(tmp_path, engine):
    from factoryline.deep_audit_io import execute_adapter_profile

    profile, contract, source, output = adapter_inputs(tmp_path)
    profile["engine"] = contract["lane"]["engine"] = engine
    # This is a synthetic artifact transport test, not execution of these tools.
    result = execute_adapter_profile(profile, contract, source, output)
    assert result["schema"] == "factory.deep-worker.v1"
    assert result["run_id"] == "test"
    assert result["candidate_sha256"] == "c" * 64
    coverage = result["artifacts"]["coverage.json"]
    assert coverage["observed"] == "coverage.json"
    assert "complete" not in coverage
    assert coverage["native_invocations"][0]["execution"]["exit_code"] == 0
    assert coverage["invocation_sha256"] == digest(coverage["native_invocations"])


@pytest.mark.parametrize(
    "failure", ["profile", "source", "stale", "missing", "exit", "drift"]
)
def test_adapter_rejects_drift_stale_missing_and_failed_execution(tmp_path, failure):
    from factoryline.deep_audit_io import execute_adapter_profile

    profile, contract, source, output = adapter_inputs(tmp_path)
    code = {
        "profile": "E_ADAPTER_PROFILE",
        "source": "E_REPORT_DRIFT",
        "stale": "E_ADAPTER_STALE",
        "missing": "E_SOURCE_MISSING",
        "exit": "E_ADAPTER_COMMAND",
        "drift": "E_REPORT_DRIFT",
    }[failure]
    if failure == "profile":
        profile["tool_version"] = "wrong-version"
    elif failure == "source":
        (source / "app.txt").write_bytes(b"changed")
    elif failure == "stale":
        (output / "report.json").write_text("{}")
    elif failure == "missing":
        profile["commands"][0]["argv"][-1] = "pass"
    elif failure == "exit":
        profile["commands"][0]["argv"][-1] = "raise SystemExit(7)"
    elif failure == "drift":
        profile["commands"][0]["argv"][-1] += "; Path('app.txt').write_text('changed')"
    with pytest.raises(RuntimeAuditError, match=code):
        execute_adapter_profile(profile, contract, source, output)


def test_adapter_rejects_relative_executable_and_boolean_exit_code(tmp_path):
    from factoryline.deep_audit_io import execute_adapter_profile

    profile, contract, source, output = adapter_inputs(tmp_path)
    profile["commands"][0]["accepted_exit_codes"] = [True]
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_PROFILE"):
        execute_adapter_profile(profile, contract, source, output)
    profile["commands"][0]["accepted_exit_codes"] = [0]
    profile["commands"][0]["argv"][0] = "python"
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_PROFILE"):
        execute_adapter_profile(profile, contract, source, output)


@pytest.mark.parametrize("local_id", [False, True])
def test_docker_preflight_verifies_exact_immutable_pin(monkeypatch, local_id):
    import factoryline.deep_audit as module

    pin = ("" if local_id else "example/adapter@") + "sha256:" + "a" * 64
    calls = []

    def control(base, args):
        calls.append(args)
        value = "linux" if args[0] == "info" else (pin if local_id else [pin])
        return {"exit_code": 0}, json.dumps(value).encode()

    monkeypatch.setattr(module, "_docker_control", control)
    module._docker_preflight(["docker"], {"image": pin})
    field = ".Id" if local_id else ".RepoDigests"
    assert calls[-1] == ["image", "inspect", pin, "--format", "{{json " + field + "}}"]


@pytest.mark.parametrize("local_id", [False, True])
@pytest.mark.parametrize("actual", [None, {}, [], "sha256:" + "b" * 64])
def test_docker_preflight_rejects_wrong_pin_shape_or_digest(
    monkeypatch, local_id, actual
):
    import factoryline.deep_audit as module

    pin = ("" if local_id else "example/adapter@") + "sha256:" + "a" * 64

    def control(base, args):
        value = "linux" if args[0] == "info" else actual
        return {"exit_code": 0}, json.dumps(value).encode()

    monkeypatch.setattr(module, "_docker_control", control)
    with pytest.raises(RuntimeAuditError, match="E_IMAGE_PIN"):
        module._docker_preflight(["docker"], {"image": pin})


def test_docker_preflight_missing_local_image_never_pulls(monkeypatch):
    import factoryline.deep_audit as module

    calls = []

    def control(base, args):
        calls.append(args)
        return (
            ({"exit_code": 0}, b'"linux"')
            if args[0] == "info"
            else ({"exit_code": 1}, b"")
        )

    monkeypatch.setattr(module, "_docker_control", control)
    with pytest.raises(RuntimeAuditError, match="E_IMAGE_UNAVAILABLE"):
        module._docker_preflight(["docker"], {"image": "sha256:" + "a" * 64})
    assert [args[0] for args in calls] == ["info", "image"]


def test_missing_nested_source_has_typed_error(tmp_path: Path) -> None:
    from factoryline.deep_audit_io import local_file

    with pytest.raises(RuntimeAuditError) as exc:
        local_file(tmp_path, "missing/report.json")
    assert exc.value.code == "E_SOURCE_MISSING"


def inputs(tmp_path, *, clean=False, canary_kind="fail", canary_suppressed=False):
    def bind(plan):
        for key, name in (("report", "scan.json"), ("canary_report", "canary.json")):
            payload = report()
            result = payload["runs"][0]["results"][0]
            result["ruleId"] = "leak"
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "leak"
            result["partialFingerprints"]["primary/v1"] = key
            if key == "canary_report":
                result["kind"] = canary_kind
                if canary_suppressed:
                    result["suppressions"] = [
                        {"kind": "external", "status": "accepted"}
                    ]
            elif clean:
                payload["runs"][0]["results"] = []
            raw = json.dumps(payload).encode()
            (tmp_path / name).write_bytes(raw)
            plan["analyzers"][0][key]["sha256"] = sha256_bytes(raw)
        plan["canaries"][0]["fingerprint_sha256"] = digest(
            {"partialFingerprints:primary/v1": "canary_report"}
        )

    args = fixture(tmp_path, bind)
    checked = verify_deep_audit_plan(*args)
    analyzer = checked["plan"]["analyzers"][0]
    targets = [
        normalize_sarif(
            tmp_path, analyzer["report"], analyzer, checked["source_hashes"]
        )
    ]
    canaries = [
        normalize_sarif(
            tmp_path, analyzer["canary_report"], analyzer, checked["source_hashes"]
        )
    ]
    return args, checked["plan"], targets, canaries


def rehash(report):
    report.pop("normalized_sha256", None)
    report["normalized_sha256"] = digest(report)


def codes(receipt):
    return {action["code"] for action in receipt["repair_queue"]}


def test_signed_execution_threshold_and_idempotent_receipt(tmp_path):
    args, plan, targets, canaries = inputs(tmp_path)
    result = execute_deep_audit(*args)
    receipt = result["receipt"]
    assert receipt["decision"] == "BLOCKED"
    assert codes(receipt) == {"DEEP_RULE_THRESHOLD"}
    assert receipt["repair_queue"][0]["remediation"] == "Close owned resources"
    action = receipt["agent_actions"][0]
    assert action["measurement_id"] == receipt["repair_queue"][0]["rule_id"]
    assert action["candidate_sha256"] == receipt["candidate_sha256"]
    assert action["action"] == receipt["repair_queue"][0]["remediation"]
    assert action["evidence_to_attach"] and action["stop_condition"]
    assert execute_deep_audit(*args) == result
    status = deep_audit_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["agent_actions"] == receipt["agent_actions"]
    assert evaluate_deep_audit(plan, targets, canaries)["authority"] == "none"


def test_clean_with_detected_canary_requires_human_review(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    receipt = execute_deep_audit(*args)["receipt"]
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert receipt["repair_queue"] == []
    assert receipt["agent_actions"] == []
    assert receipt["authority"] == "none"
    assert (
        deep_audit_status(tmp_path)["verification"]
        == "self_hash_only_not_signature_or_freshness"
    )


@pytest.mark.parametrize(
    "kind", ["pass", "notApplicable", "review", "open", "informational"]
)
def test_nonfailure_canary_cannot_validate_analyzer(tmp_path, kind):
    args, _, _, _ = inputs(tmp_path, clean=True, canary_kind=kind)
    assert "HOLLOW_DEEP_AUDIT" in codes(execute_deep_audit(*args)["receipt"])


def test_suppressed_canary_cannot_validate_analyzer(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True, canary_suppressed=True)
    assert "HOLLOW_DEEP_AUDIT" in codes(execute_deep_audit(*args)["receipt"])


def test_missing_fingerprint_canary_fails_closed(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path, clean=True)
    canaries[0]["findings"] = []
    rehash(canaries[0])
    assert "HOLLOW_DEEP_AUDIT" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_trace_order_and_suppression_require_review(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    finding = targets[0]["findings"][0]
    finding["flows"][0].reverse()
    finding["suppressed"] = True
    rehash(targets[0])
    result = evaluate_deep_audit(plan, targets, canaries)
    assert {"DEEP_TRACE_INCOMPLETE", "DEEP_SUPPRESSION_UNAPPROVED"} <= codes(result)


def test_unknown_new_error_is_not_ignored(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    targets[0]["findings"][0]["rule_id"] = "unmapped"
    rehash(targets[0])
    assert "DEEP_UNKNOWN_ERROR" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_missing_duplicate_and_changed_reports_rejected(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ANALYZER_INCOMPLETE"):
        evaluate_deep_audit(plan, [], canaries)
    with pytest.raises(RuntimeAuditError, match="E_DEEP_REPORT"):
        evaluate_deep_audit(plan, targets * 2, canaries)
    targets[0]["findings"] = []
    with pytest.raises(RuntimeAuditError, match="E_DEEP_REPORT"):
        evaluate_deep_audit(plan, targets, canaries)


def test_tampered_receipt_never_falls_back_to_green(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    result = execute_deep_audit(*args)
    from pathlib import Path

    Path(result["receipt_path"]).write_text("{}")
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"
    with pytest.raises(RuntimeAuditError, match="E_RECEIPT_COLLISION"):
        execute_deep_audit(*args)


def test_absent_and_pass_labels_do_not_hide_signed_threshold_findings(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    targets[0]["findings"][0].update(baseline="absent", kind="pass")
    rehash(targets[0])
    assert "DEEP_RULE_THRESHOLD" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_cluster_signals_do_not_claim_causation(tmp_path):
    from factoryline.deep_audit import _clusters

    _, _, targets, _ = inputs(tmp_path)
    first = {**targets[0]["findings"][0], "obligation_id": "o", "category": "memory"}
    second = {
        **deepcopy(first),
        "analyzer_id": "second",
        "finding_id": "b" * 64,
        "category": "security",
    }
    clusters = _clusters([first, second])
    assert {item["kind"] for item in clusters} == {"corroboration", "compound_risk"}
    assert all(item["claim"] == "routing_signal_not_causation" for item in clusters)


def test_status_rejects_oversize_receipt(tmp_path, monkeypatch):
    args, _, _, _ = inputs(tmp_path, clean=True)
    execute_deep_audit(*args)
    monkeypatch.setattr("factoryline.deep_audit.LIMIT", 10)
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_rejects_non_directory_history(tmp_path):
    (tmp_path / ".factory").write_text("not a directory")
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_without_history_is_not_run(tmp_path):
    assert deep_audit_status(tmp_path)["state"] == "NOT_RUN"

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


def native_inputs(tmp_path):
    import sys

    profile, contract, source, output = adapter_inputs(tmp_path)
    profile["engine"] = contract["lane"]["engine"] = "osv"
    profile.update(
        schema="factory.native-profile.v1",
        report_format="osv-json",
        version_argv=[sys.executable, "-c", "print('test-harness-1')"],
    )
    contract["lane"]["languages"] = ["text"]
    contract["inventory"]["files"][0]["language"] = "text"
    profile["commands"][0]["argv"][-1] = (
        "from pathlib import Path; Path(r'{report}').write_text('{\"results\": []}')"
    )
    return profile, contract, source, output


def test_native_adapter_retains_execution_without_inventing_completion(tmp_path):
    from factoryline.deep_audit_io import execute_native_profile

    args = native_inputs(tmp_path)
    result = execute_native_profile(*args)
    coverage = result["artifacts"]["coverage.json"]
    assert coverage["complete"] is False
    assert coverage["errors"] == [
        "NATIVE_SOURCE_ACCOUNTING_REQUIRED",
        "NATIVE_CHALLENGES_REQUIRED",
    ]
    assert coverage["native_invocations"][0]["execution"]["exit_code"] == 0
    assert coverage["version_probe"]["exit_code"] == 0
    assert result["artifacts"]["challenges.json"]["observations"] == []


@pytest.mark.parametrize(
    "failure", ["version", "version_exit", "native_exit", "missing", "stale"]
)
def test_native_adapter_rejects_failed_native_execution(tmp_path, failure):
    from factoryline.deep_audit_io import execute_native_profile

    profile, contract, source, output = native_inputs(tmp_path)
    codes = {
        "version": "E_TOOLCHAIN_DRIFT",
        "version_exit": "E_TOOLCHAIN_PROBE",
        "native_exit": "E_ADAPTER_COMMAND",
        "missing": "E_SOURCE_MISSING",
        "stale": "E_ADAPTER_STALE",
    }
    if failure == "version":
        profile["version_argv"][-1] = "print('test-harness-10')"
    elif failure == "version_exit":
        profile["version_argv"][-1] = "raise SystemExit(1)"
    elif failure == "native_exit":
        profile["commands"][0]["argv"][-1] = "raise SystemExit(8)"
    elif failure == "missing":
        profile["commands"][0]["argv"][-1] = "pass"
    elif failure == "stale":
        (output / "report.json").write_text("{}")
    with pytest.raises(RuntimeAuditError, match=codes[failure]):
        execute_native_profile(profile, contract, source, output)


def test_native_sarif_enrichment_uses_actual_invocation_and_preserves_failures():
    from factoryline.deep_audit_io import _native_sarif_metadata

    raw = {"runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}]}
    result = _native_sarif_metadata(
        raw, {"tool_version": "8.28.0"}, [{"execution": {"exit_code": 1}}]
    )
    assert result["runs"][0]["tool"]["driver"]["version"] == "8.28.0"
    assert "version" not in raw["runs"][0]["tool"]["driver"]
    raw["runs"][0]["invocations"] = [{"executionSuccessful": False}]
    assert (
        _native_sarif_metadata(raw, {"tool_version": "8.28.0"}, [])["runs"][0][
            "invocations"
        ][0]["executionSuccessful"]
        is False
    )


def test_runtime_native_coverage_preserves_uncovered_branches(tmp_path):
    from factoryline.deep_audit_io import _native_coverage_report

    (tmp_path / "runtime.xml").write_text(
        '<testsuite><testcase file="test_app.py" line="2"/></testsuite>'
    )
    raw = {
        "meta": {"branch_coverage": True},
        "files": {
            "app.py": {
                "summary": {
                    "num_statements": 4,
                    "covered_lines": 3,
                    "num_branches": 2,
                    "covered_branches": 1,
                }
            }
        },
    }
    inventory = {
        "files": [
            {"path": "app.py", "sha256": "a" * 64},
            {"path": "test_app.py", "sha256": "b" * 64},
        ]
    }
    report = _native_coverage_report(
        raw, {"tool_version": "7.10.7"}, inventory, tmp_path
    )
    assert report["metrics"]["tests"] == 1
    assert report["source_coverage"]["app.py"]["branches_covered"] == 1
    assert report["source_coverage"]["app.py"]["lines_covered"] == 3
    assert report["harness"]["sha256"] == "b" * 64


@pytest.mark.parametrize("invalid", ["no_branch", "entity", "unbound", "skipped"])
def test_runtime_native_coverage_rejects_unmeasured_or_unbound_evidence(
    tmp_path, invalid
):
    from factoryline.deep_audit_io import _native_coverage_report

    raw = {"meta": {"branch_coverage": invalid != "no_branch"}, "files": {}}
    xml = '<testsuite><testcase file="test_app.py"/></testsuite>'
    if invalid == "entity":
        xml = '<!DOCTYPE testsuite [<!ENTITY x "unsafe">]>' + xml
    elif invalid == "unbound":
        xml = '<testsuite><testcase file="other.py"/></testsuite>'
    elif invalid == "skipped":
        xml = (
            '<testsuite><testcase file="test_app.py"><skipped/></testcase></testsuite>'
        )
    (tmp_path / "runtime.xml").write_text(xml)
    with pytest.raises(RuntimeAuditError):
        _native_coverage_report(
            raw,
            {"tool_version": "7"},
            {"files": [{"path": "test_app.py", "sha256": "a" * 64}]},
            tmp_path,
        )


def test_fuzz_snapshot_reports_measured_arcs_and_observed_callbacks(tmp_path):
    from factoryline.deep_audit_io import _fuzz_snapshot

    class MeasuredCoverage:
        def json_report(self, outfile):
            Path(outfile).write_text(
                json.dumps(
                    {
                        "files": {
                            "fuzz.py": {
                                "executed_branches": [[1, 2]],
                                "summary": {
                                    "num_statements": 3,
                                    "covered_lines": 2,
                                    "num_branches": 2,
                                    "covered_branches": 1,
                                },
                            }
                        }
                    }
                )
            )

    contract = {
        "lane": {"tool_version": "2.0.7"},
        "inventory": {"files": [{"path": "fuzz.py", "sha256": "a" * 64}]},
    }
    output = tmp_path / "fuzz.json"
    _fuzz_snapshot(
        MeasuredCoverage(),
        contract,
        "fuzz.py",
        output,
        {"executions": 64, "inputs": {"one", "two"}, "findings": []},
    )
    result = json.loads(output.read_text())
    assert result["metrics"] == {
        "executions": 64,
        "corpus_size": 2,
        "coverage_edges": 1,
    }
    assert result["source_coverage"]["fuzz.py"]["lines_covered"] == 2
    assert "lower bound" in result["metric_definitions"]["executions"]


def test_native_sarif_expands_only_bound_source_references():
    from factoryline.deep_audit_io import _native_sarif_paths

    report = {
        "runs": [
            {
                "originalUriBaseIds": {"SRC": {"uri": "file:///src/"}},
                "artifacts": [{"location": {"uri": "app.py", "uriBaseId": "SRC"}}],
                "results": [
                    {
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"index": 0},
                                    "region": {"startLine": 1},
                                }
                            }
                        ]
                    }
                ],
            }
        ]
    }
    result = _native_sarif_paths(report, {"app.py": "a" * 64})
    assert result["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ] == {"uri": "app.py"}
    report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ] = {"uri": "app.py", "uriBaseId": "UNKNOWN"}
    with pytest.raises(RuntimeAuditError, match="E_SARIF_INDIRECTION"):
        _native_sarif_paths(report, {"app.py": "a" * 64})


@pytest.mark.parametrize(
    "uri", ["file:///etc/app.py", "../app.py", "/app.py", "https://host/app.py"]
)
def test_native_source_paths_reject_foreign_roots_and_traversal(uri):
    from factoryline.deep_audit_io import _native_source_path

    with pytest.raises(RuntimeAuditError):
        _native_source_path(uri, {"app.py": "a" * 64})


def test_native_dependency_paths_preserve_bound_manifest_identity():
    from factoryline.deep_audit_io import _native_dependency_paths

    sources = {"requirements.txt": "a" * 64}
    osv = {"results": [{"source": {"path": "/src/requirements.txt"}}]}
    syft = {"artifacts": [{"locations": [{"path": "/requirements.txt"}]}]}
    _native_dependency_paths(osv, "osv-json", sources)
    _native_dependency_paths(syft, "syft-json", sources)
    assert osv["results"][0]["source"]["path"] == "requirements.txt"
    assert syft["artifacts"][0]["locations"][0]["path"] == "requirements.txt"


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


@pytest.mark.parametrize("uri", ["/src/app.py", "file:///src/app.py"])
def test_native_absolute_source_ignores_unused_base(uri):
    from factoryline.deep_audit_io import _native_artifact_path

    assert (
        _native_artifact_path(
            {"uri": uri, "uriBaseId": "%SRCROOT%"}, {}, {"app.py": "a" * 64}
        )
        == "app.py"
    )


@pytest.mark.parametrize("target", [None, "/src", "/outside"])
def test_syft_native_metadata_source_is_exactly_bound(target):
    from factoryline.deep_audit_sarif import _execution_syft

    source = {"type": "directory", "name": "/src", "metadata": {"path": "/src"}}
    if target is not None:
        source["target"] = target
    report = {
        "source": source,
        "descriptor": {"name": "syft", "version": "1.33.0"},
        "schema": {"version": "16.0.0"},
        "artifacts": [
            {
                "id": "one",
                "name": "requests",
                "version": "2.31.0",
                "type": "python",
                "locations": [{"path": "requirements.txt"}],
            }
        ],
    }
    if target == "/outside":
        with pytest.raises(RuntimeAuditError, match="E_SBOM_SOURCE"):
            _execution_syft(
                report, {"tool_version": "1.33.0"}, {"requirements.txt": "a" * 64}
            )
    else:
        assert (
            _execution_syft(
                report, {"tool_version": "1.33.0"}, {"requirements.txt": "a" * 64}
            )
            == []
        )


def test_native_unbound_absolute_source_still_rejected():
    from factoryline.deep_audit_io import _native_artifact_path

    with pytest.raises(RuntimeAuditError):
        _native_artifact_path(
            {"uri": "/src/other.py", "uriBaseId": "%SRCROOT%"},
            {},
            {"app.py": "a" * 64},
        )


def test_osv_empty_native_results_remain_valid_not_complete():
    from factoryline.deep_audit_sarif import _execution_osv

    assert _execution_osv({"results": []}, {}, {"requirements.txt": "a" * 64}) == []
    with pytest.raises(RuntimeAuditError):
        _execution_osv({}, {}, {"requirements.txt": "a" * 64})
    with pytest.raises(RuntimeAuditError, match="E_DEPENDENCY_ERRORS"):
        _execution_osv({"results": [], "errors": ["analysis failed"]}, {}, {})


def test_status_without_history_is_not_run(tmp_path):
    assert deep_audit_status(tmp_path)["state"] == "NOT_RUN"


@pytest.mark.parametrize(
    "field,value",
    [
        ("num_statements", -1),
        ("covered_lines", True),
        ("covered_lines", 3),
        ("num_branches", 1.5),
        ("covered_branches", 4),
    ],
)
def test_native_coverage_rejects_invalid_or_impossible_measurements(field, value):
    from factoryline.deep_audit_io import _native_source_counts

    summary = {
        "num_statements": 2,
        "covered_lines": 1,
        "num_branches": 2,
        "covered_branches": 1,
    }
    summary[field] = value
    with pytest.raises(RuntimeAuditError):
        _native_source_counts(
            {"files": {"app.py": {"summary": summary}}}, {"app.py": "a" * 64}
        )


def test_native_coverage_rejects_duplicate_normalized_paths():
    from factoryline.deep_audit_io import _native_source_counts

    measured = {
        "summary": {
            "num_statements": 2,
            "covered_lines": 1,
            "num_branches": 2,
            "covered_branches": 1,
        }
    }
    with pytest.raises(RuntimeAuditError, match="duplicate native"):
        _native_source_counts(
            {"files": {"app.py": measured, "/src/app.py": measured}},
            {"app.py": "a" * 64},
        )


def test_native_runtime_accounting_distinguishes_measured_and_missing_sources():
    from factoryline.deep_audit_io import _native_runtime_accounting

    inventory = {
        "files": [
            {"path": "app.py", "sha256": "a" * 64, "language": "python"},
            {"path": "untouched.py", "sha256": "b" * 64, "language": "python"},
        ]
    }
    lane = {"languages": ["python"]}
    report = {"source_coverage": {"app.py": {"sha256": "a" * 64}}}
    partial = _native_runtime_accounting(report, inventory, lane)
    assert partial["state"] == "PARTIAL"
    assert partial["missing_paths"] == ["untouched.py"]
    report["source_coverage"]["untouched.py"] = {"sha256": "b" * 64}
    complete = _native_runtime_accounting(report, inventory, lane)
    assert complete["state"] == "COMPLETE"
    assert complete["missing_paths"] == []
    report["source_coverage"]["app.py"]["sha256"] = "c" * 64
    with pytest.raises(RuntimeAuditError, match="hash differs"):
        _native_runtime_accounting(report, inventory, lane)

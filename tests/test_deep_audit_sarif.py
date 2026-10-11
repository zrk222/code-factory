from copy import deepcopy
import json

import pytest

from factoryline.deep_audit_io import digest, relative_path, strict_json
from factoryline.deep_audit_sarif import normalize_sarif
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes

ANALYZER = {"id": "scanner", "driver": "Example", "version": "1"}


@pytest.mark.parametrize("kind", ["positive", "negative", "mutation"])
def test_trivy_signed_policy_keeps_binary_and_control_config_distinct(kind):
    from factoryline.deep_audit_sarif import _challenge_execution_config_valid_v2

    lane = {
        "engine": "trivy",
        "ruleset_sha256": "a" * 64,
        "native_policy": {
            "config_sha256": "b" * 64,
            "baseline_ignore_sha256": "c" * 64,
        },
        "rule_ids": ["DS001", "DS002"],
        "mutation_config_sha256": {"DS001": "d" * 64},
    }
    execution = {
        "baseline_config_sha256": "c" * 64,
        "effective_config_sha256": "d" * 64 if kind == "mutation" else "c" * 64,
        "mutation": {
            "disabled_rule_id": "DS001",
            "remaining_rule_inventory_sha256": digest(["DS002"]),
        }
        if kind == "mutation"
        else None,
    }
    obligation = {"detector_rule_id": "DS001"}
    identity = ("test-control", kind)
    assert _challenge_execution_config_valid_v2(execution, obligation, identity, lane)
    assert not _challenge_execution_config_valid_v2(
        {**execution, "baseline_config_sha256": lane["ruleset_sha256"]},
        obligation,
        identity,
        lane,
    )
    del lane["native_policy"]
    assert not _challenge_execution_config_valid_v2(
        execution, obligation, identity, lane
    )


@pytest.mark.parametrize(
    "policy",
    [
        {},
        {"config_sha256": "b" * 64},
        {"config_sha256": "b" * 64, "baseline_ignore_sha256": "invalid"},
    ],
)
def test_trivy_missing_or_invalid_control_policy_is_incomplete(policy):
    from factoryline.deep_audit_sarif import _challenge_baseline_config_sha256

    assert (
        _challenge_baseline_config_sha256({"engine": "trivy", "native_policy": policy})
        is None
    )


def test_semgrep_negative_challenge_rejects_unrelated_detector_findings():
    from factoryline.deep_audit_sarif import _challenge_findings_valid

    with pytest.raises(RuntimeAuditError, match="signed oracle"):
        _challenge_findings_valid(
            [{"rule_id": "other-rule", "suppressed": False}],
            {},
            {"engine": "semgrep"},
            {"detector_rule_id": "target-rule"},
            "negative",
        )


@pytest.mark.parametrize("kind", ["negative", "mutation"])
def test_semgrep_clean_challenge_has_no_target_finding(kind):
    from factoryline.deep_audit_sarif import _challenge_findings_valid

    _challenge_findings_valid(
        [], {}, {"engine": "semgrep"}, {"detector_rule_id": "target-rule"}, kind
    )


@pytest.mark.parametrize("missing", [True, False])
def test_signed_semgrep_requires_rederived_native_rule_execution(missing):
    from factoryline.deep_audit_sarif import _rule_accounting_gaps
    from test_deep_audit import semgrep_execution_evidence

    evidence, lane, sources, baseline = semgrep_execution_evidence()
    coverage = {"semgrep_rule_execution": evidence}
    assert _rule_accounting_gaps(coverage, lane, sources, baseline) == []
    if missing:
        coverage.clear()
    else:
        evidence["observations"][0]["raw_report_sha256"] = "0" * 64
    assert _rule_accounting_gaps(coverage, lane, sources, baseline) == [
        "SEMGREP_NATIVE_RULE_EXECUTION_UNVERIFIED"
    ]


def location(line=1, path="app.py"):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line},
        }
    }


def report():
    finding = {
        "ruleId": "unsafe",
        "ruleIndex": 0,
        "level": "error",
        "partialFingerprints": {"primary/v1": "stable-id"},
        "locations": [location()],
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {"location": location(), "kinds": ["source"]},
                            {"location": location(2), "kinds": ["sink"]},
                        ]
                    }
                ]
            }
        ],
    }
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Example",
                        "version": "1",
                        "rules": [{"id": "unsafe"}],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [finding],
            }
        ],
    }


def ingest(tmp_path, payload):
    (tmp_path / "app.py").write_text("one\ntwo\n", encoding="utf-8")
    raw = json.dumps(payload).encode()
    (tmp_path / "report.json").write_bytes(raw)
    return normalize_sarif(
        tmp_path,
        {"path": "report.json", "sha256": sha256_bytes(raw)},
        ANALYZER,
        {"app.py": sha256_bytes((tmp_path / "app.py").read_bytes())},
    )


def test_trace_native_identity_and_hashes(tmp_path):
    before = ingest(tmp_path, report())
    changed = report()
    changed["runs"][0]["results"][0]["locations"] = [location(2)]
    after = ingest(tmp_path, changed)
    left, right = before["findings"][0], after["findings"][0]
    assert left["finding_id"] == right["finding_id"]
    assert left["trace_sha256"] != right["trace_sha256"]
    assert left["trace_depth"] == 2
    assert left["flows"][0][0]["kinds"] == ["source"]
    assert before["authority"] == "none"
    assert before["normalized_sha256"] == digest(
        {key: value for key, value in before.items() if key != "normalized_sha256"}
    )


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda r: r.update(version="2.0.0"), "E_SARIF_VERSION"),
        (lambda r: r["runs"][0].update(invocations=[]), "E_SARIF_SHAPE"),
        (
            lambda r: r["runs"][0]["invocations"][0].update(executionSuccessful=False),
            "E_ANALYZER_INCOMPLETE",
        ),
        (
            lambda r: r["runs"][0]["invocations"][0].update(executionSuccessful=1),
            "E_ANALYZER_INCOMPLETE",
        ),
        (
            lambda r: r["runs"][0]["tool"]["driver"].update(version="2"),
            "E_ANALYZER_MISMATCH",
        ),
        (
            lambda r: r["runs"][0]["results"][0].update(partialFingerprints={}),
            "E_NATIVE_FINGERPRINT",
        ),
        (lambda r: r["runs"][0]["results"][0].update(level="safe"), "E_SARIF_ENUM"),
        (
            lambda r: r["runs"][0]["results"][0].update(baselineState="fixed"),
            "E_SARIF_ENUM",
        ),
        (lambda r: r["runs"][0]["results"][0].update(ruleIndex=1), "E_FIELD"),
        (
            lambda r: r["runs"][0]["results"].append(
                deepcopy(r["runs"][0]["results"][0])
            ),
            "E_DUPLICATE_FINDING",
        ),
        (
            lambda r: r["runs"][0]["results"][0].update(
                locations=[location(path="other.py")]
            ),
            "E_TRACE_UNBOUND",
        ),
        (
            lambda r: r["runs"][0]["results"][0].update(
                suppressions=[{"kind": "hidden"}]
            ),
            "E_SARIF_ENUM",
        ),
        (
            lambda r: r["runs"][0]["invocations"][0].update(
                toolConfigurationNotifications=[{"level": "error"}]
            ),
            "E_ANALYZER_INCOMPLETE",
        ),
    ],
)
def test_rejects_bad_evidence(tmp_path, mutate, code):
    payload = report()
    mutate(payload)
    with pytest.raises(RuntimeAuditError, match=code):
        ingest(tmp_path, payload)


@pytest.mark.parametrize(
    "path",
    [
        "../x",
        "/x",
        "C:/x",
        "a\\b",
        "%2e%2e/x",
        "a//b",
        "a/./b",
        "a ",
        "CON",
        "x?y",
        "x:y",
    ],
)
def test_paths_fail_closed(path):
    with pytest.raises(RuntimeAuditError, match="E_PATH_ESCAPE"):
        relative_path(path)


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b"[]", b"{"]
)
def test_strict_json_rejects_ambiguous_data(raw):
    with pytest.raises(RuntimeAuditError):
        strict_json(raw)


def test_source_and_report_drift(tmp_path):
    ingest(tmp_path, report())
    binding = {
        "path": "report.json",
        "sha256": sha256_bytes((tmp_path / "report.json").read_bytes()),
    }
    sources = {"app.py": sha256_bytes((tmp_path / "app.py").read_bytes())}
    altered = report()
    altered["runs"][0]["results"][0]["partialFingerprints"]["primary/v1"] = (
        "different-valid-finding"
    )
    (tmp_path / "report.json").write_text(json.dumps(altered), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        normalize_sarif(tmp_path, binding, ANALYZER, sources)
    (tmp_path / "app.py").write_text("changed")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        normalize_sarif(tmp_path, binding, ANALYZER, sources)


def test_suppression_and_pass_kind_are_preserved_not_accepted_as_canary(tmp_path):
    payload = report()
    payload["runs"][0]["results"][0].update(
        kind="pass", suppressions=[{"kind": "external"}]
    )
    finding = ingest(tmp_path, payload)["findings"][0]
    assert finding["suppressed"] is True
    assert finding["kind"] == "pass"


def test_driver_default_error_is_not_weakened_to_warning(tmp_path):
    payload = report()
    del payload["runs"][0]["results"][0]["level"]
    payload["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {
        "level": "error"
    }
    assert ingest(tmp_path, payload)["findings"][0]["level"] == "error"


def test_reordering_nested_flow_changes_trace_not_identity(tmp_path):
    payload = report()
    before = ingest(tmp_path, payload)["findings"][0]
    payload["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0][
        "locations"
    ].reverse()
    after = ingest(tmp_path, payload)["findings"][0]
    assert before["finding_id"] == after["finding_id"]
    assert before["trace_sha256"] != after["trace_sha256"]


@pytest.mark.parametrize("disabled", [None, "rule-a"])
def test_semgrep_config_inventory_is_derived_from_signed_config(disabled):
    from factoryline.deep_audit_io import canonical_bytes, sha256_bytes
    from factoryline.deep_audit_sarif import _semgrep_config_inventory_valid

    execution = {
        "effective_config_sha256": "a" * 64,
        "mutation": None if disabled is None else {"disabled_rule_id": disabled},
    }
    lane = {"rule_ids": ["rule-a", "rule-b"]}
    raw = canonical_bytes(
        {
            "ruleset_sha256": "a" * 64,
            "rule_ids": [r for r in lane["rule_ids"] if r != disabled],
        }
    )
    artifact = {"sha256": sha256_bytes(raw), "bytes": len(raw)}
    assert _semgrep_config_inventory_valid(execution, lane, artifact)
    assert not _semgrep_config_inventory_valid(
        execution, lane, {**artifact, "sha256": "b" * 64}
    )
    assert not _semgrep_config_inventory_valid(
        execution, lane, {**artifact, "bytes": len(raw) + 1}
    )


def trivy_execution_evidence():
    import base64
    from factoryline.deep_audit_io import canonical_bytes, _trivy_observation

    config, ignore = b"# pinned config\n", b"\n"
    lane = {
        "engine": "trivy",
        "tool_version": "0.68.1",
        "timeout_seconds": 30,
        "ruleset_sha256": "a" * 64,
        "rule_ids": ["DS001", "DS002"],
        "native_artifact_roles": ["policy_inventory", "sarif_report"],
        "native_policy": {
            "config_sha256": sha256_bytes(config),
            "baseline_ignore_sha256": sha256_bytes(ignore),
        },
    }
    sources = {"Dockerfile": "b" * 64}
    sarif = {"runs": [{"results": []}]}
    native = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {"ID": rule, "Status": "PASS"} for rule in lane["rule_ids"]
                ],
                "MisconfSummary": {"Successes": 2, "Failures": 0},
            }
        ],
    }
    argv = [
        "/usr/local/bin/trivy",
        "config",
        "--config",
        "/opt/factory/rules/trivy.yaml",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--ignorefile",
        "/tmp/control.ignore",
        "--format",
        "sarif",
        "--output",
        "/tmp/report.sarif",
        "/src",
    ]
    json_argv = list(argv)
    json_argv[10] = "json"
    json_argv[12] = "/tmp/policy.json"
    json_argv.insert(2, "--include-non-failures")
    facts = {
        "exit_code": 0,
        "timed_out": False,
        "timeout_seconds": 30,
        "duration_ms": 1,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_sha256": "c" * 64,
        "stderr_sha256": "d" * 64,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    evidence = {
        "schema": "factory.trivy-rule-execution.v1",
        "config_base64": base64.b64encode(config).decode(),
        "ignore_base64": base64.b64encode(ignore).decode(),
        "sources": sources,
        "observations": [
            _trivy_observation("sarif", argv, dict(facts), canonical_bytes(sarif)),
            _trivy_observation("json", json_argv, dict(facts), canonical_bytes(native)),
        ],
    }
    return evidence, lane, sources, sarif


def test_trivy_host_rederives_explicit_native_statuses():
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    evidence, lane, sources, report = trivy_execution_evidence()
    assert (
        _rule_accounting_gaps({"trivy_rule_execution": evidence}, lane, sources, report)
        == []
    )
    assert _rule_accounting_gaps({}, lane, sources, report) == [
        "TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"
    ]


@pytest.mark.parametrize(
    "tamper",
    [
        "null",
        "missing_rule",
        "duplicate_rule",
        "unsupported_status",
        "summary",
        "missing_source",
        "extra_source",
    ],
)
def test_trivy_host_rejects_resealed_incomplete_native_checks(tamper):
    import base64
    from factoryline.deep_audit_io import canonical_bytes
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    evidence, lane, sources, report = trivy_execution_evidence()
    observation = evidence["observations"][1]
    native = json.loads(base64.b64decode(observation["raw_report_base64"]))
    result = native["Results"][0]
    if tamper == "null":
        native["Results"] = None
    elif tamper == "missing_rule":
        result["Misconfigurations"].pop()
        result["MisconfSummary"]["Successes"] = 1
    elif tamper == "duplicate_rule":
        result["Misconfigurations"].append(dict(result["Misconfigurations"][0]))
    elif tamper == "unsupported_status":
        result["Misconfigurations"][0]["Status"] = "SKIPPED"
    elif tamper == "summary":
        result["MisconfSummary"]["Successes"] = 3
    elif tamper == "missing_source":
        sources["nested/Dockerfile"] = "e" * 64
    else:
        result["Target"] = "unbound/Dockerfile"
    raw = canonical_bytes(native)
    observation.update(
        raw_report_base64=base64.b64encode(raw).decode(),
        raw_report_sha256=sha256_bytes(raw),
    )
    assert _rule_accounting_gaps(
        {"trivy_rule_execution": evidence}, lane, sources, report
    ) == ["TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"]


@pytest.mark.parametrize(
    "tamper", ["timeout", "duration", "extra_option", "raw_hash", "config"]
)
def test_trivy_host_rejects_process_or_policy_tampering(tamper):
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    evidence, lane, sources, report = trivy_execution_evidence()
    observation = evidence["observations"][1]
    if tamper == "timeout":
        observation["execution"]["timeout_seconds"] = 31
    elif tamper == "duration":
        observation["execution"]["duration_ms"] = 30001
    elif tamper == "extra_option":
        for item in evidence["observations"]:
            item["argv"].insert(-1, "--skip-files=Dockerfile")
    elif tamper == "raw_hash":
        observation["raw_report_sha256"] = "0" * 64
    else:
        lane["native_policy"]["config_sha256"] = "0" * 64
    assert _rule_accounting_gaps(
        {"trivy_rule_execution": evidence}, lane, sources, report
    ) == ["TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"]


def test_trivy_challenge_artifacts_bind_actual_native_json_bytes():
    import base64
    from factoryline.deep_audit_sarif import _trivy_challenge_native_valid

    evidence, lane, sources, report = trivy_execution_evidence()
    artifacts = [
        {
            "kind": role,
            "sha256": item["raw_report_sha256"],
            "bytes": len(base64.b64decode(item["raw_report_base64"])),
        }
        for item, role in zip(
            evidence["observations"], ("sarif_report", "policy_inventory")
        )
    ]
    execution = {"mutation": None, "native_artifacts": artifacts}
    challenge = {"trivy_rule_execution": evidence, "report": {"native_report": report}}
    assert _trivy_challenge_native_valid(
        execution,
        challenge,
        {"fixture_manifest": sources},
        {"detector_rule_id": "DS001"},
        lane,
    )
    artifacts[1]["bytes"] += 1
    assert not _trivy_challenge_native_valid(
        execution,
        challenge,
        {"fixture_manifest": sources},
        {"detector_rule_id": "DS001"},
        lane,
    )


def test_trivy_clean_negative_rejects_unrelated_failure():
    from factoryline.deep_audit_sarif import _challenge_findings_valid

    with pytest.raises(RuntimeAuditError, match="signed oracle"):
        _challenge_findings_valid(
            [{"rule_id": "DS002", "suppressed": False}],
            {},
            {"engine": "trivy"},
            {"detector_rule_id": "DS001"},
            "negative",
        )


def test_trivy_plain_native_ignore_mutation_has_only_target():
    from factoryline.deep_audit_io import _trivy_mutation, _trivy_ignore_ids

    assert _trivy_mutation(b"\n", "DS001") == b"DS001\n"
    assert _trivy_ignore_ids(b"\n") == []
    assert _trivy_ignore_ids(b"DS001\n") == ["DS001"]
    with pytest.raises(RuntimeAuditError):
        _trivy_mutation(b"DS002\n", "DS001")


@pytest.mark.parametrize(
    "ignore",
    [
        b"DS001\nDS001\n",
        b"DS002\nDS001\n",
        b"misconfigurations: []",
        b"# ignored",
        b"DS001 ",
        b"\xff",
    ],
)
def test_trivy_ignore_rejects_ambiguous_or_extra_policy(ignore):
    from factoryline.deep_audit_io import _trivy_ignore_ids

    with pytest.raises(RuntimeAuditError):
        _trivy_ignore_ids(ignore)


def test_verify_trivy_rule_execution_rederives_native_pass_matrix():
    from factoryline.deep_audit_io import verify_trivy_rule_execution

    evidence, lane, sources, report = trivy_execution_evidence()
    result = verify_trivy_rule_execution(evidence, lane, sources, report)
    assert result == {
        "state": "VERIFIED",
        "checks": {"Dockerfile": {"DS001": "PASS", "DS002": "PASS"}},
        "findings": 0,
    }
    evidence["observations"][1]["raw_report_sha256"] = "0" * 64
    with pytest.raises(RuntimeAuditError, match="report bytes differ"):
        verify_trivy_rule_execution(evidence, lane, sources, report)

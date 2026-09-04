from copy import deepcopy
import json

import pytest

from factoryline.deep_audit_io import digest, relative_path, strict_json
from factoryline.deep_audit_sarif import normalize_sarif
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes

ANALYZER = {"id": "scanner", "driver": "Example", "version": "1"}


def location(line=1, path="app.py"):
    return {"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}


def report():
    finding = {"ruleId": "unsafe", "ruleIndex": 0, "level": "error", "partialFingerprints": {"primary/v1": "stable-id"},
               "locations": [location()], "codeFlows": [{"threadFlows": [{"locations": [
                   {"location": location(), "kinds": ["source"]},
                   {"location": location(2), "kinds": ["sink"]}]}]}]}
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Example", "version": "1", "rules": [{"id": "unsafe"}]}},
            "invocations": [{"executionSuccessful": True}], "results": [finding]}]}


def ingest(tmp_path, payload):
    (tmp_path / "app.py").write_text("one\ntwo\n", encoding="utf-8")
    raw = json.dumps(payload).encode()
    (tmp_path / "report.json").write_bytes(raw)
    return normalize_sarif(tmp_path, {"path": "report.json", "sha256": sha256_bytes(raw)}, ANALYZER,
                           {"app.py": sha256_bytes((tmp_path / "app.py").read_bytes())})


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
    assert before["normalized_sha256"] == digest({key: value for key, value in before.items() if key != "normalized_sha256"})


@pytest.mark.parametrize("mutate,code", [
    (lambda r: r.update(version="2.0.0"), "E_SARIF_VERSION"),
    (lambda r: r["runs"][0].update(invocations=[]), "E_SARIF_SHAPE"),
    (lambda r: r["runs"][0]["invocations"][0].update(executionSuccessful=False), "E_ANALYZER_INCOMPLETE"),
    (lambda r: r["runs"][0]["invocations"][0].update(executionSuccessful=1), "E_ANALYZER_INCOMPLETE"),
    (lambda r: r["runs"][0]["tool"]["driver"].update(version="2"), "E_ANALYZER_MISMATCH"),
    (lambda r: r["runs"][0]["results"][0].update(partialFingerprints={}), "E_NATIVE_FINGERPRINT"),
    (lambda r: r["runs"][0]["results"][0].update(level="safe"), "E_SARIF_ENUM"),
    (lambda r: r["runs"][0]["results"][0].update(baselineState="fixed"), "E_SARIF_ENUM"),
    (lambda r: r["runs"][0]["results"][0].update(ruleIndex=1), "E_FIELD"),
    (lambda r: r["runs"][0]["results"].append(deepcopy(r["runs"][0]["results"][0])), "E_DUPLICATE_FINDING"),
    (lambda r: r["runs"][0]["results"][0].update(locations=[location(path="other.py")]), "E_TRACE_UNBOUND"),
    (lambda r: r["runs"][0]["results"][0].update(suppressions=[{"kind": "hidden"}]), "E_SARIF_ENUM"),
    (lambda r: r["runs"][0]["invocations"][0].update(toolConfigurationNotifications=[{"level": "error"}]), "E_ANALYZER_INCOMPLETE"),
])
def test_rejects_bad_evidence(tmp_path, mutate, code):
    payload = report()
    mutate(payload)
    with pytest.raises(RuntimeAuditError, match=code):
        ingest(tmp_path, payload)


@pytest.mark.parametrize("path", ["../x", "/x", "C:/x", "a\\b", "%2e%2e/x", "a//b", "a/./b", "a ", "CON", "x?y", "x:y"])
def test_paths_fail_closed(path):
    with pytest.raises(RuntimeAuditError, match="E_PATH_ESCAPE"):
        relative_path(path)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[]', b'{'])
def test_strict_json_rejects_ambiguous_data(raw):
    with pytest.raises(RuntimeAuditError):
        strict_json(raw)


def test_source_and_report_drift(tmp_path):
    ingest(tmp_path, report())
    binding = {"path": "report.json", "sha256": sha256_bytes((tmp_path/"report.json").read_bytes())}
    sources = {"app.py": sha256_bytes((tmp_path/"app.py").read_bytes())}
    altered = report()
    altered["runs"][0]["results"][0]["partialFingerprints"]["primary/v1"] = "different-valid-finding"
    (tmp_path/"report.json").write_text(json.dumps(altered), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        normalize_sarif(tmp_path, binding, ANALYZER, sources)
    (tmp_path/"app.py").write_text("changed")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        normalize_sarif(tmp_path, binding, ANALYZER, sources)


def test_suppression_and_pass_kind_are_preserved_not_accepted_as_canary(tmp_path):
    payload = report()
    payload["runs"][0]["results"][0].update(kind="pass", suppressions=[{"kind": "external"}])
    finding = ingest(tmp_path, payload)["findings"][0]
    assert finding["suppressed"] is True
    assert finding["kind"] == "pass"


def test_driver_default_error_is_not_weakened_to_warning(tmp_path):
    payload = report()
    del payload["runs"][0]["results"][0]["level"]
    payload["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {"level": "error"}
    assert ingest(tmp_path, payload)["findings"][0]["level"] == "error"


def test_reordering_nested_flow_changes_trace_not_identity(tmp_path):
    payload = report()
    before = ingest(tmp_path, payload)["findings"][0]
    payload["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"].reverse()
    after = ingest(tmp_path, payload)["findings"][0]
    assert before["finding_id"] == after["finding_id"]
    assert before["trace_sha256"] != after["trace_sha256"]
